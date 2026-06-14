from __future__ import annotations

import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from app.dedup.deduplicator import (
    find_near_duplicate_candidates,
    find_near_duplicate_pairs,
    shared_salient_title_terms,
)
from app.pipeline.policy import (
    AGGREGATOR_SOURCE_NAMES,
    LOW_SCORE_DUPLICATE_GUARD_THRESHOLD,
    PRIMARY_SOURCE_DOMAINS,
    REWRITE_SOURCE_DOMAINS,
    _host_matches,
    _normalized_host,
    _shared_named_entity_terms,
)
from app.pipeline.state import _FetchedCandidate, _RecentArticle, _RunDedupeContext
from app.time_utils import ensure_utc

logger = logging.getLogger("app.pipeline")


class DedupeMixin:
    def _filter_stored_exact_duplicates(
        self,
        candidates: list[_FetchedCandidate],
        context: _RunDedupeContext,
    ) -> tuple[list[_FetchedCandidate], int]:
        if not candidates:
            return candidates, 0

        self._load_existing_exact_keys(candidates, context)
        survivors: list[_FetchedCandidate] = []
        duplicate_count = 0
        for candidate in candidates:
            content_hash_article_id = context.content_hash_article_ids.get(candidate.content_hash)
            if content_hash_article_id:
                logger.info(
                    "Duplicate detected, skipping reason=content_hash url=%s title=%s existing_article_id=%s",
                    candidate.item.url,
                    candidate.item.title,
                    content_hash_article_id,
                )
                duplicate_count += 1
                continue

            fingerprint_article_id = context.fingerprint_article_ids.get(candidate.fingerprint)
            if fingerprint_article_id:
                logger.info(
                    "Duplicate detected, skipping reason=fingerprint url=%s title=%s existing_article_id=%s",
                    candidate.item.url,
                    candidate.item.title,
                    fingerprint_article_id,
                )
                duplicate_count += 1
                continue

            survivors.append(candidate)
        return survivors, duplicate_count

    def _filter_stored_near_duplicates(
        self,
        candidates: list[_FetchedCandidate],
        context: _RunDedupeContext,
    ) -> tuple[list[_FetchedCandidate], int]:
        if not self.near_duplicate_enabled or not candidates or not context.recent_articles:
            return candidates, 0

        allowed_existing_indices = {
            candidate_index: {
                article_index
                for article_index, article in enumerate(context.recent_articles)
                if self._recent_article_within_window(
                    article,
                    candidate.item.published_at,
                    self.near_duplicate_lookback_hours,
                )
            }
            for candidate_index, candidate in enumerate(candidates)
        }
        matches = find_near_duplicate_candidates(
            [candidate.similarity_document for candidate in candidates],
            context.similarity_documents,
            threshold=self.stored_near_duplicate_threshold,
            allowed_existing_indices=allowed_existing_indices,
        )

        survivors: list[_FetchedCandidate] = []
        duplicate_count = 0
        for candidate_index, candidate in enumerate(candidates):
            match = matches.get(candidate_index)
            if match is None:
                survivors.append(candidate)
                continue

            matched_article = context.recent_articles[match.index]
            if not self._passes_low_score_duplicate_guard(
                match.score,
                candidate.item.title,
                matched_article.title,
            ):
                survivors.append(candidate)
                continue

            incoming_priority = self._candidate_source_priority(candidate)
            matched_priority = self._recent_article_source_priority(matched_article)
            if incoming_priority > matched_priority:
                logger.info(
                    (
                        "Stored duplicate replacement selected reason=near_similarity "
                        "url=%s title=%s replacement_article_id=%s score=%.3f "
                        "replaced_url=%s replaced_title=%s incoming_source_priority=%s "
                        "stored_source_priority=%s"
                    ),
                    candidate.item.url,
                    candidate.item.title,
                    matched_article.article_id,
                    match.score,
                    matched_article.url,
                    matched_article.title,
                    incoming_priority,
                    matched_priority,
                )
                survivors.append(replace(candidate, replacement_article_id=matched_article.article_id))
                continue

            logger.info(
                (
                    "Duplicate detected, skipping reason=near_similarity url=%s title=%s "
                    "matched_article_id=%s score=%.3f matched_url=%s matched_title=%s "
                    "incoming_source_priority=%s stored_source_priority=%s"
                ),
                candidate.item.url,
                candidate.item.title,
                matched_article.article_id,
                match.score,
                matched_article.url,
                matched_article.title,
                incoming_priority,
                matched_priority,
            )
            duplicate_count += 1
        return survivors, duplicate_count

    def _dedupe_current_run_candidates(
        self,
        candidates: list[_FetchedCandidate],
    ) -> tuple[list[_FetchedCandidate], int]:
        if len(candidates) < 2:
            return candidates, 0

        parents = list(range(len(candidates)))

        def find(index: int) -> int:
            while parents[index] != index:
                parents[index] = parents[parents[index]]
                index = parents[index]
            return index

        group_reasons: dict[int, set[str]] = {index: set() for index in range(len(candidates))}
        group_similarity_scores: dict[int, list[float]] = {index: [] for index in range(len(candidates))}

        def union(left_index: int, right_index: int, reason: str, score: float | None = None) -> None:
            left_root = find(left_index)
            right_root = find(right_index)
            group_reasons.setdefault(left_root, set()).add(reason)
            group_reasons.setdefault(right_root, set()).add(reason)
            if score is not None:
                group_similarity_scores.setdefault(left_root, []).append(score)
                group_similarity_scores.setdefault(right_root, []).append(score)
            if left_root != right_root:
                parents[right_root] = left_root
                group_reasons[left_root].update(group_reasons.pop(right_root, set()))
                group_similarity_scores[left_root].extend(group_similarity_scores.pop(right_root, []))

        def union_exact_duplicates(attribute: str, reason: str) -> None:
            seen: dict[str, int] = {}
            for index, candidate in enumerate(candidates):
                key = getattr(candidate, attribute)
                first_index = seen.get(key)
                if first_index is None:
                    seen[key] = index
                else:
                    union(first_index, index, reason)

        union_exact_duplicates("canonical_url", "canonical_url")
        union_exact_duplicates("content_hash", "content_hash")
        union_exact_duplicates("fingerprint", "fingerprint")

        if self.near_duplicate_enabled:
            documents = [candidate.similarity_document for candidate in candidates]
            for match in find_near_duplicate_pairs(documents, threshold=self.current_run_near_duplicate_threshold):
                left = candidates[match.left_index]
                right = candidates[match.right_index]
                if self._within_near_duplicate_window(left, right) and self._passes_low_score_duplicate_guard(
                    match.score,
                    left.item.title,
                    right.item.title,
                ):
                    union(match.left_index, match.right_index, "near_similarity", match.score)

        groups: dict[int, list[int]] = {}
        for index in range(len(candidates)):
            groups.setdefault(find(index), []).append(index)

        survivor_indices: set[int] = set()
        for group_indices in groups.values():
            survivor_index = max(
                group_indices,
                key=lambda index: self._candidate_survivor_key(candidates[index]),
            )
            survivor_indices.add(survivor_index)

        loser_indices = set(range(len(candidates))) - survivor_indices
        for loser_index in sorted(loser_indices):
            loser = candidates[loser_index]
            root = find(loser_index)
            survivor = candidates[
                max(
                    groups[root],
                    key=lambda index: self._candidate_survivor_key(candidates[index]),
                )
            ]
            similarity_scores = group_similarity_scores.get(root, [])
            similarity_score = max(similarity_scores) if similarity_scores else None
            logger.info(
                (
                    "Current-run duplicate detected, skipping reason=%s url=%s title=%s "
                    "survivor_url=%s survivor_title=%s similarity_score=%s"
                ),
                ",".join(sorted(group_reasons.get(root) or {"unknown"})),
                loser.item.url,
                loser.item.title,
                survivor.item.url,
                survivor.item.title,
                f"{similarity_score:.3f}" if similarity_score is not None else "n/a",
            )

        survivors = [
            candidate
            for index, candidate in enumerate(candidates)
            if index in survivor_indices
        ]
        return survivors, len(loser_indices)

    def _candidate_survivor_key(self, candidate: _FetchedCandidate) -> tuple[int, datetime, int]:
        published_at = ensure_utc(candidate.item.published_at)
        return (
            self._candidate_source_priority(candidate),
            published_at or datetime.min.replace(tzinfo=timezone.utc),
            -candidate.original_index,
        )

    def _candidate_source_priority(self, candidate: _FetchedCandidate) -> int:
        return self._source_priority(candidate.item.source_name, candidate.item.url)

    def _recent_article_source_priority(self, article: _RecentArticle) -> int:
        return self._source_priority(article.source_name, article.url)

    def _source_priority(self, source_name: str, url: str) -> int:
        source_name = source_name.strip().lower()
        host = _normalized_host(url)
        if _host_matches(host, PRIMARY_SOURCE_DOMAINS):
            return 3
        if _host_matches(host, REWRITE_SOURCE_DOMAINS):
            return 0
        if source_name in AGGREGATOR_SOURCE_NAMES:
            return 1
        return 2

    def _passes_low_score_duplicate_guard(self, score: float, left_title: str, right_title: str) -> bool:
        if score >= LOW_SCORE_DUPLICATE_GUARD_THRESHOLD:
            return True
        return bool(
            shared_salient_title_terms(left_title, right_title)
            or _shared_named_entity_terms(left_title, right_title)
        )

    def _within_near_duplicate_window(self, left: _FetchedCandidate, right: _FetchedCandidate) -> bool:
        left_time = ensure_utc(left.item.published_at)
        right_time = ensure_utc(right.item.published_at)
        if left_time is None or right_time is None:
            return True
        return abs(left_time - right_time) <= timedelta(hours=self.near_duplicate_lookback_hours)
