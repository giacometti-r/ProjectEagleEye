from __future__ import annotations

import logging

from app.alerts.emailer import Emailer
from app.db import Database
from app.dedup.deduplicator import (
    build_content_hash,
    build_fingerprint,
    build_similarity_document,
    build_topic_document,
    canonicalize_url,
)
from app.detection.attack_classifier import AttackClassifier
from app.detection.victim_extractor import VictimExtractor
from app.fetch.article_fetcher import ArticleFetcher
from app.pipeline.dedupe import DedupeMixin
from app.pipeline.metrics import PipelineMetrics
from app.pipeline.processing import ProcessingMixin
from app.pipeline.routing import RoutingMixin
from app.pipeline.state import _DigestQueueEntry, _FetchedCandidate, _PreparedInput, _RunDedupeContext
from app.pipeline.storage import StorageMixin
from app.sources.base import SourceArticle

logger = logging.getLogger("app.pipeline")


class MonitorPipeline(ProcessingMixin, DedupeMixin, StorageMixin, RoutingMixin):
    def __init__(
        self,
        database: Database,
        fetcher: ArticleFetcher,
        classifier: AttackClassifier,
        victim_extractor: VictimExtractor,
        emailer: Emailer,
        min_victim_confidence: float = 0.65,
        incident_dedupe_window_hours: int = 48,
        near_duplicate_enabled: bool = True,
        stored_near_duplicate_threshold: float = 0.38,
        current_run_near_duplicate_threshold: float = 0.34,
        near_duplicate_lookback_hours: int | None = None,
        near_duplicate_max_comparisons: int = 500,
        suppress_out_of_scope_digest: bool = True,
        digest_enabled: bool = True,
        digest_recipient_email: str | None = None,
        digest_max_items_per_run: int = 100,
        digest_topic_dedupe_enabled: bool = True,
        digest_topic_dedupe_threshold: float = 0.40,
        digest_topic_dedupe_lookback_hours: int | None = 168,
    ) -> None:
        self.database = database
        self.fetcher = fetcher
        self.classifier = classifier
        self.victim_extractor = victim_extractor
        self.emailer = emailer
        self.min_victim_confidence = min_victim_confidence
        self.incident_dedupe_window_hours = incident_dedupe_window_hours
        self.near_duplicate_enabled = near_duplicate_enabled
        self.stored_near_duplicate_threshold = stored_near_duplicate_threshold
        self.current_run_near_duplicate_threshold = current_run_near_duplicate_threshold
        self.near_duplicate_lookback_hours = near_duplicate_lookback_hours or incident_dedupe_window_hours
        self.near_duplicate_max_comparisons = near_duplicate_max_comparisons
        self.suppress_out_of_scope_digest = suppress_out_of_scope_digest
        self.digest_enabled = digest_enabled
        self.digest_recipient_email = digest_recipient_email or emailer.recipient_email
        self.digest_max_items_per_run = digest_max_items_per_run
        self.digest_topic_dedupe_enabled = digest_topic_dedupe_enabled
        self.digest_topic_dedupe_threshold = digest_topic_dedupe_threshold
        self.digest_topic_dedupe_lookback_hours = digest_topic_dedupe_lookback_hours

    def run(self, articles: list[SourceArticle]) -> PipelineMetrics:
        metrics = PipelineMetrics(processed=len(articles))
        digest_queue: list[_DigestQueueEntry] = []
        prepared_inputs: list[_PreparedInput] = []
        candidates: list[_FetchedCandidate] = []

        for original_index, item in enumerate(articles):
            try:
                prepared_inputs.append(
                    _PreparedInput(
                        item=item,
                        canonical_url=canonicalize_url(item.url),
                        original_index=original_index,
                    )
                )
            except Exception as exc:
                logger.exception("Unhandled processing failure url=%s error=%s", item.url, exc)
                metrics = metrics.add(errors=1)
                continue

        context = self._build_run_dedupe_context(prepared_inputs)

        for prepared in prepared_inputs:
            if prepared.canonical_url in context.existing_canonical_urls:
                logger.info(
                    "Duplicate detected, skipping reason=canonical_url url=%s title=%s",
                    prepared.item.url,
                    prepared.item.title,
                )
                metrics = metrics.add(skipped=1)
                continue

            try:
                candidate = self._fetch_candidate(prepared)
            except Exception as exc:
                logger.exception("Unhandled processing failure url=%s error=%s", prepared.item.url, exc)
                metrics = metrics.add(errors=1)
                continue

            if candidate is None:
                metrics = metrics.add(skipped=1)
                continue
            candidates.append(candidate)

        candidates, stored_exact_count = self._filter_stored_exact_duplicates(candidates, context)
        if stored_exact_count:
            metrics = metrics.add(skipped=stored_exact_count)

        candidates, duplicate_count = self._dedupe_current_run_candidates(candidates)
        if duplicate_count:
            metrics = metrics.add(skipped=duplicate_count)

        candidates, stored_near_count = self._filter_stored_near_duplicates(candidates, context)
        if stored_near_count:
            metrics = metrics.add(skipped=stored_near_count)

        for candidate in candidates:
            try:
                metrics = self._process_prepared(candidate, digest_queue, metrics, context)
            except Exception as exc:
                logger.exception("Unhandled processing failure url=%s error=%s", candidate.item.url, exc)
                metrics = metrics.add(errors=1)

        return self._flush_digest_queue(digest_queue, metrics)

    def _build_run_dedupe_context(self, prepared_inputs: list[_PreparedInput]) -> _RunDedupeContext:
        canonical_urls = {prepared.canonical_url for prepared in prepared_inputs}
        return _RunDedupeContext(
            existing_canonical_urls=self._load_existing_canonical_urls(canonical_urls),
            content_hash_article_ids={},
            fingerprint_article_ids={},
            recent_articles=self._load_recent_articles(),
            near_duplicate_max_comparisons=self.near_duplicate_max_comparisons,
        )

    def _fetch_candidate(self, prepared: _PreparedInput) -> _FetchedCandidate | None:
        item = prepared.item
        content = self.fetcher.fetch(item.url)
        if not content:
            return None

        fingerprint = build_fingerprint(item.title, content.full_text)
        content_hash = build_content_hash(content.full_text)
        similarity_document = build_similarity_document(item.title, content.abstract, content.full_text)
        topic_document = build_topic_document(item.title, content.abstract, content.full_text)

        return _FetchedCandidate(
            item=item,
            content=content,
            canonical_url=prepared.canonical_url,
            fingerprint=fingerprint,
            content_hash=content_hash,
            similarity_document=similarity_document,
            topic_document=topic_document,
            original_index=prepared.original_index,
        )
