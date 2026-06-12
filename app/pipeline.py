from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.alerts.emailer import AlertEmail, DigestEmailItem, Emailer
from app.db import Database
from app.dedup.deduplicator import (
    build_content_hash,
    build_fingerprint,
    build_incident_key,
    build_similarity_document,
    canonicalize_url,
    find_near_duplicate,
    find_near_duplicate_pairs,
    find_topic_duplicate,
)
from app.detection.attack_classifier import AttackClassifier
from app.detection.victim_extractor import VictimExtractor
from app.fetch.article_fetcher import ArticleContent, ArticleFetcher
from app.models import Alert, Article, ArticleFingerprint
from app.sources.base import SourceArticle
from app.time_utils import ensure_utc

logger = logging.getLogger(__name__)


def _clip(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len]


@dataclass(frozen=True)
class PipelineMetrics:
    processed: int = 0
    alerts_sent: int = 0
    digest_sent: int = 0
    digest_queued: int = 0
    skipped: int = 0
    errors: int = 0

    def add(
        self,
        *,
        processed: int = 0,
        alerts_sent: int = 0,
        digest_sent: int = 0,
        digest_queued: int = 0,
        skipped: int = 0,
        errors: int = 0,
    ) -> PipelineMetrics:
        return PipelineMetrics(
            processed=self.processed + processed,
            alerts_sent=self.alerts_sent + alerts_sent,
            digest_sent=self.digest_sent + digest_sent,
            digest_queued=self.digest_queued + digest_queued,
            skipped=self.skipped + skipped,
            errors=self.errors + errors,
        )


@dataclass(frozen=True)
class _DigestQueueEntry:
    alert_id: int
    item: DigestEmailItem


@dataclass(frozen=True)
class _NearDuplicateResult:
    article_id: int
    score: float
    title: str


@dataclass(frozen=True)
class _TopicDuplicateResult:
    article_id: int
    score: float
    title: str
    shared_title_terms: tuple[str, ...]


@dataclass(frozen=True)
class _FetchedCandidate:
    item: SourceArticle
    content: ArticleContent
    canonical_url: str
    fingerprint: str
    content_hash: str
    similarity_document: str
    original_index: int


@dataclass(frozen=True)
class _RecentArticle:
    article_id: int
    title: str
    abstract: str
    text: str


class MonitorPipeline:
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
        similarity_dedupe_threshold: float = 0.30,
        near_duplicate_lookback_hours: int | None = None,
        near_duplicate_max_comparisons: int = 500,
        suppress_out_of_scope_digest: bool = True,
        digest_enabled: bool = True,
        digest_recipient_email: str | None = None,
        digest_max_items_per_run: int = 100,
        digest_topic_dedupe_enabled: bool = True,
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
        self.similarity_dedupe_threshold = similarity_dedupe_threshold
        self.near_duplicate_lookback_hours = near_duplicate_lookback_hours or incident_dedupe_window_hours
        self.near_duplicate_max_comparisons = near_duplicate_max_comparisons
        self.suppress_out_of_scope_digest = suppress_out_of_scope_digest
        self.digest_enabled = digest_enabled
        self.digest_recipient_email = digest_recipient_email or emailer.recipient_email
        self.digest_max_items_per_run = digest_max_items_per_run
        self.digest_topic_dedupe_enabled = digest_topic_dedupe_enabled
        self.digest_topic_dedupe_lookback_hours = digest_topic_dedupe_lookback_hours

    def run(self, articles: list[SourceArticle]) -> PipelineMetrics:
        metrics = PipelineMetrics()
        digest_queue: list[_DigestQueueEntry] = []
        candidates: list[_FetchedCandidate] = []

        for original_index, item in enumerate(articles):
            try:
                candidate = self._prepare_candidate(item, original_index)
            except Exception as exc:
                logger.exception("Unhandled processing failure url=%s error=%s", item.url, exc)
                metrics = metrics.add(processed=1, errors=1)
                continue

            if candidate is None:
                metrics = metrics.add(processed=1, skipped=1)
            else:
                candidates.append(candidate)
                metrics = metrics.add(processed=1)

        survivors, duplicate_count = self._dedupe_current_run_candidates(candidates)
        if duplicate_count:
            metrics = metrics.add(skipped=duplicate_count)

        for candidate in survivors:
            try:
                metrics = self._process_prepared(candidate, digest_queue, metrics)
            except Exception as exc:
                logger.exception("Unhandled processing failure url=%s error=%s", candidate.item.url, exc)
                metrics = metrics.add(errors=1)

        return self._flush_digest_queue(digest_queue, metrics)

    def _prepare_candidate(self, item: SourceArticle, original_index: int) -> _FetchedCandidate | None:
        canonical_url = canonicalize_url(item.url)

        with self.database.session() as session:
            existing = session.scalar(select(Article.id).where(Article.canonical_url == canonical_url))
            if existing:
                return None

        content = self.fetcher.fetch(item.url)
        if not content:
            return None

        fingerprint = build_fingerprint(item.title, content.full_text)
        content_hash = build_content_hash(content.full_text)
        similarity_document = build_similarity_document(item.title, content.abstract, content.full_text)

        with self.database.session() as session:
            content_hash_exists = session.scalar(select(Article.id).where(Article.content_hash == content_hash))
            if content_hash_exists:
                logger.info(
                    "Duplicate content hash detected, skipping url=%s existing_article_id=%s",
                    item.url,
                    content_hash_exists,
                )
                return None

            fp_exists = session.scalar(
                select(ArticleFingerprint.id).where(ArticleFingerprint.fingerprint == fingerprint)
            )
            if fp_exists:
                logger.info("Duplicate fingerprint detected, skipping url=%s", item.url)
                return None

        if self.near_duplicate_enabled:
            near_duplicate = self._find_near_duplicate(item.title, content.abstract, content.full_text, item.published_at)
            if near_duplicate is not None:
                logger.info(
                    "Near duplicate detected, skipping url=%s matched_article_id=%s score=%.3f matched_title=%s",
                    item.url,
                    near_duplicate.article_id,
                    near_duplicate.score,
                    near_duplicate.title,
                )
                return None

        return _FetchedCandidate(
            item=item,
            content=content,
            canonical_url=canonical_url,
            fingerprint=fingerprint,
            content_hash=content_hash,
            similarity_document=similarity_document,
            original_index=original_index,
        )

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

        def union(left_index: int, right_index: int) -> None:
            left_root = find(left_index)
            right_root = find(right_index)
            if left_root != right_root:
                parents[right_root] = left_root

        def union_exact_duplicates(attribute: str) -> None:
            seen: dict[str, int] = {}
            for index, candidate in enumerate(candidates):
                key = getattr(candidate, attribute)
                first_index = seen.get(key)
                if first_index is None:
                    seen[key] = index
                else:
                    union(first_index, index)

        union_exact_duplicates("canonical_url")
        union_exact_duplicates("content_hash")
        union_exact_duplicates("fingerprint")

        if self.near_duplicate_enabled:
            documents = [candidate.similarity_document for candidate in candidates]
            for match in find_near_duplicate_pairs(documents, threshold=self.similarity_dedupe_threshold):
                left = candidates[match.left_index]
                right = candidates[match.right_index]
                if self._within_near_duplicate_window(left, right):
                    union(match.left_index, match.right_index)

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
            survivor = candidates[
                max(
                    groups[find(loser_index)],
                    key=lambda index: self._candidate_survivor_key(candidates[index]),
                )
            ]
            logger.info(
                "Current-run duplicate detected, skipping url=%s survivor_url=%s",
                loser.item.url,
                survivor.item.url,
            )

        survivors = [
            candidate
            for index, candidate in enumerate(candidates)
            if index in survivor_indices
        ]
        return survivors, len(loser_indices)

    def _candidate_survivor_key(self, candidate: _FetchedCandidate) -> tuple[datetime, int]:
        published_at = ensure_utc(candidate.item.published_at)
        return (published_at or datetime.min.replace(tzinfo=timezone.utc), -candidate.original_index)

    def _within_near_duplicate_window(self, left: _FetchedCandidate, right: _FetchedCandidate) -> bool:
        left_time = ensure_utc(left.item.published_at)
        right_time = ensure_utc(right.item.published_at)
        if left_time is None or right_time is None:
            return True
        return abs(left_time - right_time) <= timedelta(hours=self.near_duplicate_lookback_hours)

    def _process_prepared(
        self,
        candidate: _FetchedCandidate,
        digest_queue: list[_DigestQueueEntry],
        metrics: PipelineMetrics,
    ) -> PipelineMetrics:
        item = candidate.item
        content = candidate.content
        canonical_url = candidate.canonical_url
        fingerprint = candidate.fingerprint
        content_hash = candidate.content_hash

        classification = self.classifier.classify(item.title, content.full_text)
        victim = self.victim_extractor.extract(item.title, content.full_text)

        has_confident_victim = bool(
            victim.victim_name
            and victim.victim_category
            and victim.confidence >= self.min_victim_confidence
        )
        incident_key: str | None = None
        if classification.attack_type and victim.victim_name:
            incident_key = build_incident_key(victim.victim_name, classification.attack_type)

        duplicate_incident = False
        if classification.article_type == "incident" and classification.attack_type and incident_key:
            duplicate_incident = self._has_recent_incident_duplicate(incident_key, item.published_at)
        if duplicate_incident:
            logger.info(
                "Duplicate incident detected, skipping url=%s incident_key=%s",
                item.url,
                incident_key,
            )
            return metrics.add(skipped=1)

        immediate_ready = (
            classification.article_type == "incident"
            and classification.attack_type is not None
            and has_confident_victim
            and not duplicate_incident
        )
        routing_reason = self._routing_reason(classification.article_type, classification.attack_type, has_confident_victim, duplicate_incident)

        if self.digest_topic_dedupe_enabled and not immediate_ready:
            topic_duplicate = self._find_digest_topic_duplicate(
                item.title,
                content.abstract,
                content.full_text,
                item.published_at,
            )
            if topic_duplicate is not None:
                logger.info(
                    "Digest topic duplicate detected, skipping url=%s matched_article_id=%s score=%.3f matched_title=%s shared_title_terms=%s",
                    item.url,
                    topic_duplicate.article_id,
                    topic_duplicate.score,
                    topic_duplicate.title,
                    ",".join(topic_duplicate.shared_title_terms),
                )
                return metrics.add(skipped=1)

        article_id: int | None = None
        alert_id: int | None = None
        immediate_email: AlertEmail | None = None
        digest_item: DigestEmailItem | None = None
        suppressed_out_of_scope = False

        with self.database.session() as session:
            existing = session.scalar(select(Article.id).where(Article.canonical_url == canonical_url))
            if existing:
                return metrics.add(skipped=1)

            content_hash_exists = session.scalar(select(Article.id).where(Article.content_hash == content_hash))
            if content_hash_exists:
                logger.info(
                    "Duplicate content hash detected during insert guard, skipping url=%s existing_article_id=%s",
                    item.url,
                    content_hash_exists,
                )
                return metrics.add(skipped=1)

            fp_exists = session.scalar(
                select(ArticleFingerprint.id).where(ArticleFingerprint.fingerprint == fingerprint)
            )
            if fp_exists:
                return metrics.add(skipped=1)

            try:
                victim_name = victim.victim_name or "Unknown entity"
                victim_category = victim.victim_category or "unknown"
                attack_type = classification.attack_type or "unknown"

                article = Article(
                    source_name=_clip(item.source_name, 1024),
                    source_type=_clip(item.source_type, 40),
                    title=item.title,
                    url=item.url,
                    canonical_url=canonical_url,
                    published_at=item.published_at,
                    article_text=content.full_text,
                    abstract=content.abstract,
                    article_type=_clip(classification.article_type, 40),
                    attack_type=_clip(attack_type, 80),
                    victim_name=_clip(victim_name, 200),
                    victim_category=_clip(victim_category, 40),
                    incident_key=incident_key,
                    content_hash=content_hash,
                )
                session.add(article)
                session.flush()
                article_id = article.id

                session.add(ArticleFingerprint(article_id=article.id, fingerprint=fingerprint))

                if immediate_ready:
                    immediate_email = self._build_immediate_email(item, content, classification, victim)
                    alert = Alert(
                        article_id=article.id,
                        recipient_email=self.emailer.recipient_email,
                        channel="immediate",
                        routing_reason=None,
                        subject=immediate_email.subject,
                        body=immediate_email.body,
                        status="pending",
                        error_message=None,
                    )
                else:
                    suppressed_out_of_scope = (
                        routing_reason == "out_of_scope" and self.suppress_out_of_scope_digest
                    )
                    digest_subject = (
                        f"Digest skipped: {routing_reason}"
                        if suppressed_out_of_scope
                        else f"Digest queued: {routing_reason}"
                    )
                    digest_body = (
                        f"Title: {item.title}\n"
                        f"Source: {item.source_name}\n"
                        f"Routing reason: {routing_reason}\n"
                        f"Attack type: {classification.attack_type or 'unknown'}\n"
                        f"Victim: {victim.victim_name or 'n/a'}\n"
                        f"Published date: {self._published_date(item.published_at)}\n"
                        f"Article link: {item.url}\n"
                    )
                    if suppressed_out_of_scope:
                        status = "skipped"
                    elif self.digest_enabled and len(digest_queue) < self.digest_max_items_per_run:
                        status = "queued"
                    else:
                        status = "skipped"
                    digest_reason = (
                        routing_reason
                        if status == "queued" or suppressed_out_of_scope
                        else "digest_overflow_or_disabled"
                    )
                    alert = Alert(
                        article_id=article.id,
                        recipient_email=self.digest_recipient_email,
                        channel="digest",
                        routing_reason=digest_reason,
                        subject=digest_subject,
                        body=digest_body,
                        status=status,
                        error_message=None,
                    )
                    if status == "queued":
                        digest_item = DigestEmailItem(
                            title=item.title,
                            source_name=item.source_name,
                            routing_reason=routing_reason,
                            link=item.url,
                            published_date=self._published_date(item.published_at),
                            attack_type=classification.attack_type,
                            victim_name=victim.victim_name,
                        )

                session.add(alert)
                session.flush()
                alert_id = alert.id
            except IntegrityError:
                session.rollback()
                logger.info("Duplicate detected during insert, skipping url=%s", item.url)
                return metrics.add(skipped=1)

        next_metrics = metrics.add(
            digest_queued=1 if digest_item else 0,
            skipped=1 if suppressed_out_of_scope else 0,
        )

        if immediate_ready and article_id is not None and alert_id is not None:
            send_status = "sent"
            send_error = None
            try:
                if immediate_email is None:
                    immediate_email = self._build_immediate_email(item, content, classification, victim)
                self.emailer.send(immediate_email)
            except Exception as exc:
                logger.exception("Immediate email sending failed url=%s error=%s", item.url, exc)
                send_status = "failed"
                send_error = str(exc)

            with self.database.session() as session:
                alert = session.scalar(select(Alert).where(Alert.id == alert_id, Alert.article_id == article_id))
                if alert is not None:
                    alert.status = send_status
                    alert.error_message = send_error

            sent_delta = 1 if send_status == "sent" else 0
            return next_metrics.add(alerts_sent=sent_delta)

        if digest_item and alert_id is not None:
            digest_queue.append(_DigestQueueEntry(alert_id=alert_id, item=digest_item))
        return next_metrics

    def _build_immediate_email(
        self,
        item: SourceArticle,
        content: ArticleContent,
        classification: object,
        victim: object,
    ) -> AlertEmail:
        victim_name = getattr(victim, "victim_name") or "Unknown entity"
        victim_category = getattr(victim, "victim_category") or "unknown"
        attack_type = getattr(classification, "attack_type") or "unknown"
        return AlertEmail(
            subject=self.emailer.build_subject(victim_name, victim_category, attack_type),
            body=self.emailer.build_body(
                abstract=content.abstract,
                attack_type=attack_type,
                victim_name=victim_name,
                victim_category=victim_category,
                source_name=item.source_name,
                published_date=self._published_date(item.published_at),
                link=item.url,
            ),
        )

    def _routing_reason(
        self,
        article_type: str,
        attack_type: str | None,
        has_confident_victim: bool,
        duplicate_incident: bool,
    ) -> str:
        if duplicate_incident:
            return "duplicate_incident"
        if article_type != "incident":
            return article_type
        if attack_type is None:
            return "out_of_taxonomy"
        if not has_confident_victim:
            return "low_victim_confidence"
        return "qualified_incident"

    def _has_recent_incident_duplicate(self, incident_key: str, candidate_time: datetime | None) -> bool:
        with self.database.session() as session:
            matches = session.execute(
                select(Article.published_at, Article.created_at).where(Article.incident_key == incident_key)
            ).all()

        if not matches:
            return False
        candidate_reference = ensure_utc(candidate_time)
        if candidate_reference is None:
            return True

        window = timedelta(hours=self.incident_dedupe_window_hours)
        for published_at, created_at in matches:
            reference = ensure_utc(published_at or created_at)
            if reference is None:
                return True
            if abs(candidate_reference - reference) <= window:
                return True
        return False

    def _load_recent_articles(
        self,
        candidate_time: datetime | None,
        lookback_hours: int | None,
    ) -> list[_RecentArticle]:
        if self.near_duplicate_max_comparisons <= 0:
            return []

        with self.database.session() as session:
            rows = session.execute(
                select(
                    Article.id,
                    Article.title,
                    Article.abstract,
                    Article.article_text,
                    Article.published_at,
                    Article.created_at,
                )
                .order_by(Article.created_at.desc())
                .limit(self.near_duplicate_max_comparisons)
            ).all()

        if not rows:
            return []

        candidate_reference = ensure_utc(candidate_time)
        window = (
            timedelta(hours=lookback_hours)
            if lookback_hours is not None and lookback_hours > 0
            else None
        )
        articles: list[_RecentArticle] = []
        for article_id, title, abstract, text, published_at, created_at in rows:
            if candidate_reference is not None and window is not None:
                reference = ensure_utc(published_at or created_at)
                if reference is not None and abs(candidate_reference - reference) > window:
                    continue

            articles.append(
                _RecentArticle(
                    article_id=article_id,
                    title=title,
                    abstract=abstract,
                    text=text,
                )
            )
        return articles

    def _find_digest_topic_duplicate(
        self,
        title: str,
        abstract: str,
        text: str,
        candidate_time: datetime | None,
    ) -> _TopicDuplicateResult | None:
        recent_articles = self._load_recent_articles(candidate_time, self.digest_topic_dedupe_lookback_hours)
        if not recent_articles:
            return None

        existing_items = [
            (article.title, article.abstract, article.text)
            for article in recent_articles
        ]

        match = find_topic_duplicate(
            title,
            abstract,
            text,
            existing_items,
            threshold=self.similarity_dedupe_threshold,
        )
        if match is None:
            return None

        matched_article = recent_articles[match.index]
        return _TopicDuplicateResult(
            article_id=matched_article.article_id,
            score=match.score,
            title=matched_article.title,
            shared_title_terms=match.shared_title_terms,
        )

    def _find_near_duplicate(
        self,
        title: str,
        abstract: str,
        text: str,
        candidate_time: datetime | None,
    ) -> _NearDuplicateResult | None:
        recent_articles = self._load_recent_articles(candidate_time, self.near_duplicate_lookback_hours)
        if not recent_articles:
            return None

        existing_documents = [
            build_similarity_document(article.title, article.abstract, article.text)
            for article in recent_articles
        ]

        candidate_document = build_similarity_document(title, abstract, text)
        match = find_near_duplicate(
            candidate_document,
            existing_documents,
            threshold=self.similarity_dedupe_threshold,
        )
        if match is None:
            return None

        matched_article = recent_articles[match.index]
        return _NearDuplicateResult(
            article_id=matched_article.article_id,
            score=match.score,
            title=matched_article.title,
        )

    def _flush_digest_queue(
        self,
        digest_queue: list[_DigestQueueEntry],
        metrics: PipelineMetrics,
    ) -> PipelineMetrics:
        if not self.digest_enabled or not digest_queue:
            return metrics

        digest_email = AlertEmail(
            subject=self.emailer.build_digest_subject(len(digest_queue)),
            body=self.emailer.build_digest_body([entry.item for entry in digest_queue]),
        )

        send_status = "sent"
        send_error = None
        try:
            self.emailer.send(digest_email, recipient_email=self.digest_recipient_email)
        except Exception as exc:
            logger.exception("Digest email sending failed error=%s", exc)
            send_status = "failed"
            send_error = str(exc)

        alert_ids = [entry.alert_id for entry in digest_queue]
        with self.database.session() as session:
            alerts = session.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all()
            for alert in alerts:
                alert.status = send_status
                alert.error_message = send_error
                alert.subject = digest_email.subject
                alert.body = digest_email.body

        digest_sent_delta = 1 if send_status == "sent" else 0
        return metrics.add(digest_sent=digest_sent_delta)

    def _published_date(self, published_at: datetime | None) -> str:
        published_at = ensure_utc(published_at)
        if not published_at:
            return "unknown"
        return published_at.isoformat()
