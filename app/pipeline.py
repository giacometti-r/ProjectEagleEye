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
    canonicalize_url,
)
from app.detection.attack_classifier import AttackClassifier
from app.detection.victim_extractor import VictimExtractor
from app.fetch.article_fetcher import ArticleFetcher
from app.models import Alert, Article, ArticleFingerprint
from app.sources.base import SourceArticle

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


@dataclass(frozen=True)
class _DigestQueueEntry:
    alert_id: int
    item: DigestEmailItem


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
        digest_enabled: bool = True,
        digest_recipient_email: str | None = None,
        digest_max_items_per_run: int = 100,
    ) -> None:
        self.database = database
        self.fetcher = fetcher
        self.classifier = classifier
        self.victim_extractor = victim_extractor
        self.emailer = emailer
        self.min_victim_confidence = min_victim_confidence
        self.incident_dedupe_window_hours = incident_dedupe_window_hours
        self.digest_enabled = digest_enabled
        self.digest_recipient_email = digest_recipient_email or emailer.recipient_email
        self.digest_max_items_per_run = digest_max_items_per_run

    def run(self, articles: list[SourceArticle]) -> PipelineMetrics:
        metrics = PipelineMetrics()
        digest_queue: list[_DigestQueueEntry] = []

        for item in articles:
            try:
                metrics = self._process_one(item, digest_queue, metrics)
            except Exception as exc:
                logger.exception("Unhandled processing failure url=%s error=%s", item.url, exc)
                metrics = PipelineMetrics(
                    processed=metrics.processed,
                    alerts_sent=metrics.alerts_sent,
                    digest_sent=metrics.digest_sent,
                    digest_queued=metrics.digest_queued,
                    skipped=metrics.skipped,
                    errors=metrics.errors + 1,
                )

        return self._flush_digest_queue(digest_queue, metrics)

    def _process_one(
        self,
        item: SourceArticle,
        digest_queue: list[_DigestQueueEntry],
        metrics: PipelineMetrics,
    ) -> PipelineMetrics:
        canonical_url = canonicalize_url(item.url)

        with self.database.session() as session:
            existing = session.scalar(select(Article.id).where(Article.canonical_url == canonical_url))
            if existing:
                return PipelineMetrics(
                    metrics.processed + 1,
                    metrics.alerts_sent,
                    metrics.digest_sent,
                    metrics.digest_queued,
                    metrics.skipped + 1,
                    metrics.errors,
                )

        content = self.fetcher.fetch(item.url)
        if not content:
            return PipelineMetrics(
                metrics.processed + 1,
                metrics.alerts_sent,
                metrics.digest_sent,
                metrics.digest_queued,
                metrics.skipped + 1,
                metrics.errors,
            )

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

        immediate_ready = (
            classification.article_type == "incident"
            and classification.attack_type is not None
            and has_confident_victim
            and not duplicate_incident
        )
        routing_reason = self._routing_reason(classification.article_type, classification.attack_type, has_confident_victim, duplicate_incident)

        fingerprint = build_fingerprint(item.title, content.full_text)
        content_hash = build_content_hash(content.full_text)

        article_id: int | None = None
        alert_id: int | None = None
        digest_item: DigestEmailItem | None = None

        with self.database.session() as session:
            fp_exists = session.scalar(
                select(ArticleFingerprint.id).where(ArticleFingerprint.fingerprint == fingerprint)
            )
            if fp_exists:
                return PipelineMetrics(
                    metrics.processed + 1,
                    metrics.alerts_sent,
                    metrics.digest_sent,
                    metrics.digest_queued,
                    metrics.skipped + 1,
                    metrics.errors,
                )

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
                    subject = self.emailer.build_subject(victim.victim_name or "Unknown entity", victim.victim_category or "unknown", classification.attack_type or "unknown")
                    body = self.emailer.build_body(
                        abstract=content.abstract,
                        attack_type=classification.attack_type or "unknown",
                        victim_name=victim.victim_name or "Unknown entity",
                        victim_category=victim.victim_category or "unknown",
                        source_name=item.source_name,
                        published_date=self._published_date(item.published_at),
                        link=item.url,
                    )
                    alert = Alert(
                        article_id=article.id,
                        recipient_email=self.emailer.recipient_email,
                        channel="immediate",
                        routing_reason=None,
                        subject=subject,
                        body=body,
                        status="pending",
                        error_message=None,
                    )
                else:
                    digest_subject = f"Digest queued: {routing_reason}"
                    digest_body = (
                        f"Title: {item.title}\n"
                        f"Source: {item.source_name}\n"
                        f"Routing reason: {routing_reason}\n"
                        f"Attack type: {classification.attack_type or 'unknown'}\n"
                        f"Victim: {victim.victim_name or 'n/a'}\n"
                        f"Published date: {self._published_date(item.published_at)}\n"
                        f"Article link: {item.url}\n"
                    )
                    status = "queued" if self.digest_enabled and len(digest_queue) < self.digest_max_items_per_run else "skipped"
                    digest_reason = routing_reason if status == "queued" else "digest_overflow_or_disabled"
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
                return PipelineMetrics(
                    metrics.processed + 1,
                    metrics.alerts_sent,
                    metrics.digest_sent,
                    metrics.digest_queued,
                    metrics.skipped + 1,
                    metrics.errors,
                )

        next_metrics = PipelineMetrics(
            metrics.processed + 1,
            metrics.alerts_sent,
            metrics.digest_sent,
            metrics.digest_queued + (1 if digest_item else 0),
            metrics.skipped,
            metrics.errors,
        )

        if immediate_ready and article_id is not None and alert_id is not None:
            send_status = "sent"
            send_error = None
            try:
                subject = self.emailer.build_subject(victim.victim_name or "Unknown entity", victim.victim_category or "unknown", classification.attack_type or "unknown")
                body = self.emailer.build_body(
                    abstract=content.abstract,
                    attack_type=classification.attack_type or "unknown",
                    victim_name=victim.victim_name or "Unknown entity",
                    victim_category=victim.victim_category or "unknown",
                    source_name=item.source_name,
                    published_date=self._published_date(item.published_at),
                    link=item.url,
                )
                self.emailer.send(AlertEmail(subject=subject, body=body))
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
            return PipelineMetrics(
                next_metrics.processed,
                next_metrics.alerts_sent + sent_delta,
                next_metrics.digest_sent,
                next_metrics.digest_queued,
                next_metrics.skipped,
                next_metrics.errors,
            )

        if digest_item and alert_id is not None:
            digest_queue.append(_DigestQueueEntry(alert_id=alert_id, item=digest_item))
        return next_metrics

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
        if candidate_time is None:
            return True

        window = timedelta(hours=self.incident_dedupe_window_hours)
        for published_at, created_at in matches:
            reference = self._ensure_utc(published_at or created_at)
            if reference is None:
                return True
            if abs(self._ensure_utc(candidate_time) - reference) <= window:
                return True
        return False

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
        return PipelineMetrics(
            metrics.processed,
            metrics.alerts_sent,
            metrics.digest_sent + digest_sent_delta,
            metrics.digest_queued,
            metrics.skipped,
            metrics.errors,
        )

    def _published_date(self, published_at: datetime | None) -> str:
        if not published_at:
            return "unknown"
        return published_at.astimezone(timezone.utc).isoformat()

    def _ensure_utc(self, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
