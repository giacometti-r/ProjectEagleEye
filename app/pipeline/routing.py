from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import select

from app.alerts.emailer import AlertEmail
from app.fetch.article_fetcher import ArticleContent
from app.models import Alert
from app.pipeline.metrics import PipelineMetrics
from app.pipeline.state import _DigestQueueEntry
from app.sources.base import SourceArticle
from app.time_utils import ensure_utc

logger = logging.getLogger("app.pipeline")


class RoutingMixin:
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

    def _build_digest_audit_body(
        self,
        item: SourceArticle,
        classification: object,
        victim: object,
        routing_reason: str,
    ) -> str:
        return (
            f"Title: {item.title}\n"
            f"Source: {item.source_name}\n"
            f"Routing reason: {routing_reason}\n"
            f"Attack type: {getattr(classification, 'attack_type', None) or 'unknown'}\n"
            f"Victim: {getattr(victim, 'victim_name', None) or 'n/a'}\n"
            f"Published date: {self._published_date(item.published_at)}\n"
            f"Article link: {item.url}\n"
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
