from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.alerts.emailer import AlertEmail, DigestEmailItem
from app.dedup.deduplicator import build_incident_key
from app.models import Alert, Article, ArticleFingerprint
from app.pipeline.metrics import PipelineMetrics
from app.pipeline.policy import _clip
from app.pipeline.state import _DigestQueueEntry, _FetchedCandidate, _RunDedupeContext

logger = logging.getLogger("app.pipeline")


class ProcessingMixin:
    def _process_prepared(
        self,
        candidate: _FetchedCandidate,
        digest_queue: list[_DigestQueueEntry],
        metrics: PipelineMetrics,
        context: _RunDedupeContext,
    ) -> PipelineMetrics:
        item = candidate.item
        content = candidate.content
        canonical_url = candidate.canonical_url
        fingerprint = candidate.fingerprint
        content_hash = candidate.content_hash
        replacement_article_id = candidate.replacement_article_id

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
            duplicate_incident = self._has_recent_incident_duplicate(
                incident_key,
                item.published_at,
                exclude_article_id=replacement_article_id,
            )
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
        )
        routing_reason = self._routing_reason(
            classification.article_type,
            classification.attack_type,
            has_confident_victim,
            duplicate_incident,
        )

        if self.digest_topic_dedupe_enabled and not immediate_ready:
            topic_duplicate = self._find_digest_topic_duplicate(
                candidate,
                item.published_at,
                context,
                exclude_article_id=replacement_article_id,
            )
            if topic_duplicate is not None:
                logger.info(
                    (
                        "Duplicate detected, skipping reason=topic_similarity url=%s title=%s "
                        "matched_article_id=%s score=%.3f matched_url=%s matched_title=%s shared_title_terms=%s"
                    ),
                    item.url,
                    item.title,
                    topic_duplicate.article_id,
                    topic_duplicate.score,
                    topic_duplicate.url,
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
            canonical_query = select(Article.id).where(Article.canonical_url == canonical_url)
            if replacement_article_id is not None:
                canonical_query = canonical_query.where(Article.id != replacement_article_id)
            existing = session.scalar(canonical_query)
            if existing:
                if replacement_article_id is not None:
                    logger.info(
                        (
                            "Duplicate detected during replacement guard, skipping "
                            "reason=replacement_conflict conflict_type=canonical_url "
                            "url=%s title=%s replacement_article_id=%s existing_article_id=%s"
                        ),
                        item.url,
                        item.title,
                        replacement_article_id,
                        existing,
                    )
                else:
                    logger.info(
                        "Duplicate detected during insert guard, skipping reason=canonical_url url=%s title=%s",
                        item.url,
                        item.title,
                    )
                return metrics.add(skipped=1)

            content_hash_query = select(Article.id).where(Article.content_hash == content_hash)
            if replacement_article_id is not None:
                content_hash_query = content_hash_query.where(Article.id != replacement_article_id)
            content_hash_exists = session.scalar(content_hash_query)
            if content_hash_exists:
                if replacement_article_id is not None:
                    logger.info(
                        (
                            "Duplicate detected during replacement guard, skipping "
                            "reason=replacement_conflict conflict_type=content_hash "
                            "url=%s title=%s replacement_article_id=%s existing_article_id=%s"
                        ),
                        item.url,
                        item.title,
                        replacement_article_id,
                        content_hash_exists,
                    )
                else:
                    logger.info(
                        (
                            "Duplicate detected during insert guard, skipping reason=content_hash "
                            "url=%s title=%s existing_article_id=%s"
                        ),
                        item.url,
                        item.title,
                        content_hash_exists,
                    )
                return metrics.add(skipped=1)

            fingerprint_query = select(ArticleFingerprint.article_id).where(
                ArticleFingerprint.fingerprint == fingerprint
            )
            if replacement_article_id is not None:
                fingerprint_query = fingerprint_query.where(ArticleFingerprint.article_id != replacement_article_id)
            fp_exists = session.scalar(fingerprint_query)
            if fp_exists:
                if replacement_article_id is not None:
                    logger.info(
                        (
                            "Duplicate detected during replacement guard, skipping "
                            "reason=replacement_conflict conflict_type=fingerprint "
                            "url=%s title=%s replacement_article_id=%s existing_article_id=%s"
                        ),
                        item.url,
                        item.title,
                        replacement_article_id,
                        fp_exists,
                    )
                else:
                    logger.info(
                        "Duplicate detected during insert guard, skipping reason=fingerprint url=%s title=%s",
                        item.url,
                        item.title,
                    )
                return metrics.add(skipped=1)

            try:
                victim_name = victim.victim_name or "Unknown entity"
                victim_category = victim.victim_category or "unknown"
                attack_type = classification.attack_type or "unknown"

                if replacement_article_id is not None:
                    article = session.get(Article, replacement_article_id)
                    if article is None:
                        logger.info(
                            (
                                "Duplicate detected during replacement guard, skipping "
                                "reason=replacement_conflict conflict_type=missing_target "
                                "url=%s title=%s replacement_article_id=%s"
                            ),
                            item.url,
                            item.title,
                            replacement_article_id,
                        )
                        return metrics.add(skipped=1)
                else:
                    article = Article()
                    session.add(article)

                article.source_name = _clip(item.source_name, 1024)
                article.source_type = _clip(item.source_type, 40)
                article.title = item.title
                article.url = item.url
                article.canonical_url = canonical_url
                article.published_at = item.published_at
                article.article_text = content.full_text
                article.abstract = content.abstract
                article.article_type = _clip(classification.article_type, 40)
                article.attack_type = _clip(attack_type, 80)
                article.victim_name = _clip(victim_name, 200)
                article.victim_category = _clip(victim_category, 40)
                article.incident_key = incident_key
                article.content_hash = content_hash

                session.flush()
                article_id = article.id

                fingerprint_record = session.scalar(
                    select(ArticleFingerprint).where(ArticleFingerprint.article_id == article.id)
                )
                if fingerprint_record is None:
                    session.add(ArticleFingerprint(article_id=article.id, fingerprint=fingerprint))
                else:
                    fingerprint_record.fingerprint = fingerprint

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
                    digest_body = self._build_digest_audit_body(item, classification, victim, routing_reason)
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
                if replacement_article_id is not None:
                    logger.info(
                        (
                            "Duplicate detected during replacement, skipping "
                            "reason=replacement_conflict conflict_type=integrity_error "
                            "url=%s title=%s replacement_article_id=%s"
                        ),
                        item.url,
                        item.title,
                        replacement_article_id,
                    )
                else:
                    logger.info(
                        "Duplicate detected during insert, skipping reason=integrity_error url=%s title=%s",
                        item.url,
                        item.title,
                    )
                return metrics.add(skipped=1)

        next_metrics = metrics.add(
            digest_queued=1 if digest_item else 0,
            skipped=1 if suppressed_out_of_scope else 0,
        )

        if article_id is not None:
            context.add_recent_article(
                article_id=article_id,
                source_name=item.source_name,
                source_type=item.source_type,
                title=item.title,
                url=item.url,
                abstract=content.abstract,
                text=content.full_text,
                published_at=item.published_at,
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
