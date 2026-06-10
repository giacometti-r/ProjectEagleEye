from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.alerts.emailer import Emailer
from app.config import load_settings
from app.db import Database
from app.detection.attack_classifier import AttackClassifier
from app.detection.victim_extractor import VictimExtractor
from app.fetch.article_fetcher import ArticleFetcher
from app.logging_config import configure_logging
from app.pipeline import MonitorPipeline
from app.schema_init import initialize_schema
from app.sources.base import SourceArticle
from app.sources.gdelt import GdeltSource
from app.sources.google_news import GoogleNewsRssSource
from app.sources.rss import RssSource

logger = logging.getLogger(__name__)


def gather_articles(settings: object) -> list[SourceArticle]:
    from app.config import Settings

    cfg = settings if isinstance(settings, Settings) else load_settings()

    sources = []
    for feed_url in cfg.rss_feeds:
        sources.append(RssSource(feed_url=feed_url, max_articles=cfg.max_articles_per_source))

    for query in cfg.google_news_queries:
        sources.append(GoogleNewsRssSource(query=query, max_articles=cfg.max_articles_per_source))

    if cfg.enable_gdelt:
        combined_query = (
            "(phishing OR malvertising OR impersonation OR \"business email compromise\" OR "
            "smishing OR vishing OR \"fake update\" OR \"SEO poisoning\" OR \"watering hole\" "
            "OR \"social media scam\" OR \"credential theft\") "
            "AND (company OR government OR university OR hospital OR healthcare)"
        )
        sources.append(
            GdeltSource(
                query=combined_query,
                max_articles=cfg.max_articles_per_source,
                timeout=cfg.request_timeout_seconds,
                timespan_minutes=cfg.gdelt_query_window_minutes,
            )
        )

    all_articles: list[SourceArticle] = []
    for source in sources:
        try:
            all_articles.extend(source.fetch())
        except Exception as exc:
            logger.warning("Source fetch failed source=%s error=%s", source.__class__.__name__, exc)

    # Enforce newest-first processing even when upstream feed/API ordering differs.
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    all_articles.sort(key=lambda x: x.published_at or epoch, reverse=True)

    return all_articles


def main() -> int:
    settings = load_settings()
    configure_logging(settings.log_level)

    database = Database(settings)
    initialize_schema(database)

    emailer = Emailer(
        smtp_host=settings.smtp_host,
        smtp_port=settings.smtp_port,
        smtp_username=settings.smtp_username,
        smtp_password=settings.smtp_password,
        sender_email=settings.sender_email,
        recipient_email=settings.recipient_email,
    )

    pipeline = MonitorPipeline(
        database=database,
        fetcher=ArticleFetcher(
            settings.request_timeout_seconds,
            abstract_max_chars=settings.abstract_max_chars,
        ),
        classifier=AttackClassifier(),
        victim_extractor=VictimExtractor(max_words=settings.max_victim_words),
        emailer=emailer,
        min_victim_confidence=settings.min_victim_confidence,
        incident_dedupe_window_hours=settings.incident_dedupe_window_hours,
        near_duplicate_enabled=settings.near_duplicate_enabled,
        near_duplicate_threshold=settings.near_duplicate_threshold,
        near_duplicate_lookback_hours=settings.near_duplicate_lookback_hours,
        near_duplicate_max_comparisons=settings.near_duplicate_max_comparisons,
        suppress_out_of_scope_digest=settings.suppress_out_of_scope_digest,
        digest_enabled=settings.digest_enabled,
        digest_recipient_email=settings.digest_recipient_email,
        digest_max_items_per_run=settings.digest_max_items_per_run,
    )

    articles = gather_articles(settings)
    metrics = pipeline.run(articles)

    logger.info(
        "Run complete processed=%s alerts_sent=%s digest_sent=%s digest_queued=%s skipped=%s errors=%s",
        metrics.processed,
        metrics.alerts_sent,
        metrics.digest_sent,
        metrics.digest_queued,
        metrics.skipped,
        metrics.errors,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
