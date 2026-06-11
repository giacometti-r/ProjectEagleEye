from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

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


def _ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _filter_fresh_articles(articles: list[SourceArticle], max_age_hours: int) -> list[SourceArticle]:
    if max_age_hours <= 0:
        return articles

    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    fresh_articles = [
        article
        for article in articles
        if (published_at := _ensure_utc(article.published_at)) is None or published_at >= cutoff
    ]
    dropped = len(articles) - len(fresh_articles)
    if dropped:
        logger.info(
            "Dropped stale source articles count=%s max_article_age_hours=%s",
            dropped,
            max_age_hours,
        )
    return fresh_articles


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
            "(phishing OR malvertising OR \"brand impersonation\" OR \"employee impersonation\" OR "
            "\"executive impersonation\" OR \"tech support scam\" OR \"social engineering\" OR "
            "deepfake OR \"voice cloning\" OR \"business email compromise\" OR "
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

    all_articles = _filter_fresh_articles(all_articles, cfg.max_article_age_hours)

    # Enforce newest-first processing even when upstream feed/API ordering differs.
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    all_articles.sort(key=lambda x: _ensure_utc(x.published_at) or epoch, reverse=True)

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
        digest_topic_dedupe_enabled=settings.digest_topic_dedupe_enabled,
        digest_topic_dedupe_threshold=settings.digest_topic_dedupe_threshold,
        digest_topic_dedupe_lookback_hours=settings.digest_topic_dedupe_lookback_hours,
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
