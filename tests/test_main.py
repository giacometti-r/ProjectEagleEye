from __future__ import annotations

from datetime import datetime, timedelta, timezone

import app.main as app_main
from app.config import Settings
from app.sources.base import SourceArticle


def _settings(max_article_age_hours: int) -> Settings:
    return Settings(
        smtp_host="smtp",
        smtp_port=587,
        smtp_username="u",
        smtp_password="p",
        sender_email="from@example.com",
        recipient_email="to@example.com",
        database_url="sqlite+pysqlite:///:memory:",
        log_level="INFO",
        request_timeout_seconds=5,
        max_articles_per_source=10,
        max_article_age_hours=max_article_age_hours,
        enable_gdelt=False,
        gdelt_query_window_minutes=180,
        rss_feeds=["https://example.com/feed"],
        google_news_queries=[],
        min_victim_confidence=0.65,
        incident_dedupe_window_hours=48,
        near_duplicate_enabled=True,
        near_duplicate_threshold=0.78,
        near_duplicate_lookback_hours=None,
        near_duplicate_max_comparisons=500,
        suppress_out_of_scope_digest=True,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        digest_max_items_per_run=100,
        digest_topic_dedupe_enabled=True,
        digest_topic_dedupe_threshold=0.30,
        digest_topic_dedupe_lookback_hours=168,
        abstract_max_chars=420,
        max_victim_words=8,
    )


def test_gather_articles_filters_stale_source_items(monkeypatch) -> None:
    now = datetime.now(timezone.utc)
    articles = [
        SourceArticle("rss", "rss", "fresh", "https://example.com/fresh", now - timedelta(hours=1)),
        SourceArticle("rss", "rss", "stale", "https://example.com/stale", now - timedelta(days=8)),
        SourceArticle("rss", "rss", "missing", "https://example.com/missing", None),
    ]

    class FakeRssSource:
        def __init__(self, feed_url: str, max_articles: int) -> None:
            del feed_url, max_articles

        def fetch(self) -> list[SourceArticle]:
            return articles

    monkeypatch.setattr(app_main, "RssSource", FakeRssSource)

    result = app_main.gather_articles(_settings(max_article_age_hours=168))

    assert [article.title for article in result] == ["fresh", "missing"]


def test_gather_articles_keeps_stale_items_when_age_filter_disabled(monkeypatch) -> None:
    now = datetime.now(timezone.utc)
    articles = [
        SourceArticle("rss", "rss", "fresh", "https://example.com/fresh", now - timedelta(hours=1)),
        SourceArticle("rss", "rss", "stale", "https://example.com/stale", now - timedelta(days=8)),
    ]

    class FakeRssSource:
        def __init__(self, feed_url: str, max_articles: int) -> None:
            del feed_url, max_articles

        def fetch(self) -> list[SourceArticle]:
            return articles

    monkeypatch.setattr(app_main, "RssSource", FakeRssSource)

    result = app_main.gather_articles(_settings(max_article_age_hours=0))

    assert [article.title for article in result] == ["fresh", "stale"]
