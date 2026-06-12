from __future__ import annotations

from urllib.parse import quote_plus

from app.sources.rss import RssSource


class GoogleNewsRssSource(RssSource):
    def __init__(
        self,
        query: str,
        max_articles: int,
        language: str = "en-US",
        region: str = "US",
        recency_window: str = "7d",
        timeout_seconds: int = 15,
    ) -> None:
        query_with_window = f"{query} when:{recency_window}".strip()
        rss_url = (
            "https://news.google.com/rss/search?"
            f"q={quote_plus(query_with_window)}&hl={quote_plus(language)}&gl={quote_plus(region)}&ceid={quote_plus(region + ':en')}"
        )
        super().__init__(rss_url, max_articles, timeout_seconds=timeout_seconds, source_name_override="Google News")
