from __future__ import annotations

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import feedparser
import requests

from app.fetch.url_guard import UnsafeUrlError, validate_public_http_url
from app.sources.base import SourceArticle

logger = logging.getLogger(__name__)

try:
    from googlenewsdecoder import gnewsdecoder
except ImportError:  # pragma: no cover - dependency should be present in production
    logger.warning("Could not import googlenewsdecoder")
    gnewsdecoder = None


class RssSource:
    def __init__(
        self,
        feed_url: str,
        max_articles: int,
        timeout_seconds: int = 15,
        decode_google_news_urls: bool = True,
        source_name_override: str | None = None,
    ) -> None:
        self.feed_url = feed_url
        self.max_articles = max_articles
        self.timeout_seconds = timeout_seconds
        self.decode_google_news_urls = decode_google_news_urls
        self.source_name_override = source_name_override
        self._session = requests.Session()
        self._session.trust_env = False

    def _maybe_decode_google_news_url(self, url: str) -> str | None:
        logger.debug(
            "Google News decode check started decode_enabled=%s decoder_available=%s url=%s",
            self.decode_google_news_urls,
            gnewsdecoder is not None,
            url,
        )
        if not self.decode_google_news_urls:
            logger.debug("Google News decode skipped: feature disabled url=%s", url)
            return url

        parsed = urlparse(url)
        logger.debug(
            "Google News decode parsed URL scheme=%s netloc=%s path=%s query=%s",
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.query,
        )
        if parsed.netloc != "news.google.com":
            logger.debug(
                "Google News decode skipped: non-Google-News host netloc=%s url=%s",
                parsed.netloc,
                url,
            )
            return url
        if gnewsdecoder is None:
            logger.debug(
                "Google News decode unavailable: googlenewsdecoder missing, dropping Google News URL url=%s",
                url,
            )
            return None

        try:
            decoded = gnewsdecoder(url)
            logger.debug(
                "Google News decoder returned type=%s payload=%s",
                type(decoded).__name__,
                decoded,
            )
        except Exception as exc:
            logger.warning("Failed to decode Google News URL url=%s error=%s", url, exc)
            return None

        status = decoded.get("status") if isinstance(decoded, dict) else None
        decoded_url = decoded.get("decoded_url") if isinstance(decoded, dict) else None
        logger.debug(
            "Google News decode evaluation status=%s decoded_url_present=%s decoded_url=%s",
            status,
            bool(decoded_url),
            decoded_url,
        )

        if status and decoded_url:
            logger.debug("Google News link decoded original=%s decoded=%s", url, decoded_url)
            return str(decoded_url)

        logger.debug(
            "Google News decode failed status_or_decoded_url_missing original=%s payload=%s",
            url,
            decoded,
        )
        logger.debug(
            "Dropping undecoded Google News URL to avoid consent redirects original=%s",
            url,
        )
        return None

    def _download_feed(self) -> bytes:
        safe_feed_url = validate_public_http_url(self.feed_url, require_dns_resolution=False)
        response = self._session.get(
            safe_feed_url,
            timeout=self.timeout_seconds,
            headers={"User-Agent": "CyberNewsAlert/1.0 (+https://example.local)"},
        )
        response.raise_for_status()
        return response.content

    def fetch(self) -> list[SourceArticle]:
        try:
            feed_content = self._download_feed()
        except (requests.RequestException, UnsafeUrlError) as exc:
            logger.warning("Skipping RSS feed due to fetch failure feed_url=%s error=%s", self.feed_url, exc)
            return []

        parsed = feedparser.parse(feed_content)
        source_name = self.source_name_override or parsed.feed.get("title", self.feed_url)

        articles: list[SourceArticle] = []
        for entry in parsed.entries[: self.max_articles]:
            link = entry.get("link")
            title = entry.get("title")
            if not link or not title:
                continue
            decoded_link = self._maybe_decode_google_news_url(link)
            if not decoded_link:
                logger.debug(
                    "Skipping RSS entry because Google News URL could not be decoded title=%s original_url=%s",
                    title,
                    link,
                )
                continue

            try:
                link = validate_public_http_url(decoded_link, require_dns_resolution=False)
            except UnsafeUrlError as exc:
                logger.debug(
                    "Skipping RSS entry because URL failed safety checks title=%s url=%s error=%s",
                    title,
                    decoded_link,
                    exc,
                )
                continue

            published_at = None
            published_parsed = entry.get("published_parsed") or entry.get("updated_parsed")
            if published_parsed:
                published_at = datetime(*published_parsed[:6], tzinfo=timezone.utc)

            articles.append(
                SourceArticle(
                    source_name=source_name,
                    source_type="rss",
                    title=title,
                    url=link,
                    published_at=published_at,
                )
            )

        logger.info("Fetched %s RSS entries from %s", len(articles), self.feed_url)
        return articles
