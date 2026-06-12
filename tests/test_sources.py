from __future__ import annotations

import requests

from app.sources.rss import RssSource


class _FeedResponse:
    content = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Example Feed</title>
    <item>
      <title>Acme Corp attacked in phishing</title>
      <link>https://example.com/article</link>
      <pubDate>Mon, 01 Jun 2026 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

    def raise_for_status(self) -> None:
        return None


def test_rss_source_fetches_with_timeout_and_isolated_session(monkeypatch) -> None:
    source = RssSource("https://example.com/feed.xml", max_articles=5, timeout_seconds=7)
    captured: dict[str, object] = {}

    def fake_get(url: str, *, timeout: int, headers: dict[str, str]) -> _FeedResponse:
        captured["url"] = url
        captured["timeout"] = timeout
        captured["headers"] = headers
        return _FeedResponse()

    monkeypatch.setattr(source._session, "get", fake_get)

    articles = source.fetch()

    assert source._session.trust_env is False
    assert captured["url"] == "https://example.com/feed.xml"
    assert captured["timeout"] == 7
    assert "CyberNewsAlert" in captured["headers"]["User-Agent"]
    assert len(articles) == 1
    assert articles[0].source_name == "Example Feed"
    assert articles[0].url == "https://example.com/article"


def test_rss_source_rejects_unsafe_feed_url(monkeypatch) -> None:
    source = RssSource("http://127.0.0.1/feed.xml", max_articles=5)

    def fail_get(url: str, *, timeout: int, headers: dict[str, str]) -> _FeedResponse:
        del url, timeout, headers
        raise AssertionError("unsafe feed URL should not be fetched")

    monkeypatch.setattr(source._session, "get", fail_get)

    assert source.fetch() == []


def test_rss_source_returns_empty_on_fetch_failure(monkeypatch) -> None:
    source = RssSource("https://example.com/feed.xml", max_articles=5)

    def fake_get(url: str, *, timeout: int, headers: dict[str, str]) -> _FeedResponse:
        del url, timeout, headers
        raise requests.Timeout("slow feed")

    monkeypatch.setattr(source._session, "get", fake_get)

    assert source.fetch() == []
