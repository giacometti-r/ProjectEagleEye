from __future__ import annotations

import requests
import pytest
from bs4 import BeautifulSoup

from app.fetch.article_fetcher import ArticleFetcher
from app.fetch.url_guard import UnsafeUrlError, validate_public_http_url


class _MockResponse:
    def __init__(self, status_code: int, headers: dict[str, str] | None = None, body: bytes = b"") -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body
        self.encoding = "utf-8"

    @property
    def is_redirect(self) -> bool:
        return self.status_code in {301, 302, 303, 307, 308}

    @property
    def is_permanent_redirect(self) -> bool:
        return self.status_code in {301, 308}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status={self.status_code}")

    def iter_content(self, chunk_size: int = 8192) -> bytes:
        del chunk_size
        yield self._body

    def __enter__(self) -> _MockResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        del exc_type, exc, tb
        return False


def test_extract_abstract_filters_navigation_noise() -> None:
    fetcher = ArticleFetcher(timeout_seconds=5, abstract_max_chars=420)
    text = (
        "Menu News Comment Features Interviews Science Lifestyle Share on Twitter Share on WhatsApp. "
        "Since last week, students and staff at the University of Cambridge reported phishing emails "
        "sent from compromised university member accounts. "
        "The campaign requested gift-card shipping fees and administrators warned recipients not to pay. "
        "Write for us and follow our channels for more updates."
    )
    abstract = fetcher._extract_abstract(text)
    assert "Menu News Comment" not in abstract
    assert "Share on WhatsApp" not in abstract
    assert "University of Cambridge reported phishing emails" in abstract


def test_extract_abstract_clips_to_max_chars() -> None:
    fetcher = ArticleFetcher(timeout_seconds=5, abstract_max_chars=120)
    text = (
        "Investigators said Acme Corp was attacked in a phishing campaign that stole employee credentials "
        "and enabled mailbox access across several departments. "
        "The incident response team reset accounts and blocked malicious domains."
    )
    abstract = fetcher._extract_abstract(text)
    assert len(abstract) <= 120
    assert abstract.endswith(".")


def test_extract_abstract_uses_metadata_fallback_when_text_is_noisy() -> None:
    fetcher = ArticleFetcher(timeout_seconds=5, abstract_max_chars=180)
    text = "Menu Share on WhatsApp. Advertisement. Follow us. Subscribe."
    abstract = fetcher._extract_abstract(
        text,
        metadata_abstract="Researchers reported a phishing campaign targeting multiple organizations.",
    )
    assert "phishing campaign" in abstract


def test_extract_text_handles_tag_with_missing_attrs_dict() -> None:
    fetcher = ArticleFetcher(timeout_seconds=5, abstract_max_chars=180)
    soup = BeautifulSoup(
        "<html><body><article><p>Acme Corp was attacked in a phishing incident impacting employees.</p></article></body></html>",
        "html.parser",
    )
    tag = soup.find("article")
    assert tag is not None
    tag.attrs = None  # Simulate malformed tag state seen in production pages.

    text = fetcher._extract_text(soup)
    assert "Acme Corp was attacked in a phishing incident" in text


def test_extract_text_prefers_entry_content_with_no_share_class() -> None:
    fetcher = ArticleFetcher(timeout_seconds=5, abstract_max_chars=180)
    article_body = (
        "A newly identified cyber extortion operation is gaining attention among incident responders after "
        "security researchers uncovered a threat group using voice phishing, cloud data theft and aggressive "
        "extortion tactics to target organizations. "
    ) * 4
    soup = BeautifulSoup(
        (
            "<html><body>"
            "<div class='latest-news'>Unlock left : 0 Yes No Are you sure want to cancel subscription?</div>"
            "<div class='entry-content no-share'><p>"
            f"{article_body}"
            "</p></div>"
            "<div class='newsletter-signup'>Subscribe to our newsletter</div>"
            "</body></html>"
        ),
        "html.parser",
    )

    text = fetcher._extract_text(soup)

    assert text.startswith("A newly identified cyber extortion operation")
    assert "Unlock left" not in text
    assert "Subscribe to our newsletter" not in text


def test_extract_abstract_rejects_subscription_popup_noise() -> None:
    fetcher = ArticleFetcher(timeout_seconds=5, abstract_max_chars=180)
    abstract = fetcher._extract_abstract(
        "Unlock left : 0 Yes No Are you sure want to cancel subscription? Queue Update Required Flash plugin.",
        metadata_abstract="Researchers reported a cyber extortion operation targeting Microsoft 365 data.",
    )

    assert abstract == "Researchers reported a cyber extortion operation targeting Microsoft 365 data."


def test_validate_public_http_url_rejects_non_http_schemes() -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_http_url("file:///etc/passwd", require_dns_resolution=False)
    with pytest.raises(UnsafeUrlError):
        validate_public_http_url("ftp://example.com/resource", require_dns_resolution=False)


def test_validate_public_http_url_rejects_embedded_credentials() -> None:
    with pytest.raises(UnsafeUrlError):
        validate_public_http_url("https://user:pass@example.com/news", require_dns_resolution=False)


def test_validate_public_http_url_rejects_local_or_private_targets() -> None:
    blocked_urls = [
        "https://localhost/admin",
        "http://127.0.0.1/internal",
        "http://10.0.0.8/private",
        "http://169.254.1.10/linklocal",
        "http://224.0.0.9/multicast",
        "http://240.0.0.9/reserved",
    ]
    for candidate in blocked_urls:
        with pytest.raises(UnsafeUrlError):
            validate_public_http_url(candidate, require_dns_resolution=False)


def test_validate_public_http_url_allows_public_https_target() -> None:
    def fake_resolver(host: str, port: int, type: int) -> list[tuple[object, ...]]:  # noqa: A002
        del host, port, type
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    validated = validate_public_http_url("https://news.example.com/story", resolver=fake_resolver)
    assert validated == "https://news.example.com/story"


def test_download_rejects_private_redirect_target(monkeypatch: pytest.MonkeyPatch) -> None:
    fetcher = ArticleFetcher(timeout_seconds=5)
    redirect = _MockResponse(status_code=302, headers={"Location": "http://10.0.0.7/private"})
    calls: list[str] = []

    def fake_get(
        url: str,
        *,
        timeout: int,
        headers: dict[str, str],
        allow_redirects: bool,
        stream: bool,
    ) -> _MockResponse:
        del timeout, headers, allow_redirects, stream
        calls.append(url)
        return redirect

    def fake_validate(url: str, require_dns_resolution: bool = True) -> str:
        del require_dns_resolution
        if "10.0.0.7" in url:
            raise UnsafeUrlError("private redirect target")
        return url

    monkeypatch.setattr(fetcher._session, "get", fake_get)
    monkeypatch.setattr("app.fetch.article_fetcher.validate_public_http_url", fake_validate)

    with pytest.raises(UnsafeUrlError):
        fetcher._download("https://example.com/start")
    assert calls == ["https://example.com/start"]


def test_download_rejects_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    fetcher = ArticleFetcher(timeout_seconds=5, max_response_bytes=10)
    oversized = _MockResponse(
        status_code=200,
        headers={"Content-Type": "text/html", "Content-Length": "9999"},
        body=b"small",
    )

    def fake_get(
        url: str,
        *,
        timeout: int,
        headers: dict[str, str],
        allow_redirects: bool,
        stream: bool,
    ) -> _MockResponse:
        del url, timeout, headers, allow_redirects, stream
        return oversized

    monkeypatch.setattr(fetcher._session, "get", fake_get)
    monkeypatch.setattr("app.fetch.article_fetcher.validate_public_http_url", lambda u, require_dns_resolution=True: u)

    with pytest.raises(requests.RequestException):
        fetcher._download("https://example.com/start")
