from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from html import unescape
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.fetch.url_guard import UnsafeUrlError, validate_public_http_url

logger = logging.getLogger(__name__)

SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
MEANINGFUL_SENTENCE_RE = re.compile(r"[A-Za-z]{3,}")
NOISE_SENTENCE_RE = re.compile(
    (
        r"\b(menu|news search|share on|write for us|comment|features|lifestyle|fashion|film|"
        r"whatsapp|linkedin|advertisement|subscribe|cookie policy|privacy policy|follow us|"
        r"unlock left|cancel subscription|queue update required|flash plugin)\b"
    ),
    re.I,
)
BOILERPLATE_ATTR_TOKENS = {
    "nav",
    "menu",
    "header",
    "footer",
    "promo",
    "advert",
    "advertisement",
    "ad",
    "share",
    "social",
    "cookie",
    "newsletter",
    "subscribe",
}
CONTENT_ATTR_VALUES = {
    "article-body",
    "article-content",
    "entry-content",
    "post-content",
    "single-post-content",
    "td-post-content",
}
ARTICLE_CONTENT_SELECTORS = (
    ".entry-content",
    ".post-content",
    ".single-post-content",
    ".td-post-content",
    "[itemprop='articleBody']",
    "article",
    "main",
)
ALLOWED_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "application/xml",
    "text/xml",
)


@dataclass(frozen=True)
class ArticleContent:
    full_text: str
    abstract: str


class ArticleFetcher:
    def __init__(
        self,
        timeout_seconds: int,
        abstract_max_chars: int = 420,
        max_redirect_hops: int = 5,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.abstract_max_chars = abstract_max_chars
        self.max_redirect_hops = max_redirect_hops
        self.max_response_bytes = max_response_bytes
        self.user_agent = "CyberNewsAlert/1.0 (+https://example.local)"
        self._session = requests.Session()
        self._session.trust_env = False

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=8),
        retry=retry_if_exception_type(requests.RequestException),
    )
    def _download(self, url: str) -> str:
        current_url = validate_public_http_url(url)

        for _ in range(self.max_redirect_hops + 1):
            with self._session.get(
                current_url,
                timeout=self.timeout_seconds,
                headers={"User-Agent": self.user_agent},
                allow_redirects=False,
                stream=True,
            ) as response:
                if response.is_redirect or response.is_permanent_redirect:
                    location = response.headers.get("Location")
                    if not location:
                        raise requests.RequestException("Redirect response missing Location header")
                    current_url = validate_public_http_url(urljoin(current_url, location))
                    continue

                response.raise_for_status()
                self._enforce_content_type(response.headers.get("Content-Type"))
                return self._read_body_with_limit(response)

        raise requests.TooManyRedirects(f"Exceeded redirect hop limit for url={url}")

    def fetch(self, url: str) -> ArticleContent | None:
        try:
            html = self._download(url)
        except (requests.RequestException, UnsafeUrlError) as exc:
            logger.warning("Failed to fetch article url=%s error=%s", url, exc)
            return None

        soup = BeautifulSoup(html, "html.parser")
        text = self._extract_text(soup)
        if not text:
            return None

        metadata_abstract = self._extract_metadata_abstract(soup)
        abstract = self._extract_abstract(text, metadata_abstract=metadata_abstract)
        if not abstract:
            return None

        return ArticleContent(full_text=text, abstract=abstract)

    def _enforce_content_type(self, content_type: str | None) -> None:
        if not content_type:
            return

        lowered = content_type.lower()
        if any(allowed in lowered for allowed in ALLOWED_CONTENT_TYPES):
            return
        raise requests.RequestException(f"Unsupported content type: {content_type}")

    def _read_body_with_limit(self, response: requests.Response) -> str:
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.max_response_bytes:
                    raise requests.RequestException(
                        f"Response too large content_length={content_length} limit={self.max_response_bytes}"
                    )
            except ValueError:
                logger.debug("Ignoring non-numeric Content-Length value=%s", content_length)

        raw = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            raw.extend(chunk)
            if len(raw) > self.max_response_bytes:
                raise requests.RequestException(
                    f"Response exceeded byte limit limit={self.max_response_bytes}"
                )

        encoding = response.encoding or "utf-8"
        return raw.decode(encoding, errors="replace")

    def _extract_text(self, soup: BeautifulSoup) -> str:
        for tag in soup(["script", "style", "noscript", "header", "footer", "nav", "form", "aside"]):
            tag.decompose()

        for node in soup.find_all(True):
            attrs_obj = getattr(node, "attrs", None)
            if not isinstance(attrs_obj, dict):
                node.attrs = {}
                continue

            if self._is_boilerplate_node(attrs_obj):
                node.decompose()

        for selector in ARTICLE_CONTENT_SELECTORS:
            candidates = []
            for node in soup.select(selector):
                text = node.get_text(" ", strip=True)
                if len(text) > 400:
                    candidates.append(text)
            if candidates:
                return self._normalize_extracted_text(max(candidates, key=len))

        body = soup.select_one("body")
        fallback = body.get_text(" ", strip=True) if body else soup.get_text(" ", strip=True)
        return self._normalize_extracted_text(fallback)

    def _normalize_extracted_text(self, text: str) -> str:
        normalized = re.sub(r"\s+", " ", unescape(text)).strip()
        normalized = re.sub(r"\bAdvertisement\b", "", normalized, flags=re.I)
        normalized = re.sub(r"\s+", " ", normalized).strip()
        return normalized

    def _is_boilerplate_node(self, attrs: dict[str, object]) -> bool:
        values: list[str] = []
        node_id = attrs.get("id")
        if isinstance(node_id, str):
            values.append(node_id)

        class_value = attrs.get("class")
        if isinstance(class_value, list):
            values.extend(str(value) for value in class_value)
        elif isinstance(class_value, str):
            values.extend(class_value.split())

        return any(self._is_boilerplate_attr_value(value) for value in values)

    def _is_boilerplate_attr_value(self, value: str) -> bool:
        normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
        if not normalized:
            return False
        if normalized in CONTENT_ATTR_VALUES:
            return False
        if normalized.startswith(("entry-content", "post-content", "single-post-content", "td-post-content")):
            return False
        if normalized.startswith(("no-", "without-", "disable-", "disabled-")):
            return False

        tokens = [token for token in normalized.split("-") if token]
        return any(token in BOILERPLATE_ATTR_TOKENS for token in tokens)

    def _extract_metadata_abstract(self, soup: BeautifulSoup) -> str:
        for key, value in (
            ("property", "og:description"),
            ("name", "description"),
        ):
            tag = soup.find("meta", attrs={key: value})
            if tag and tag.get("content"):
                content = re.sub(r"\s+", " ", str(tag["content"]).strip())
                if len(content) >= 50 and not self._is_noisy_sentence(content):
                    return content
        return ""

    def _extract_abstract(self, text: str, metadata_abstract: str = "", max_sentences: int = 3) -> str:
        sentences = SENTENCE_SPLIT_RE.split(text)
        kept: list[str] = []

        for sentence in sentences:
            candidate = sentence.strip()
            if len(candidate) < 40:
                continue
            if not MEANINGFUL_SENTENCE_RE.search(candidate):
                continue
            if self._is_noisy_sentence(candidate):
                continue
            if not self._has_alpha_density(candidate):
                continue
            kept.append(candidate)
            if len(kept) >= max_sentences:
                break

        abstract = " ".join(kept)
        if not abstract and metadata_abstract:
            abstract = metadata_abstract
        if len(abstract) <= self.abstract_max_chars:
            return abstract
        return self._clip_sentence_boundary(abstract, self.abstract_max_chars)

    def _is_noisy_sentence(self, sentence: str) -> bool:
        if NOISE_SENTENCE_RE.search(sentence):
            return True
        if sentence.count("|") >= 2:
            return True
        if sentence.count(" 20") >= 3:
            return True
        if sentence.count(",") > 8:
            return True
        return False

    def _has_alpha_density(self, sentence: str) -> bool:
        letters = sum(1 for ch in sentence if ch.isalpha())
        total = max(len(sentence), 1)
        return (letters / total) >= 0.55

    def _clip_sentence_boundary(self, text: str, max_chars: int) -> str:
        sentences = [s.strip() for s in SENTENCE_SPLIT_RE.split(text) if s.strip()]
        kept: list[str] = []
        for sentence in sentences:
            candidate = " ".join(kept + [sentence]).strip()
            if len(candidate) <= max_chars:
                kept.append(sentence)
                continue
            break
        if kept:
            result = " ".join(kept).strip()
            return result if result.endswith((".", "!", "?")) else f"{result}."

        for sentence in sentences:
            if len(sentence) <= max_chars:
                return sentence if sentence.endswith((".", "!", "?")) else f"{sentence}."

        clipped = text[:max_chars].rstrip()
        last_space = clipped.rfind(" ")
        if last_space >= 40:
            clipped = clipped[:last_space]
        return clipped
