from __future__ import annotations

import re
from urllib.parse import urlparse

LOW_SCORE_DUPLICATE_GUARD_THRESHOLD = 0.40
AGGREGATOR_SOURCE_NAMES = {"gdelt", "google news"}
PRIMARY_SOURCE_DOMAINS = {
    "bleepingcomputer.com",
    "cisa.gov",
    "darkreading.com",
    "google.com",
    "googleblog.com",
    "krebsonsecurity.com",
    "meta.com",
    "microsoft.com",
    "securityweek.com",
    "thehackernews.com",
    "therecord.media",
}
REWRITE_SOURCE_DOMAINS = {
    "benzinga.com",
    "itpro.com",
    "mexc.com",
    "newsbytesapp.com",
}
KNOWN_ENTITY_TERMS = {
    "acme",
    "cisa",
    "deepseek",
    "google",
    "meta",
    "microsoft",
    "nso",
    "openai",
    "whatsapp",
}
NAMED_ENTITY_TOKEN_RE = re.compile(r"\b[A-Z][A-Za-z0-9&.-]{2,}\b|\b[A-Z]{2,}\b")


def _clip(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len]


def _normalized_host(url: str) -> str:
    host = urlparse(url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def _host_matches(host: str, domains: set[str]) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in domains)


def _named_entity_terms(title: str) -> set[str]:
    title_without_source = title.rsplit(" - ", 1)[0]
    terms = set()
    for token in NAMED_ENTITY_TOKEN_RE.findall(title_without_source):
        normalized = token.strip(".,:;!?()[]{}").lower()
        if len(normalized) <= 2:
            continue
        if token.isupper() or any(char.isupper() for char in token[1:]) or normalized in KNOWN_ENTITY_TERMS:
            terms.add(normalized)
    return terms


def _shared_named_entity_terms(left_title: str, right_title: str) -> tuple[str, ...]:
    return tuple(sorted(_named_entity_terms(left_title) & _named_entity_terms(right_title)))
