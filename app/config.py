from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import List


DEFAULT_RSS_FEEDS = [
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://therecord.media/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://www.securityweek.com/feed/",
]

DEFAULT_GOOGLE_NEWS_QUERIES = [
    '(phishing OR "spear phishing" OR "business email compromise") (company OR government OR university OR hospital OR organization)',
    '(malvertising OR "credential theft" OR smishing OR vishing) (victim OR company OR organization)',
    '("SEO poisoning" OR "watering hole" OR "social media scam" OR "fake update" OR "brand impersonation" OR "employee impersonation" OR "executive impersonation" OR "tech support scam" OR "social engineering" OR deepfake OR "voice cloning") (cyber OR malware OR credentials OR phishing OR scam OR organization)',
]


@dataclass(frozen=True)
class Settings:
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    sender_email: str
    recipient_email: str
    database_url: str
    log_level: str
    request_timeout_seconds: int
    max_articles_per_source: int
    enable_gdelt: bool
    gdelt_query_window_minutes: int
    rss_feeds: List[str]
    google_news_queries: List[str]
    min_victim_confidence: float
    incident_dedupe_window_hours: int
    near_duplicate_enabled: bool
    near_duplicate_threshold: float
    near_duplicate_lookback_hours: int | None
    near_duplicate_max_comparisons: int
    suppress_out_of_scope_digest: bool
    digest_enabled: bool
    digest_recipient_email: str
    digest_max_items_per_run: int
    abstract_max_chars: int
    max_victim_words: int


class ConfigError(ValueError):
    pass


def _require(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise ConfigError(f"Missing required env var: {name}")
    return value


def _parse_list_env(name: str, default: List[str]) -> List[str]:
    value = os.getenv(name)
    if not value:
        return default

    value = value.strip()
    if value.startswith("["):
        try:
            parsed = json.loads(value)
            if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
                raise ConfigError(f"{name} must be a JSON string array")
            return [x.strip() for x in parsed if x.strip()]
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{name} contains invalid JSON: {exc}") from exc

    return [x.strip() for x in value.split(",") if x.strip()]


def load_settings() -> Settings:
    return Settings(
        smtp_host=_require("SMTP_HOST"),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_username=_require("SMTP_USERNAME"),
        smtp_password=_require("SMTP_PASSWORD"),
        sender_email=_require("SENDER_EMAIL"),
        recipient_email=_require("RECIPIENT_EMAIL"),
        database_url=_require("DATABASE_URL"),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        request_timeout_seconds=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "15")),
        max_articles_per_source=int(os.getenv("MAX_ARTICLES_PER_SOURCE", "50")),
        enable_gdelt=os.getenv("ENABLE_GDELT", "true").strip().lower() in {"1", "true", "yes"},
        gdelt_query_window_minutes=int(os.getenv("GDELT_QUERY_WINDOW_MINUTES", "180")),
        rss_feeds=_parse_list_env("RSS_FEEDS", DEFAULT_RSS_FEEDS),
        google_news_queries=_parse_list_env("GOOGLE_NEWS_QUERIES", DEFAULT_GOOGLE_NEWS_QUERIES),
        min_victim_confidence=float(os.getenv("MIN_VICTIM_CONFIDENCE", "0.65")),
        incident_dedupe_window_hours=int(os.getenv("INCIDENT_DEDUPE_WINDOW_HOURS", "48")),
        near_duplicate_enabled=os.getenv("NEAR_DUPLICATE_ENABLED", "true").strip().lower()
        in {"1", "true", "yes"},
        near_duplicate_threshold=float(os.getenv("NEAR_DUPLICATE_THRESHOLD", "0.78")),
        near_duplicate_lookback_hours=(
            int(os.getenv("NEAR_DUPLICATE_LOOKBACK_HOURS", "").strip())
            if os.getenv("NEAR_DUPLICATE_LOOKBACK_HOURS", "").strip()
            else None
        ),
        near_duplicate_max_comparisons=int(os.getenv("NEAR_DUPLICATE_MAX_COMPARISONS", "500")),
        suppress_out_of_scope_digest=os.getenv("SUPPRESS_OUT_OF_SCOPE_DIGEST", "true").strip().lower()
        in {"1", "true", "yes"},
        digest_enabled=os.getenv("DIGEST_ENABLED", "true").strip().lower() in {"1", "true", "yes"},
        digest_recipient_email=os.getenv("DIGEST_RECIPIENT_EMAIL", os.getenv("RECIPIENT_EMAIL", "")).strip()
        or _require("RECIPIENT_EMAIL"),
        digest_max_items_per_run=int(os.getenv("DIGEST_MAX_ITEMS_PER_RUN", "100")),
        abstract_max_chars=int(os.getenv("ABSTRACT_MAX_CHARS", "420")),
        max_victim_words=int(os.getenv("MAX_VICTIM_WORDS", "8")),
    )
