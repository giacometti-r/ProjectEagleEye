from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import inspect, select

from app.alerts.emailer import AlertEmail, DigestEmailItem
from app.config import Settings
from app.db import Database
from app.dedup.deduplicator import (
    build_content_hash,
    build_fingerprint,
    build_similarity_document,
    build_topic_document,
    canonicalize_url,
)
from app.fetch.article_fetcher import ArticleContent
from app.models import Alert, Article, ArticleFingerprint
from app.pipeline import MonitorPipeline, PipelineMetrics
from app.pipeline.state import _FetchedCandidate, _RunDedupeContext
from app.schema_init import initialize_schema
from app.sources.base import SourceArticle


class FakeFetcher:
    def __init__(self, content: ArticleContent) -> None:
        self.content = content

    def fetch(self, url: str) -> ArticleContent | None:
        return self.content


class UrlMapFetcher(FakeFetcher):
    def __init__(self, content_by_url: dict[str, ArticleContent]) -> None:
        self.content_by_url = content_by_url
        super().__init__(ArticleContent(full_text="", abstract=""))

    def fetch(self, url: str) -> ArticleContent | None:
        return self.content_by_url[url]


class CountingUrlMapFetcher(UrlMapFetcher):
    def __init__(self, content_by_url: dict[str, ArticleContent]) -> None:
        self.calls: list[str] = []
        super().__init__(content_by_url)

    def fetch(self, url: str) -> ArticleContent | None:
        self.calls.append(url)
        return super().fetch(url)


class FakeClassifier:
    @dataclass(frozen=True)
    class Result:
        article_type: str
        attack_type: str | None
        attack_confidence: float
        incident_confidence: float
        reasons: tuple[str, ...]

    def classify(self, title: str, text: str) -> Result:
        return self.Result(
            article_type="incident",
            attack_type="phishing",
            attack_confidence=0.9,
            incident_confidence=0.9,
            reasons=("incident-evidence",),
        )


class OutOfTaxonomyClassifier(FakeClassifier):
    def classify(self, title: str, text: str) -> FakeClassifier.Result:
        return self.Result(
            article_type="incident",
            attack_type=None,
            attack_confidence=0.2,
            incident_confidence=0.95,
            reasons=("out-of-taxonomy",),
        )


class OutOfScopeClassifier(FakeClassifier):
    def classify(self, title: str, text: str) -> FakeClassifier.Result:
        return self.Result(
            article_type="out_of_scope",
            attack_type=None,
            attack_confidence=0.0,
            incident_confidence=0.0,
            reasons=("out-of-scope",),
        )


class FakeVictimExtractor:
    @dataclass(frozen=True)
    class Result:
        victim_name: str | None
        victim_category: str | None
        confidence: float
        reason: str

    def extract(self, title: str, text: str) -> Result:
        return self.Result(victim_name="Acme Corp", victim_category="company", confidence=0.9, reason="matched_title")


class LowConfidenceVictimExtractor(FakeVictimExtractor):
    def extract(self, title: str, text: str) -> FakeVictimExtractor.Result:
        return self.Result(victim_name=None, victim_category=None, confidence=0.1, reason="no_named_org")


class FakeEmailer:
    recipient_email = "to@example.com"

    def __init__(self) -> None:
        self.sent: list[tuple[AlertEmail, str | None]] = []

    def build_subject(self, victim_name: str, victim_category: str, attack_type: str) -> str:
        return f"{victim_name} was attacked using {attack_type}"

    def build_body(self, **kwargs: str) -> str:
        return f"body:{kwargs['attack_type']}:{kwargs['victim_name']}"

    def build_digest_subject(self, item_count: int) -> str:
        return f"digest:{item_count}"

    def build_digest_body(self, items: list[DigestEmailItem]) -> str:
        return "\n".join(f"{item.routing_reason}:{item.title}" for item in items)

    def send(self, email: AlertEmail, recipient_email: str | None = None) -> None:
        self.sent.append((email, recipient_email))


class FailingEmailer(FakeEmailer):
    def send(self, email: AlertEmail, recipient_email: str | None = None) -> None:
        raise RuntimeError("smtp down")


def _settings(db_url: str) -> Settings:
    return Settings(
        smtp_host="smtp",
        smtp_port=587,
        smtp_username="u",
        smtp_password="p",
        sender_email="from@example.com",
        recipient_email="to@example.com",
        database_url=db_url,
        log_level="INFO",
        request_timeout_seconds=5,
        max_articles_per_source=10,
        max_article_age_hours=168,
        enable_gdelt=False,
        gdelt_query_window_minutes=180,
        rss_feeds=[],
        google_news_queries=[],
        min_victim_confidence=0.65,
        incident_dedupe_window_hours=48,
        near_duplicate_enabled=True,
        stored_near_duplicate_threshold=0.38,
        current_run_near_duplicate_threshold=0.34,
        near_duplicate_lookback_hours=None,
        near_duplicate_max_comparisons=500,
        suppress_out_of_scope_digest=True,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        digest_max_items_per_run=100,
        digest_topic_dedupe_enabled=True,
        digest_topic_dedupe_threshold=0.40,
        digest_topic_dedupe_lookback_hours=168,
        abstract_max_chars=420,
        max_victim_words=8,
    )


def test_pipeline_sends_once_for_canonical_duplicates() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = FakeFetcher(ArticleContent(full_text="attack text", abstract="first sentence. second sentence."))
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
        near_duplicate_enabled=False,
    )

    articles = [
        SourceArticle(
            source_name="s1",
            source_type="rss",
            title="Acme Corp attacked in phishing",
            url="https://example.com/article?utm_source=news",
            published_at=datetime.now(timezone.utc),
        ),
        SourceArticle(
            source_name="s2",
            source_type="rss",
            title="Acme Corp attacked in phishing",
            url="https://example.com/article",
            published_at=datetime.now(timezone.utc),
        ),
    ]

    metrics = pipeline.run(articles)
    assert metrics.alerts_sent == 1
    assert metrics.digest_queued == 0
    assert metrics.digest_sent == 0
    assert len(emailer.sent) == 1

    with database.session() as session:
        alert = session.scalar(select(Alert))
        assert alert is not None
        assert alert.channel == "immediate"
        assert alert.status == "sent"


def test_pipeline_current_run_canonical_duplicate_keeps_newest() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/article?utm_source=old": ArticleContent(
                full_text="old article body about a phishing incident",
                abstract="old phishing incident.",
            ),
            "https://example.com/article": ArticleContent(
                full_text="new article body about a phishing incident",
                abstract="new phishing incident.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
        near_duplicate_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("old", "rss", "Old canonical duplicate", "https://example.com/article?utm_source=old", now),
            SourceArticle("new", "rss", "New canonical duplicate", "https://example.com/article", now + timedelta(minutes=10)),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 1
    assert metrics.skipped == 1
    assert len(emailer.sent) == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        alerts = session.scalars(select(Alert)).all()
        assert len(articles) == 1
        assert len(alerts) == 1
        assert articles[0].url == "https://example.com/article"
        assert articles[0].title == "New canonical duplicate"


def test_pipeline_current_run_content_hash_duplicate_keeps_newest() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    shared_content = ArticleContent(
        full_text="same fetched article body about Acme Corp phishing",
        abstract="same fetched article abstract.",
    )
    fetcher = UrlMapFetcher(
        {
            "https://example.com/old-content": shared_content,
            "https://example.com/new-content": shared_content,
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
        near_duplicate_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("old", "rss", "Old content duplicate", "https://example.com/old-content", now),
            SourceArticle("new", "rss", "New content duplicate", "https://example.com/new-content", now + timedelta(minutes=10)),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 1
    assert metrics.skipped == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://example.com/new-content"


def test_pipeline_current_run_fingerprint_duplicate_keeps_newest() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    shared_prefix = "Acme Corp phishing incident " * 120
    fetcher = UrlMapFetcher(
        {
            "https://example.com/old-fingerprint": ArticleContent(
                full_text=f"{shared_prefix}old trailing details",
                abstract="old fingerprint duplicate.",
            ),
            "https://example.com/new-fingerprint": ArticleContent(
                full_text=f"{shared_prefix}new trailing details",
                abstract="new fingerprint duplicate.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
        near_duplicate_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("old", "rss", "Same fingerprint title", "https://example.com/old-fingerprint", now),
            SourceArticle("new", "rss", "Same fingerprint title", "https://example.com/new-fingerprint", now + timedelta(minutes=10)),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 1
    assert metrics.skipped == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://example.com/new-fingerprint"


def test_pipeline_current_run_near_duplicate_keeps_newest_when_enabled() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/old-near": ArticleContent(
                full_text="WhatsApp disrupted NSO spyware phishing attacks against users.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing attacks.",
            ),
            "https://example.com/new-near": ArticleContent(
                full_text="Meta said WhatsApp disrupted new spyware phishing attacks linked to NSO Group.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "old",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks - BleepingComputer",
                "https://example.com/old-near",
                now,
            ),
            SourceArticle(
                "new",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks",
                "https://example.com/new-near",
                now + timedelta(minutes=10),
            ),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 1
    assert metrics.skipped == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://example.com/new-near"


def test_pipeline_current_run_duplicate_prefers_primary_source_over_newer_rewrite(caplog) -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://www.microsoft.com/en-us/security/blog/ai-brands-as-bait": ArticleContent(
                full_text=(
                    "Microsoft Threat Intelligence observed phishing, malvertising, and SEO poisoning "
                    "campaigns using AI brands as bait. Attackers impersonated OpenAI, Anthropic, and "
                    "DeepSeek to lure victims into credential theft pages and malicious downloads."
                ),
                abstract="Researchers reported an uptick in attacks.",
            ),
            "https://www.itpro.com/security/cyber-attacks/ai-hype-social-engineering": ArticleContent(
                full_text=(
                    "Threat actors are using trusted AI brands as bait in phishing, malvertising, and "
                    "search engine optimization abuse. Campaigns impersonate OpenAI, Anthropic, and "
                    "DeepSeek to lure victims into credential theft pages and malicious downloads."
                ),
                abstract="Security researchers warned about evolving social engineering activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    caplog.set_level(logging.INFO, logger="app.pipeline")
    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "AI brands as bait: How threat actors are using the AI hype in social engineering - Microsoft",
                "https://www.microsoft.com/en-us/security/blog/ai-brands-as-bait",
                now,
            ),
            SourceArticle(
                "Google News",
                "rss",
                "Hackers are capitalizing on AI hype to ramp up social engineering attacks - IT Pro",
                "https://www.itpro.com/security/cyber-attacks/ai-hype-social-engineering",
                now + timedelta(minutes=10),
            ),
        ]
    )

    assert metrics.alerts_sent == 1
    assert metrics.skipped == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://www.microsoft.com/en-us/security/blog/ai-brands-as-bait"

    assert "reason=near_similarity" in caplog.text
    assert "title=Hackers are capitalizing on AI hype" in caplog.text
    assert "survivor_title=AI brands as bait" in caplog.text
    assert "similarity_score=" in caplog.text


def test_pipeline_current_run_threshold_controls_current_matches() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/old-near": ArticleContent(
                full_text="WhatsApp disrupted NSO spyware phishing attacks against users.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing attacks.",
            ),
            "https://example.com/new-near": ArticleContent(
                full_text="Meta said WhatsApp disrupted new spyware attacks linked to NSO Group.",
                abstract="WhatsApp disrupted NSO-linked spyware activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        current_run_near_duplicate_threshold=0.90,
        digest_recipient_email="digest@example.com",
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("s1", "rss", "WhatsApp disrupts NSO spyware phishing", "https://example.com/old-near", now),
            SourceArticle(
                "s2",
                "rss",
                "Meta says WhatsApp disrupted NSO spyware",
                "https://example.com/new-near",
                now + timedelta(minutes=5),
            ),
        ]
    )

    assert metrics.skipped == 0
    assert metrics.digest_queued == 2

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2


def test_pipeline_low_score_near_duplicate_skips_with_salient_title_overlap() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/payroll-one": ArticleContent(
                full_text="Acme employees received phishing emails that used fake login pages to steal credentials.",
                abstract="",
            ),
            "https://example.com/payroll-two": ArticleContent(
                full_text="Acme staff were warned about phishing messages with fake login pages designed to steal credentials.",
                abstract="",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        current_run_near_duplicate_threshold=0.30,
        digest_recipient_email="digest@example.com",
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "s1",
                "rss",
                "Acme payroll scam targets employees",
                "https://example.com/payroll-one",
                now,
            ),
            SourceArticle(
                "s2",
                "rss",
                "Acme payroll scam warning for staff",
                "https://example.com/payroll-two",
                now + timedelta(minutes=5),
            ),
        ]
    )

    assert metrics.skipped == 1
    assert metrics.digest_queued == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 1


def test_pipeline_low_score_near_duplicate_survives_without_title_or_entity_overlap() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/chrome": ArticleContent(
                full_text="Acme employees received phishing emails that used fake login pages to steal credentials.",
                abstract="",
            ),
            "https://example.com/exchange": ArticleContent(
                full_text="Acme staff were warned about phishing messages with fake login pages designed to steal credentials.",
                abstract="",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        current_run_near_duplicate_threshold=0.30,
        digest_recipient_email="digest@example.com",
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("s1", "rss", "Chrome flaw exploited in attacks", "https://example.com/chrome", now),
            SourceArticle(
                "s2",
                "rss",
                "Microsoft Exchange zero-day patched",
                "https://example.com/exchange",
                now + timedelta(minutes=5),
            ),
        ]
    )

    assert metrics.skipped == 0
    assert metrics.digest_queued == 2

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2


def test_pipeline_borderline_near_duplicate_survives_without_title_or_entity_overlap() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/chrome": ArticleContent(
                full_text=(
                    "Employees received phishing emails that used fake login pages to steal credentials. "
                    "The messages copied company branding and asked staff to reset passwords. Security teams "
                    "found the campaign used lookalike domains and credential harvesting forms."
                ),
                abstract="",
            ),
            "https://example.com/exchange": ArticleContent(
                full_text=(
                    "Staff were warned about phishing messages with fake login pages designed to steal credentials. "
                    "The campaign copied company branding and asked employees to reset passwords. Analysts found "
                    "lookalike domains and credential harvesting forms."
                ),
                abstract="",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        current_run_near_duplicate_threshold=0.30,
        digest_recipient_email="digest@example.com",
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("s1", "rss", "Chrome flaw exploited in attacks", "https://example.com/chrome", now),
            SourceArticle(
                "s2",
                "rss",
                "Microsoft Exchange zero-day patched",
                "https://example.com/exchange",
                now + timedelta(minutes=5),
            ),
        ]
    )

    assert metrics.skipped == 0
    assert metrics.digest_queued == 2

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2


def test_pipeline_high_score_near_duplicate_skips_without_title_overlap() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/chrome": ArticleContent(
                full_text=(
                    "Employees received phishing emails that used fake login pages to steal credentials. "
                    "The messages copied company branding and asked staff to reset passwords. Security teams "
                    "found the campaign used lookalike domains and credential harvesting forms. Attackers "
                    "registered domains that imitated the company portal and sent lures through compromised mailboxes."
                ),
                abstract="",
            ),
            "https://example.com/exchange": ArticleContent(
                full_text=(
                    "Staff were warned about phishing messages with fake login pages designed to steal credentials. "
                    "The campaign copied company branding and asked employees to reset passwords. Analysts found "
                    "lookalike domains and credential harvesting forms. Attackers registered domains that imitated "
                    "the company portal and sent lures through compromised mailboxes."
                ),
                abstract="",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        current_run_near_duplicate_threshold=0.30,
        digest_recipient_email="digest@example.com",
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("s1", "rss", "Chrome flaw exploited in attacks", "https://example.com/chrome", now),
            SourceArticle(
                "s2",
                "rss",
                "Microsoft Exchange zero-day patched",
                "https://example.com/exchange",
                now + timedelta(minutes=5),
            ),
        ]
    )

    assert metrics.skipped == 1
    assert metrics.digest_queued == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 1


def test_pipeline_current_run_near_duplicates_both_survive_when_disabled() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/old-near": ArticleContent(
                full_text="WhatsApp disrupted NSO spyware phishing attacks against users.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing attacks.",
            ),
            "https://example.com/new-near": ArticleContent(
                full_text="Meta said WhatsApp disrupted new spyware phishing attacks linked to NSO Group.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        near_duplicate_enabled=False,
        digest_recipient_email="digest@example.com",
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "old",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks - BleepingComputer",
                "https://example.com/old-near",
                now,
            ),
            SourceArticle(
                "new",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks",
                "https://example.com/new-near",
                now + timedelta(minutes=10),
            ),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 2
    assert metrics.digest_sent == 1
    assert metrics.skipped == 0
    assert len(emailer.sent) == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2
        assert len(session.scalars(select(Alert)).all()) == 2


def test_pipeline_current_run_duplicate_loser_is_not_persisted_or_in_digest() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    shared_content = ArticleContent(
        full_text="shared low confidence article body",
        abstract="shared low confidence abstract.",
    )
    fetcher = UrlMapFetcher(
        {
            "https://example.com/digest-loser": shared_content,
            "https://example.com/digest-survivor": shared_content,
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("old", "rss", "Digest Loser", "https://example.com/digest-loser", now),
            SourceArticle("new", "rss", "Digest Survivor", "https://example.com/digest-survivor", now + timedelta(minutes=10)),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 1
    assert metrics.digest_sent == 1
    assert metrics.skipped == 1
    assert len(emailer.sent) == 1
    digest_body = emailer.sent[0][0].body
    assert "Digest Survivor" in digest_body
    assert "Digest Loser" not in digest_body

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        alerts = session.scalars(select(Alert)).all()
        assert len(articles) == 1
        assert len(alerts) == 1
        assert articles[0].title == "Digest Survivor"


def test_pipeline_routes_low_confidence_victim_to_digest() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = FakeFetcher(ArticleContent(full_text="attack text", abstract="first sentence. second sentence."))
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
    )

    article = SourceArticle(
        source_name="s1",
        source_type="rss",
        title="Attackers targeted officials in phishing",
        url="https://example.com/article-fallback",
        published_at=datetime.now(timezone.utc),
    )

    metrics = pipeline.run([article])
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 1
    assert metrics.digest_sent == 1
    assert len(emailer.sent) == 1
    assert emailer.sent[0][1] == "digest@example.com"

    with database.session() as session:
        alert = session.scalar(select(Alert))
        assert alert is not None
        assert alert.channel == "digest"
        assert alert.routing_reason == "low_victim_confidence"
        assert alert.status == "sent"


def test_pipeline_skips_duplicate_incident_without_digest() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/one": ArticleContent(
                full_text="initial phishing incident text",
                abstract="first sentence. second sentence.",
            ),
            "https://example.com/two": ArticleContent(
                full_text="follow up phishing incident text with new details",
                abstract="follow up sentence. second sentence.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        near_duplicate_enabled=False,
    )

    now = datetime.now(timezone.utc)
    articles = [
        SourceArticle(
            source_name="s1",
            source_type="rss",
            title="Acme Corp attacked in phishing",
            url="https://example.com/one",
            published_at=now,
        ),
        SourceArticle(
            source_name="s2",
            source_type="rss",
            title="Acme Corp attacked in phishing follow-up",
            url="https://example.com/two",
            published_at=now + timedelta(minutes=10),
        ),
    ]

    metrics = pipeline.run(articles)
    assert metrics.alerts_sent == 1
    assert metrics.digest_queued == 0
    assert metrics.digest_sent == 0
    assert metrics.skipped == 1
    assert len(emailer.sent) == 1

    with database.session() as session:
        alerts = session.scalars(select(Alert).order_by(Alert.id)).all()
        articles = session.scalars(select(Article).order_by(Article.id)).all()
        assert len(articles) == 1
        assert len(alerts) == 1
        assert alerts[0].channel == "immediate"


def test_pipeline_skips_digest_topic_duplicate() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/meta-one": ArticleContent(
                full_text="Meta said NSO spyware operators targeted WhatsApp users with one-click phishing attempts.",
                abstract="Meta said NSO spyware operators targeted WhatsApp users with one-click phishing attempts.",
            ),
            "https://example.com/meta-two": ArticleContent(
                full_text="These attempts were similar to previous one-click phishing campaigns aimed at WhatsApp users.",
                abstract="These attempts were similar to previous one-click phishing campaigns aimed at WhatsApp users.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        near_duplicate_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "first",
                "rss",
                "Meta to take legal action against Israeli spyware company NSO - Al Jazeera",
                "https://example.com/meta-one",
                now + timedelta(minutes=10),
            ),
            SourceArticle(
                "second",
                "rss",
                "Meta takes legal action against Israeli spyware firm NSO - The Straits Times",
                "https://example.com/meta-two",
                now,
            ),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 1
    assert metrics.digest_sent == 1
    assert metrics.skipped == 1
    assert len(emailer.sent) == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        alerts = session.scalars(select(Alert)).all()
        assert len(articles) == 1
        assert len(alerts) == 1
        assert articles[0].url == "https://example.com/meta-one"


def test_pipeline_skips_digest_topic_duplicate_using_article_text() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/ai-one": ArticleContent(
                full_text=(
                    "Microsoft Threat Intelligence observed phishing, malvertising, and SEO poisoning "
                    "campaigns using AI brands as bait. Attackers impersonated OpenAI, Anthropic, and "
                    "DeepSeek to lure victims into credential theft pages and malicious downloads."
                ),
                abstract="Researchers reported an uptick in attacks.",
            ),
            "https://example.com/ai-two": ArticleContent(
                full_text=(
                    "Threat actors are using trusted AI brands as bait in phishing, malvertising, and "
                    "search engine optimization abuse. Campaigns impersonate OpenAI, Anthropic, and "
                    "DeepSeek to lure victims into credential theft pages and malicious downloads."
                ),
                abstract="Security researchers warned about evolving social engineering activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        near_duplicate_enabled=False,
        digest_topic_dedupe_threshold=0.35,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "first",
                "rss",
                "Hackers are capitalizing on AI hype to ramp up social engineering attacks - IT Pro",
                "https://example.com/ai-one",
                now + timedelta(minutes=10),
            ),
            SourceArticle(
                "second",
                "rss",
                "AI brands as bait: How threat actors are using the AI hype in social engineering - Microsoft",
                "https://example.com/ai-two",
                now,
            ),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 1
    assert metrics.digest_sent == 1
    assert metrics.skipped == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 1
        assert len(session.scalars(select(Alert)).all()) == 1


def test_pipeline_digest_topic_threshold_controls_digest_matches() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/meta-one": ArticleContent(
                full_text="Meta said NSO spyware operators targeted WhatsApp users with one-click phishing attempts.",
                abstract="Meta said NSO spyware operators targeted WhatsApp users with one-click phishing attempts.",
            ),
            "https://example.com/meta-two": ArticleContent(
                full_text="These attempts were similar to previous one-click phishing campaigns aimed at WhatsApp users.",
                abstract="These attempts were similar to previous one-click phishing campaigns aimed at WhatsApp users.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        near_duplicate_enabled=False,
        digest_topic_dedupe_threshold=0.90,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "first",
                "rss",
                "Meta to take legal action against Israeli spyware company NSO - Al Jazeera",
                "https://example.com/meta-one",
                now + timedelta(minutes=10),
            ),
            SourceArticle(
                "second",
                "rss",
                "Meta takes legal action against Israeli spyware firm NSO - The Straits Times",
                "https://example.com/meta-two",
                now,
            ),
        ]
    )

    assert metrics.skipped == 0
    assert metrics.digest_queued == 2

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2
        assert len(session.scalars(select(Alert)).all()) == 2


def test_pipeline_keeps_digest_items_with_only_generic_title_overlap() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/teams": ArticleContent(
                full_text="Microsoft Teams will add warnings for suspicious brand impersonation calls.",
                abstract="Microsoft Teams will add warnings for suspicious brand impersonation calls.",
            ),
            "https://example.com/exchange": ArticleContent(
                full_text="Microsoft released Exchange Server security updates for an exploited zero-day vulnerability.",
                abstract="Microsoft released Exchange Server security updates for an exploited zero-day vulnerability.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        near_duplicate_enabled=False,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "first",
                "rss",
                "Microsoft Teams to add brand impersonation warnings to calls",
                "https://example.com/teams",
                now,
            ),
            SourceArticle(
                "second",
                "rss",
                "Microsoft patches Exchange Server zero-day exploited in attacks",
                "https://example.com/exchange",
                now + timedelta(minutes=10),
            ),
        ]
    )

    assert metrics.processed == 2
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 2
    assert metrics.digest_sent == 1
    assert metrics.skipped == 0

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2
        assert len(session.scalars(select(Alert)).all()) == 2


def test_pipeline_routes_out_of_taxonomy_to_digest() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = FakeFetcher(ArticleContent(full_text="attack text", abstract="first sentence. second sentence."))
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=OutOfTaxonomyClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
    )

    article = SourceArticle(
        source_name="s1",
        source_type="rss",
        title="Stryker hit by wiper attack",
        url="https://example.com/wiper",
        published_at=datetime.now(timezone.utc),
    )

    metrics = pipeline.run([article])
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 1
    assert metrics.digest_sent == 1

    with database.session() as session:
        alert = session.scalar(select(Alert))
        assert alert is not None
        assert alert.channel == "digest"
        assert alert.routing_reason == "out_of_taxonomy"


def test_pipeline_marks_alert_failed_when_email_send_fails() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = FakeFetcher(ArticleContent(full_text="attack text", abstract="first sentence. second sentence."))
    emailer = FailingEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    article = SourceArticle(
        source_name="s1",
        source_type="rss",
        title="Acme Corp attacked in phishing",
        url="https://example.com/article",
        published_at=datetime.now(timezone.utc),
    )

    metrics = pipeline.run([article])
    assert metrics.alerts_sent == 0
    assert metrics.errors == 0

    with database.session() as session:
        alert = session.scalar(select(Alert))
        assert alert is not None
        assert alert.channel == "immediate"
        assert alert.status == "failed"
        assert "smtp down" in (alert.error_message or "")


def test_pipeline_skips_exact_content_hash_duplicate() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    content = ArticleContent(
        full_text="Acme Corp phishing incident with identical article body.",
        abstract="Acme Corp phishing incident.",
    )
    fetcher = UrlMapFetcher(
        {
            "https://example.com/first": content,
            "https://example.com/second": content,
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle("s1", "rss", "Acme Corp attacked in phishing", "https://example.com/first", now),
            SourceArticle("s2", "rss", "Different title for same body", "https://example.com/second", now),
        ]
    )

    assert metrics.alerts_sent == 1
    assert metrics.skipped == 1
    assert len(emailer.sent) == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 1


def test_pipeline_skips_near_duplicate_before_digest_or_alert() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/one": ArticleContent(
                full_text="WhatsApp disrupted NSO spyware phishing attacks against users.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing attacks.",
            ),
            "https://example.com/two": ArticleContent(
                full_text="Meta said WhatsApp disrupted new spyware phishing attacks linked to NSO Group.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    now = datetime.now(timezone.utc)
    metrics = pipeline.run(
        [
            SourceArticle(
                "s1",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks - BleepingComputer",
                "https://example.com/one",
                now,
            ),
            SourceArticle(
                "s2",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks",
                "https://example.com/two",
                now + timedelta(minutes=5),
            ),
        ]
    )

    assert metrics.alerts_sent == 1
    assert metrics.skipped == 1
    assert metrics.digest_queued == 0
    assert len(emailer.sent) == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 1


def test_pipeline_skips_stored_near_duplicate_from_cached_recent_articles() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/stored-near": ArticleContent(
                full_text="WhatsApp disrupted NSO spyware phishing attacks against users.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing attacks.",
            ),
            "https://example.com/new-near": ArticleContent(
                full_text="Meta said WhatsApp disrupted new spyware phishing attacks linked to NSO Group.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    now = datetime.now(timezone.utc)
    first_metrics = pipeline.run(
        [
            SourceArticle(
                "s1",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks",
                "https://example.com/stored-near",
                now,
            )
        ]
    )
    second_metrics = pipeline.run(
        [
            SourceArticle(
                "s2",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks - BleepingComputer",
                "https://example.com/new-near",
                now + timedelta(minutes=5),
            )
        ]
    )

    assert first_metrics.alerts_sent == 1
    assert second_metrics.processed == 1
    assert second_metrics.skipped == 1
    assert second_metrics.alerts_sent == 0
    assert len(emailer.sent) == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 1


def test_pipeline_stored_near_threshold_controls_stored_matches() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/stored-near": ArticleContent(
                full_text="WhatsApp disrupted NSO spyware phishing attacks against users.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing attacks.",
            ),
            "https://example.com/new-near": ArticleContent(
                full_text="Meta said WhatsApp disrupted new spyware phishing attacks linked to NSO Group.",
                abstract="WhatsApp disrupted NSO-linked spyware phishing activity.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        stored_near_duplicate_threshold=0.90,
        digest_recipient_email="digest@example.com",
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    first_metrics = pipeline.run(
        [
            SourceArticle(
                "s1",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks",
                "https://example.com/stored-near",
                now,
            )
        ]
    )
    second_metrics = pipeline.run(
        [
            SourceArticle(
                "s2",
                "rss",
                "WhatsApp says it disrupted new NSO spyware phishing attacks - BleepingComputer",
                "https://example.com/new-near",
                now + timedelta(minutes=5),
            )
        ]
    )

    assert first_metrics.digest_queued == 1
    assert second_metrics.skipped == 0
    assert second_metrics.digest_queued == 1

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2


def test_pipeline_stored_near_duplicate_replaces_lower_priority_source_and_reprocesses() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://www.mexc.com/news/meta-nso": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The attacks targeted WhatsApp users with one-click "
                    "spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
            "https://thehackernews.com/2026/06/meta-nso-whatsapp.html": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The phishing attacks targeted WhatsApp users with "
                    "one-click spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    now = datetime.now(timezone.utc)
    first_metrics = pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Stock: WhatsApp Takes Action Against NSO Group Spyware - MEXC",
                "https://www.mexc.com/news/meta-nso",
                now,
            )
        ]
    )
    second_metrics = pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Blocks NSO Group's New WhatsApp Phishing Attack, Files Contempt Order - The Hacker News",
                "https://thehackernews.com/2026/06/meta-nso-whatsapp.html",
                now + timedelta(minutes=5),
            )
        ]
    )

    assert first_metrics.alerts_sent == 1
    assert second_metrics.skipped == 0
    assert second_metrics.alerts_sent == 1
    assert len(emailer.sent) == 2

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        alerts = session.scalars(select(Alert).order_by(Alert.id)).all()
        fingerprints = session.scalars(select(ArticleFingerprint)).all()

        assert len(articles) == 1
        assert articles[0].url == "https://thehackernews.com/2026/06/meta-nso-whatsapp.html"
        assert articles[0].source_name == "Google News"
        assert len(alerts) == 2
        assert all(alert.article_id == articles[0].id for alert in alerts)
        assert len(fingerprints) == 1
        assert fingerprints[0].article_id == articles[0].id


def test_pipeline_stored_near_duplicate_keeps_higher_priority_stored_source() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://thehackernews.com/2026/06/meta-nso-whatsapp.html": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The phishing attacks targeted WhatsApp users with "
                    "one-click spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
            "https://www.mexc.com/news/meta-nso": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The attacks targeted WhatsApp users with one-click "
                    "spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    now = datetime.now(timezone.utc)
    pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Blocks NSO Group's New WhatsApp Phishing Attack, Files Contempt Order - The Hacker News",
                "https://thehackernews.com/2026/06/meta-nso-whatsapp.html",
                now,
            )
        ]
    )
    second_metrics = pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Stock: WhatsApp Takes Action Against NSO Group Spyware - MEXC",
                "https://www.mexc.com/news/meta-nso",
                now + timedelta(minutes=5),
            )
        ]
    )

    assert second_metrics.skipped == 1
    assert second_metrics.alerts_sent == 0
    assert len(emailer.sent) == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://thehackernews.com/2026/06/meta-nso-whatsapp.html"


def test_pipeline_stored_near_duplicate_keeps_equal_priority_stored_source() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://example.com/meta-nso-one": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The phishing attacks targeted WhatsApp users with "
                    "one-click spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
            "https://example.net/meta-nso-two": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The attacks targeted WhatsApp users with one-click "
                    "spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    now = datetime.now(timezone.utc)
    pipeline.run(
        [
            SourceArticle(
                "Neutral Source",
                "rss",
                "Meta Blocks NSO Group WhatsApp Phishing Attack",
                "https://example.com/meta-nso-one",
                now,
            )
        ]
    )
    second_metrics = pipeline.run(
        [
            SourceArticle(
                "Another Neutral Source",
                "rss",
                "Meta Blocks NSO Group WhatsApp Spyware Attack",
                "https://example.net/meta-nso-two",
                now + timedelta(minutes=5),
            )
        ]
    )

    assert second_metrics.skipped == 1
    assert second_metrics.alerts_sent == 0
    assert len(emailer.sent) == 1

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://example.com/meta-nso-one"


def test_pipeline_stored_replacement_excludes_target_from_digest_topic_dedupe() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://www.mexc.com/news/meta-nso": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The attacks targeted WhatsApp users with one-click "
                    "spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
            "https://thehackernews.com/2026/06/meta-nso-whatsapp.html": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The phishing attacks targeted WhatsApp users with "
                    "one-click spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_recipient_email="digest@example.com",
    )

    now = datetime.now(timezone.utc)
    first_metrics = pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Stock: WhatsApp Takes Action Against NSO Group Spyware - MEXC",
                "https://www.mexc.com/news/meta-nso",
                now,
            )
        ]
    )
    second_metrics = pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Blocks NSO Group's New WhatsApp Phishing Attack, Files Contempt Order - The Hacker News",
                "https://thehackernews.com/2026/06/meta-nso-whatsapp.html",
                now + timedelta(minutes=5),
            )
        ]
    )

    assert first_metrics.digest_queued == 1
    assert first_metrics.digest_sent == 1
    assert second_metrics.skipped == 0
    assert second_metrics.digest_queued == 1
    assert second_metrics.digest_sent == 1
    assert len(emailer.sent) == 2

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        alerts = session.scalars(select(Alert).order_by(Alert.id)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://thehackernews.com/2026/06/meta-nso-whatsapp.html"
        assert len(alerts) == 2


def test_pipeline_current_run_survivor_is_selected_before_stored_near_replacement(caplog) -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = UrlMapFetcher(
        {
            "https://www.mexc.com/news/meta-nso": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The attacks targeted WhatsApp users with one-click "
                    "spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
            "https://example.org/meta-nso-analysis": ArticleContent(
                full_text=(
                    "Meta reported that WhatsApp stopped a new NSO Group spyware phishing attack. "
                    "The company filed a contempt order after operators allegedly violated a court "
                    "order. The operation targeted WhatsApp users with one-click spyware links and "
                    "malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
            "https://thehackernews.com/2026/06/meta-nso-whatsapp.html": ArticleContent(
                full_text=(
                    "Meta said WhatsApp blocked a new NSO Group spyware phishing attack. "
                    "Meta filed a contempt order against NSO Group after operators allegedly "
                    "violated a court order. The phishing attacks targeted WhatsApp users with "
                    "one-click spyware links and malicious infrastructure."
                ),
                abstract="Meta said WhatsApp blocked a new NSO Group spyware phishing attack.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=FakeVictimExtractor(),
        emailer=emailer,
    )

    caplog.set_level(logging.INFO, logger="app.pipeline")
    now = datetime.now(timezone.utc)
    pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Stock: WhatsApp Takes Action Against NSO Group Spyware - MEXC",
                "https://www.mexc.com/news/meta-nso",
                now,
            )
        ]
    )
    second_metrics = pipeline.run(
        [
            SourceArticle(
                "Neutral Source",
                "rss",
                "Meta Blocks NSO Group WhatsApp Spyware Attack",
                "https://example.org/meta-nso-analysis",
                now + timedelta(minutes=10),
            ),
            SourceArticle(
                "Google News",
                "rss",
                "Meta Blocks NSO Group's New WhatsApp Phishing Attack, Files Contempt Order - The Hacker News",
                "https://thehackernews.com/2026/06/meta-nso-whatsapp.html",
                now + timedelta(minutes=5),
            ),
        ]
    )

    assert second_metrics.skipped == 1
    assert second_metrics.alerts_sent == 1
    replacement_logs = [
        record.message
        for record in caplog.records
        if "Stored duplicate replacement selected" in record.message
    ]
    assert len(replacement_logs) == 1
    assert "url=https://thehackernews.com/2026/06/meta-nso-whatsapp.html" in replacement_logs[0]
    assert "url=https://example.org/meta-nso-analysis" not in replacement_logs[0]

    with database.session() as session:
        articles = session.scalars(select(Article)).all()
        assert len(articles) == 1
        assert articles[0].url == "https://thehackernews.com/2026/06/meta-nso-whatsapp.html"


def test_pipeline_stored_replacement_conflict_skips_safely() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    target_content = ArticleContent(
        full_text="Stored rewrite article about a Meta WhatsApp NSO phishing campaign.",
        abstract="Stored rewrite article.",
    )
    conflicting_content = ArticleContent(
        full_text="Separate existing article body that the replacement would duplicate exactly.",
        abstract="Separate existing article.",
    )
    fetcher = UrlMapFetcher(
        {
            "https://www.mexc.com/news/meta-nso": target_content,
            "https://example.com/conflict": conflicting_content,
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        near_duplicate_enabled=False,
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    pipeline.run(
        [
            SourceArticle(
                "Google News",
                "rss",
                "Meta Stock: WhatsApp Takes Action Against NSO Group Spyware - MEXC",
                "https://www.mexc.com/news/meta-nso",
                now,
            ),
            SourceArticle(
                "Neutral Source",
                "rss",
                "Unrelated stored article",
                "https://example.com/conflict",
                now + timedelta(minutes=1),
            ),
        ]
    )

    with database.session() as session:
        target_id = session.scalar(
            select(Article.id).where(Article.url == "https://www.mexc.com/news/meta-nso")
        )
        assert target_id is not None

    replacement_item = SourceArticle(
        "Google News",
        "rss",
        "Meta Blocks NSO Group's New WhatsApp Phishing Attack, Files Contempt Order - The Hacker News",
        "https://thehackernews.com/2026/06/meta-nso-whatsapp.html",
        now + timedelta(minutes=5),
    )
    replacement_candidate = _FetchedCandidate(
        item=replacement_item,
        content=conflicting_content,
        canonical_url=canonicalize_url(replacement_item.url),
        fingerprint=build_fingerprint(replacement_item.title, conflicting_content.full_text),
        content_hash=build_content_hash(conflicting_content.full_text),
        similarity_document=build_similarity_document(
            replacement_item.title,
            conflicting_content.abstract,
            conflicting_content.full_text,
        ),
        topic_document=build_topic_document(
            replacement_item.title,
            conflicting_content.abstract,
            conflicting_content.full_text,
        ),
        original_index=0,
        replacement_article_id=target_id,
    )
    context = _RunDedupeContext(
        existing_canonical_urls=set(),
        content_hash_article_ids={},
        fingerprint_article_ids={},
        recent_articles=[],
        near_duplicate_max_comparisons=500,
    )

    metrics = pipeline._process_prepared(
        replacement_candidate,
        digest_queue=[],
        metrics=PipelineMetrics(processed=1),
        context=context,
    )

    assert metrics.skipped == 1

    with database.session() as session:
        articles = session.scalars(select(Article).order_by(Article.id)).all()
        assert len(articles) == 2
        assert articles[0].url == "https://www.mexc.com/news/meta-nso"


def test_pipeline_batches_stored_exact_key_skips() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    content_seed = ArticleContent(
        full_text="Stored article body about Acme Corp phishing.",
        abstract="Stored article abstract.",
    )
    fingerprint_prefix = "Acme Corp phishing incident shared fingerprint prefix " * 120
    fetcher = CountingUrlMapFetcher(
        {
            "https://example.com/stored?utm_source=seed": content_seed,
            "https://example.com/fingerprint-seed": ArticleContent(
                full_text=f"{fingerprint_prefix}original trailing details",
                abstract="Fingerprint seed abstract.",
            ),
            "https://example.com/content-duplicate": content_seed,
            "https://example.com/fingerprint-duplicate": ArticleContent(
                full_text=f"{fingerprint_prefix}changed trailing details",
                abstract="Fingerprint duplicate abstract.",
            ),
        }
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=FakeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        near_duplicate_enabled=False,
        digest_topic_dedupe_enabled=False,
    )

    now = datetime.now(timezone.utc)
    pipeline.run(
        [
            SourceArticle("seed", "rss", "Stored content seed", "https://example.com/stored?utm_source=seed", now),
            SourceArticle(
                "seed",
                "rss",
                "Stored fingerprint seed",
                "https://example.com/fingerprint-seed",
                now + timedelta(minutes=1),
            ),
        ]
    )

    metrics = pipeline.run(
        [
            SourceArticle("dup", "rss", "Stored canonical duplicate", "https://example.com/stored", now),
            SourceArticle("dup", "rss", "Different title for stored content", "https://example.com/content-duplicate", now),
            SourceArticle(
                "dup",
                "rss",
                "Stored fingerprint seed",
                "https://example.com/fingerprint-duplicate",
                now,
            ),
        ]
    )

    assert metrics.processed == 3
    assert metrics.skipped == 3
    assert metrics.errors == 0
    assert "https://example.com/stored" not in fetcher.calls

    with database.session() as session:
        assert len(session.scalars(select(Article)).all()) == 2


def test_pipeline_suppresses_out_of_scope_digest_item() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    fetcher = FakeFetcher(
        ArticleContent(
            full_text="The article discussed physical attacks and refugee policy.",
            abstract="The article discussed physical attacks and refugee policy.",
        )
    )
    emailer = FakeEmailer()
    pipeline = MonitorPipeline(
        database=database,
        fetcher=fetcher,
        classifier=OutOfScopeClassifier(),
        victim_extractor=LowConfidenceVictimExtractor(),
        emailer=emailer,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
    )

    article = SourceArticle(
        source_name="s1",
        source_type="rss",
        title="Defiant Merkel defends refugee stance after attacks - Digital Journal",
        url="https://example.com/merkel",
        published_at=datetime.now(timezone.utc),
    )

    metrics = pipeline.run([article])
    assert metrics.alerts_sent == 0
    assert metrics.digest_queued == 0
    assert metrics.digest_sent == 0
    assert metrics.skipped == 1
    assert len(emailer.sent) == 0

    with database.session() as session:
        alert = session.scalar(select(Alert))
        assert alert is not None
        assert alert.channel == "digest"
        assert alert.routing_reason == "out_of_scope"
        assert alert.status == "skipped"


def test_initialize_schema_creates_hot_path_indexes() -> None:
    database = Database(_settings("sqlite+pysqlite:///:memory:"))
    initialize_schema(database)

    inspector = inspect(database.engine)
    article_indexes = {index["name"] for index in inspector.get_indexes("articles")}
    alert_indexes = {index["name"] for index in inspector.get_indexes("alerts")}
    fingerprint_indexes = {index["name"] for index in inspector.get_indexes("article_fingerprints")}

    assert "ix_articles_content_hash" in article_indexes
    assert "ix_articles_created_at" in article_indexes
    assert "ix_articles_published_at" in article_indexes
    assert "ix_alerts_article_id" in alert_indexes
    assert "ix_article_fingerprints_article_id" in fingerprint_indexes
