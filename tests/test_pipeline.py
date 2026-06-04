from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.alerts.emailer import AlertEmail, DigestEmailItem
from app.config import Settings
from app.db import Database
from app.fetch.article_fetcher import ArticleContent
from app.models import Alert
from app.pipeline import MonitorPipeline
from app.schema_init import initialize_schema
from app.sources.base import SourceArticle


class FakeFetcher:
    def __init__(self, content: ArticleContent) -> None:
        self.content = content

    def fetch(self, url: str) -> ArticleContent | None:
        return self.content


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
        enable_gdelt=False,
        gdelt_query_window_minutes=180,
        rss_feeds=[],
        google_news_queries=[],
        min_victim_confidence=0.65,
        incident_dedupe_window_hours=48,
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
        digest_max_items_per_run=100,
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


def test_pipeline_suppresses_duplicate_incident_into_digest() -> None:
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
        digest_enabled=True,
        digest_recipient_email="digest@example.com",
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
    assert metrics.digest_queued == 1
    assert metrics.digest_sent == 1
    assert len(emailer.sent) == 2

    with database.session() as session:
        alerts = session.scalars(select(Alert).order_by(Alert.id)).all()
        assert len(alerts) == 2
        assert alerts[0].channel == "immediate"
        assert alerts[1].channel == "digest"
        assert alerts[1].routing_reason == "duplicate_incident"


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
