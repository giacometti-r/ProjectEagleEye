from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.alerts.emailer import DigestEmailItem
from app.dedup.deduplicator import build_similarity_document, build_topic_document
from app.fetch.article_fetcher import ArticleContent
from app.sources.base import SourceArticle


@dataclass(frozen=True)
class _DigestQueueEntry:
    alert_id: int
    item: DigestEmailItem


@dataclass(frozen=True)
class _TopicDuplicateResult:
    article_id: int
    score: float
    title: str
    url: str
    shared_title_terms: tuple[str, ...]


@dataclass(frozen=True)
class _FetchedCandidate:
    item: SourceArticle
    content: ArticleContent
    canonical_url: str
    fingerprint: str
    content_hash: str
    similarity_document: str
    topic_document: str
    original_index: int
    replacement_article_id: int | None = None


@dataclass(frozen=True)
class _PreparedInput:
    item: SourceArticle
    canonical_url: str
    original_index: int


@dataclass(frozen=True)
class _RecentArticle:
    article_id: int
    source_name: str
    source_type: str
    title: str
    url: str
    published_at: datetime | None
    created_at: datetime | None
    similarity_document: str
    topic_document: str


@dataclass
class _RunDedupeContext:
    existing_canonical_urls: set[str]
    content_hash_article_ids: dict[str, int]
    fingerprint_article_ids: dict[str, int]
    recent_articles: list[_RecentArticle]
    near_duplicate_max_comparisons: int

    @property
    def similarity_documents(self) -> list[str]:
        return [article.similarity_document for article in self.recent_articles]

    def add_recent_article(
        self,
        article_id: int,
        source_name: str,
        source_type: str,
        title: str,
        url: str,
        abstract: str,
        text: str,
        published_at: datetime | None,
    ) -> None:
        if self.near_duplicate_max_comparisons <= 0:
            return
        self.recent_articles.insert(
            0,
            _RecentArticle(
                article_id=article_id,
                source_name=source_name,
                source_type=source_type,
                title=title,
                url=url,
                published_at=published_at,
                created_at=datetime.now(timezone.utc),
                similarity_document=build_similarity_document(title, abstract, text),
                topic_document=build_topic_document(title, abstract, text),
            ),
        )
        del self.recent_articles[self.near_duplicate_max_comparisons :]
