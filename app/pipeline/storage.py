from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select

from app.dedup.deduplicator import (
    build_similarity_document,
    build_topic_document,
    find_topic_duplicate_from_documents,
)
from app.models import Article, ArticleFingerprint
from app.pipeline.state import (
    _FetchedCandidate,
    _RecentArticle,
    _RunDedupeContext,
    _TopicDuplicateResult,
)
from app.time_utils import ensure_utc


class StorageMixin:
    def _load_existing_canonical_urls(self, canonical_urls: set[str]) -> set[str]:
        if not canonical_urls:
            return set()
        with self.database.session() as session:
            return set(
                session.scalars(
                    select(Article.canonical_url).where(Article.canonical_url.in_(canonical_urls))
                ).all()
            )

    def _load_existing_exact_keys(
        self,
        candidates: list[_FetchedCandidate],
        context: _RunDedupeContext,
    ) -> None:
        content_hashes = {candidate.content_hash for candidate in candidates}
        fingerprints = {candidate.fingerprint for candidate in candidates}
        if not content_hashes and not fingerprints:
            return

        with self.database.session() as session:
            if content_hashes:
                for content_hash, article_id in session.execute(
                    select(Article.content_hash, Article.id).where(Article.content_hash.in_(content_hashes))
                ):
                    context.content_hash_article_ids.setdefault(content_hash, article_id)

            if fingerprints:
                for fingerprint, article_id in session.execute(
                    select(ArticleFingerprint.fingerprint, ArticleFingerprint.article_id).where(
                        ArticleFingerprint.fingerprint.in_(fingerprints)
                    )
                ):
                    context.fingerprint_article_ids.setdefault(fingerprint, article_id)

    def _has_recent_incident_duplicate(
        self,
        incident_key: str,
        candidate_time: datetime | None,
        exclude_article_id: int | None = None,
    ) -> bool:
        with self.database.session() as session:
            matches = session.execute(
                select(Article.id, Article.published_at, Article.created_at).where(Article.incident_key == incident_key)
            ).all()

        if not matches:
            return False
        candidate_reference = ensure_utc(candidate_time)
        if candidate_reference is None:
            return any(article_id != exclude_article_id for article_id, _, _ in matches)

        window = timedelta(hours=self.incident_dedupe_window_hours)
        for article_id, published_at, created_at in matches:
            if article_id == exclude_article_id:
                continue
            reference = ensure_utc(published_at or created_at)
            if reference is None:
                return True
            if abs(candidate_reference - reference) <= window:
                return True
        return False

    def _load_recent_articles(self) -> list[_RecentArticle]:
        if self.near_duplicate_max_comparisons <= 0:
            return []

        with self.database.session() as session:
            rows = session.execute(
                select(
                    Article.id,
                    Article.source_name,
                    Article.source_type,
                    Article.title,
                    Article.url,
                    Article.abstract,
                    Article.article_text,
                    Article.published_at,
                    Article.created_at,
                )
                .order_by(Article.created_at.desc())
                .limit(self.near_duplicate_max_comparisons)
            ).all()

        if not rows:
            return []

        articles: list[_RecentArticle] = []
        for article_id, source_name, source_type, title, url, abstract, text, published_at, created_at in rows:
            articles.append(
                _RecentArticle(
                    article_id=article_id,
                    source_name=source_name,
                    source_type=source_type,
                    title=title,
                    url=url,
                    published_at=published_at,
                    created_at=created_at,
                    similarity_document=build_similarity_document(title, abstract, text),
                    topic_document=build_topic_document(title, abstract, text),
                )
            )
        return articles

    def _recent_articles_for_window(
        self,
        recent_articles: list[_RecentArticle],
        candidate_time: datetime | None,
        lookback_hours: int | None,
    ) -> list[_RecentArticle]:
        return [
            article
            for article in recent_articles
            if self._recent_article_within_window(article, candidate_time, lookback_hours)
        ]

    def _recent_article_within_window(
        self,
        article: _RecentArticle,
        candidate_time: datetime | None,
        lookback_hours: int | None,
    ) -> bool:
        candidate_reference = ensure_utc(candidate_time)
        if candidate_reference is None or lookback_hours is None or lookback_hours <= 0:
            return True

        reference = ensure_utc(article.published_at or article.created_at)
        if reference is None:
            return True
        return abs(candidate_reference - reference) <= timedelta(hours=lookback_hours)

    def _find_digest_topic_duplicate(
        self,
        candidate: _FetchedCandidate,
        candidate_time: datetime | None,
        context: _RunDedupeContext,
        exclude_article_id: int | None = None,
    ) -> _TopicDuplicateResult | None:
        recent_articles = self._recent_articles_for_window(
            context.recent_articles,
            candidate_time,
            self.digest_topic_dedupe_lookback_hours,
        )
        if exclude_article_id is not None:
            recent_articles = [
                article
                for article in recent_articles
                if article.article_id != exclude_article_id
            ]
        if not recent_articles:
            return None

        match = find_topic_duplicate_from_documents(
            candidate.item.title,
            candidate.topic_document,
            [article.title for article in recent_articles],
            [article.topic_document for article in recent_articles],
            threshold=self.digest_topic_dedupe_threshold,
        )
        if match is None:
            return None

        matched_article = recent_articles[match.index]
        return _TopicDuplicateResult(
            article_id=matched_article.article_id,
            score=match.score,
            title=matched_article.title,
            url=matched_article.url,
            shared_title_terms=match.shared_title_terms,
        )
