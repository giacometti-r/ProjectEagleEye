from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy import text

from app.db import Database
from app.models import Base


def _add_column_if_missing(conn: object, table_name: str, column_name: str, ddl: str) -> None:
    inspector = inspect(conn)
    existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name in existing_columns:
        return
    conn.execute(text(ddl))


def _add_index_if_missing(conn: object, table_name: str, index_name: str, ddl: str) -> None:
    inspector = inspect(conn)
    existing_indexes = {index["name"] for index in inspector.get_indexes(table_name)}
    if index_name in existing_indexes:
        return
    conn.execute(text(ddl))


def initialize_schema(database: Database) -> None:
    Base.metadata.create_all(bind=database.engine, checkfirst=True)
    with database.engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("ALTER TABLE articles ALTER COLUMN source_name TYPE VARCHAR(1024)"))

        _add_column_if_missing(
            conn,
            "articles",
            "article_type",
            "ALTER TABLE articles ADD COLUMN article_type VARCHAR(40) DEFAULT 'opinion'",
        )
        _add_column_if_missing(conn, "articles", "incident_key", "ALTER TABLE articles ADD COLUMN incident_key VARCHAR(64)")
        _add_column_if_missing(
            conn,
            "alerts",
            "channel",
            "ALTER TABLE alerts ADD COLUMN channel VARCHAR(20) DEFAULT 'immediate'",
        )
        _add_column_if_missing(conn, "alerts", "routing_reason", "ALTER TABLE alerts ADD COLUMN routing_reason VARCHAR(80)")
        _add_index_if_missing(conn, "articles", "ix_articles_content_hash", "CREATE INDEX ix_articles_content_hash ON articles (content_hash)")
        _add_index_if_missing(conn, "articles", "ix_articles_created_at", "CREATE INDEX ix_articles_created_at ON articles (created_at)")
        _add_index_if_missing(conn, "articles", "ix_articles_published_at", "CREATE INDEX ix_articles_published_at ON articles (published_at)")
        _add_index_if_missing(conn, "alerts", "ix_alerts_article_id", "CREATE INDEX ix_alerts_article_id ON alerts (article_id)")
        _add_index_if_missing(
            conn,
            "article_fingerprints",
            "ix_article_fingerprints_article_id",
            "CREATE INDEX ix_article_fingerprints_article_id ON article_fingerprints (article_id)",
        )
