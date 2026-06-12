from __future__ import annotations

from app.config import load_settings


def _set_required_env(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp")
    monkeypatch.setenv("SMTP_USERNAME", "user")
    monkeypatch.setenv("SMTP_PASSWORD", "pass")
    monkeypatch.setenv("SENDER_EMAIL", "from@example.com")
    monkeypatch.setenv("RECIPIENT_EMAIL", "to@example.com")
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")


def test_similarity_dedupe_threshold_uses_new_env_var(monkeypatch) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("SIMILARITY_DEDUPE_THRESHOLD", "0.42")
    monkeypatch.setenv("NEAR_DUPLICATE_THRESHOLD", "0.99")
    monkeypatch.setenv("DIGEST_TOPIC_DEDUPE_THRESHOLD", "0.99")

    settings = load_settings()

    assert settings.similarity_dedupe_threshold == 0.42
    assert not hasattr(settings, "near_duplicate_threshold")
    assert not hasattr(settings, "digest_topic_dedupe_threshold")


def test_removed_threshold_env_vars_are_ignored(monkeypatch) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.delenv("SIMILARITY_DEDUPE_THRESHOLD", raising=False)
    monkeypatch.setenv("NEAR_DUPLICATE_THRESHOLD", "0.99")
    monkeypatch.setenv("DIGEST_TOPIC_DEDUPE_THRESHOLD", "0.99")

    settings = load_settings()

    assert settings.similarity_dedupe_threshold == 0.30
