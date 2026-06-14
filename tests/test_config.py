from __future__ import annotations

from app.config import load_settings


def _set_required_env(monkeypatch) -> None:
    monkeypatch.setenv("SMTP_HOST", "smtp")
    monkeypatch.setenv("SMTP_USERNAME", "user")
    monkeypatch.setenv("SMTP_PASSWORD", "pass")
    monkeypatch.setenv("SENDER_EMAIL", "from@example.com")
    monkeypatch.setenv("RECIPIENT_EMAIL", "to@example.com")
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")


def test_dedupe_thresholds_use_dedicated_env_vars(monkeypatch) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("STORED_NEAR_DUPLICATE_THRESHOLD", "0.41")
    monkeypatch.setenv("CURRENT_RUN_NEAR_DUPLICATE_THRESHOLD", "0.36")
    monkeypatch.setenv("DIGEST_TOPIC_DEDUPE_THRESHOLD", "0.47")

    settings = load_settings()

    assert settings.stored_near_duplicate_threshold == 0.41
    assert settings.current_run_near_duplicate_threshold == 0.36
    assert settings.digest_topic_dedupe_threshold == 0.47
    assert not hasattr(settings, "similarity_dedupe_threshold")


def test_dedupe_threshold_defaults_ignore_removed_shared_env_var(monkeypatch) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("SIMILARITY_DEDUPE_THRESHOLD", "0.99")

    settings = load_settings()

    assert settings.stored_near_duplicate_threshold == 0.38
    assert settings.current_run_near_duplicate_threshold == 0.34
    assert settings.digest_topic_dedupe_threshold == 0.40
    assert not hasattr(settings, "similarity_dedupe_threshold")
