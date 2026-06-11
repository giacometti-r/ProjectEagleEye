# README_TECHNICAL

## 1. Purpose, Audience, and Scope

This document is the canonical technical reference for the `cyber-news-alert` codebase.

It targets engineers maintaining or extending the system and documents:

- Full runtime architecture and control flow.
- All tracked implementation modules and support files.
- Every Python function/class/method/property/dataclass/protocol/regex constant used by runtime and tests.
- Input/output contracts, side effects, failure behavior, and key consumers.
- Test-derived behavioral contracts.

Scope includes tracked project files under:

- `app/`
- `tests/`
- `Dockerfile`
- `requirements.txt`
- `.github/workflows/`
- `k8s/`
- `.sops.yaml`
- `.gitignore`
- `README.md`
- `LICENSE`

Scope excludes `.git` internals and cache artifacts (for example `__pycache__`, `.pytest_cache`).

---

## 2. Repository Surface Map

### 2.1 Top-Level Files

- `README.md`: operator-focused usage and feature overview.
- `README_TECHNICAL.md`: this deep technical reference.
- `LICENSE`: MIT license terms.
- `requirements.txt`: Python dependency lock list (pinned versions).
- `Dockerfile`: production runtime image build.
- `.github/workflows/`: pull request validation and main-branch image/GitOps pipeline.
- `k8s/`: Kubernetes base, production overlay, SOPS-ready Secret, and Argo CD Application.
- `.sops.yaml`: SOPS creation rule for the production secret manifest.
- `.gitignore`: VCS ignore policy.
- `.vscode/settings.json`: local IDE Python environment preferences.
- `.codex`: Codex-local marker file present in repository root.

### 2.2 Application Package (`app/`)

- `main.py`: program entrypoint and source aggregation.
- `pipeline.py`: orchestration of fetch/classify/extract/persist/send.
- `config.py`: env loading and typed settings model.
- `db.py`: SQLAlchemy engine/session wrapper.
- `models.py`: ORM schema.
- `schema_init.py`: idempotent schema bootstrap and targeted backfill.
- `logging_config.py`: global logging setup.
- `alerts/emailer.py`: SMTP subject/body rendering and send behavior.
- `fetch/article_fetcher.py`: HTTP download, article text extraction, abstract generation.
- `detection/attack_classifier.py`: article type + attack taxonomy classification.
- `detection/victim_extractor.py`: victim entity extraction and categorization.
- `dedup/deduplicator.py`: canonical URL + fingerprint + incident/content hash + TF-IDF similarity utilities.
- `sources/base.py`: source datamodel/protocol.
- `sources/rss.py`: RSS adapter with Google News URL decoding support.
- `sources/google_news.py`: Google News RSS specialization.
- `sources/gdelt.py`: GDELT Doc API adapter.
- `__init__.py` files: package markers only, no exports.

### 2.3 Test Package (`tests/`)

- `test_article_fetcher.py`: abstract/text extraction quality contracts.
- `test_attack_classifier.py`: attack/incident routing behavior.
- `test_victim_extractor.py`: victim extraction quality/noise rejection behavior.
- `test_deduplicator.py`: dedupe normalization/hash stability behavior.
- `test_emailer.py`: email formatting and digest grouping behavior.
- `test_pipeline.py`: integration-lite pipeline persistence/routing/send-state contracts.

### 2.4 Ops

- `k8s/base/cronjob.yaml`: hourly Kubernetes CronJob invoking `python -m app.main`.
- `k8s/base/postgres-statefulset.yaml`: namespaced PostgreSQL runtime with PVC-backed storage.
- `k8s/overlays/prod/kustomization.yaml`: production image tag and Secret resource composition.
- `k8s/argocd/application.yaml`: Argo CD Application targeting the production overlay.

---

## 3. End-to-End Runtime Architecture

### 3.1 Startup and Dependency Wiring

Execution starts at `app.main.main()`:

1. `load_settings()` reads process environment variables into immutable `Settings`.
2. `configure_logging()` applies `logging.basicConfig(...)` globally.
3. `Database(settings)` creates SQLAlchemy engine/session factory.
4. `initialize_schema(database)` creates tables and applies idempotent compatibility DDL.
5. `Emailer(...)`, `ArticleFetcher(...)`, `AttackClassifier()`, `VictimExtractor(...)` are constructed.
6. `MonitorPipeline(...)` is constructed with quality thresholds, near-duplicate controls, and channel controls.
7. `gather_articles(settings)` instantiates sources and fetches candidate `SourceArticle` items.
8. `pipeline.run(articles)` processes all candidates and returns `PipelineMetrics`.
9. Final metrics are logged and process returns exit code `0`.

### 3.2 Source Aggregation and Ordering

`gather_articles()` composes sources from config:

- `RssSource` per `rss_feeds` entry.
- `GoogleNewsRssSource` per `google_news_queries` entry.
- Optional `GdeltSource` when `enable_gdelt=true`.

Source failures are isolated (`try/except` per source, warning logged). Dated items older than `max_article_age_hours` are dropped before article fetch; missing timestamps are retained. Remaining articles are sorted newest-first using `published_at` (UTC), with Unix epoch fallback for missing timestamps.

### 3.3 Pipeline Flow

`MonitorPipeline.run()` executes the processing graph in three phases:

1. Candidate preparation for every fetched `SourceArticle`:
   - Canonical URL DB dedupe check (`canonicalize_url` + DB lookup on `Article.canonical_url`).
   - Remote article fetch and parse (`ArticleFetcher.fetch`), skip on failure.
   - Fingerprint/content hash/similarity document generation.
   - Exact content-hash, fingerprint, and optional near-duplicate DB checks.
2. Current-run batch dedupe across prepared candidates:
   - Groups exact matches by canonical URL, content hash, and fingerprint.
   - Groups near-duplicates with TF-IDF cosine similarity when enabled.
   - Keeps the newest `published_at`; ties and missing timestamps keep the earlier input order.
3. Survivor processing:
   - Classification (`AttackClassifier.classify`), including cyber-scope gating.
   - Victim extraction (`VictimExtractor.extract`) with conservative noise rejection.
   - Incident key creation (`build_incident_key`) when attack + victim available.
   - Cross-incident dedupe window check (`_has_recent_incident_duplicate`).
   - Duplicate incidents are skipped before persistence.
   - Immediate eligibility decision using article type + taxonomy + victim confidence + duplicate status.
   - Digest-bound topic duplicate check using title + abstract + article-text prefix similarity and shared salient title terms.
   - Transactional persistence of `Article`, `ArticleFingerprint`, and `Alert` row.
   - Immediate SMTP send or digest queueing, followed by one run-level digest flush.

### 3.4 Channel Semantics

- Immediate channel (`channel='immediate'`): only qualified incidents.
- Digest channel (`channel='digest'`): non-immediate, non-duplicate items.
- Out-of-scope items are persisted with digest `status='skipped'` and are not sent when `suppress_out_of_scope_digest=true`.
- Digest send occurs once at run end in `_flush_digest_queue`.
- Alert status transitions:
  - immediate pending -> sent|failed
  - digest queued -> sent|failed (on flush), or stored as skipped when disabled, overflow, or out-of-scope suppression applies.

### 3.5 Dedupe Layers

1. Source freshness filter (`max_article_age_hours`, missing timestamps retained).
2. Stored canonical URL dedupe (`articles.canonical_url` unique).
3. Stored exact content hash dedupe (`articles.content_hash` lookup).
4. Stored fingerprint dedupe (`article_fingerprints.fingerprint` unique).
5. Stored near-duplicate dedupe (`TfidfVectorizer` + cosine similarity over recent stored articles).
6. Current-run exact dedupe by canonical URL, content hash, and fingerprint.
7. Current-run near-duplicate dedupe using the same similarity threshold/window settings.
8. Incident-window dedupe (`articles.incident_key` + temporal comparison).
9. Digest-topic dedupe (`TfidfVectorizer` over title + abstract + article-text prefix plus salient title-overlap guard).

### 3.6 Scheduling and Operations

- Containerized execution uses the production `Dockerfile`.
- Kubernetes scheduling is defined by `k8s/base/cronjob.yaml`.
- Cron expression `0 * * * *` invokes `python -m app.main` hourly.
- Argo CD syncs `k8s/overlays/prod` into namespace `cyber-news-alert`.

---

## 4. Configuration Reference (`app/config.py` + Kubernetes env)

### 4.1 Symbol Reference

#### `DEFAULT_RSS_FEEDS` (`list[str]`)

- Purpose: fallback RSS feeds when `RSS_FEEDS` unset.
- Consumer: `load_settings()`.

#### `DEFAULT_GOOGLE_NEWS_QUERIES` (`list[str]`)

- Purpose: fallback Google News queries when `GOOGLE_NEWS_QUERIES` unset.
- Scope: avoids bare `impersonation`; uses specific brand/employee/executive impersonation, tech support scam, social engineering, deepfake, and voice-cloning terms paired with cyber/scam/credential context.
- Consumer: `load_settings()`.

#### `Settings` (`@dataclass(frozen=True)`)

- Purpose: immutable runtime configuration object.
- Construction: `load_settings()` only.
- Consumers: `main()`, `Database`, `gather_articles()`, `MonitorPipeline` wiring.

#### `ConfigError(ValueError)`

- Purpose: typed config validation error.
- Raised by: `_require()`, `_parse_list_env()`.

#### `_require(name: str) -> str`

- Purpose: enforce required env var presence.
- Input: `name` env variable key.
- Output: non-empty string value.
- Failure: raises `ConfigError` if unset/empty.

#### `_parse_list_env(name: str, default: list[str]) -> list[str]`

- Purpose: parse env list settings from JSON array or comma-separated string.
- Inputs:
  - `name`: env key.
  - `default`: fallback list.
- Output: trimmed non-empty string list.
- Parsing behavior:
  - If unset/empty => `default`.
  - If starts with `[` => JSON parsing with strict `list[str]` validation.
  - Else => split by comma.
- Failure: invalid JSON or non-`list[str]` => `ConfigError`.

#### `load_settings() -> Settings`

- Purpose: one-shot loader for all runtime settings.
- Side effects: reads process environment only.
- Output: fully populated `Settings` object.
- Failure:
  - `ConfigError` from missing required vars or invalid list JSON.
  - `ValueError` for invalid int/float conversions.

### 4.2 Environment Variables and Runtime Effects

| Settings field | Env var | Type | Required | Default | Parsing | Runtime effect |
|---|---|---|---|---|---|---|
| `smtp_host` | `SMTP_HOST` | `str` | yes | none | `_require` | SMTP server hostname. |
| `smtp_port` | `SMTP_PORT` | `int` | no | `587` | `int(...)` | SMTP port used by `Emailer.send`. |
| `smtp_username` | `SMTP_USERNAME` | `str` | yes | none | `_require` | SMTP auth username. |
| `smtp_password` | `SMTP_PASSWORD` | `str` | yes | none | `_require` | SMTP auth password. |
| `sender_email` | `SENDER_EMAIL` | `str` | yes | none | `_require` | Outbound message From header. |
| `recipient_email` | `RECIPIENT_EMAIL` | `str` | yes | none | `_require` | Immediate alert recipient default. |
| `database_url` | `DATABASE_URL` | `str` | yes | none | `_require` | SQLAlchemy engine DSN. |
| `log_level` | `LOG_LEVEL` | `str` | no | `INFO` | uppercased | Global logging level. |
| `request_timeout_seconds` | `REQUEST_TIMEOUT_SECONDS` | `int` | no | `15` | `int(...)` | HTTP timeout for article/GDELT fetch. |
| `max_articles_per_source` | `MAX_ARTICLES_PER_SOURCE` | `int` | no | `50` | `int(...)` | Upper bound per source adapter fetch. |
| `max_article_age_hours` | `MAX_ARTICLE_AGE_HOURS` | `int` | no | `168` | `int(...)` | Drops dated source items older than this before fetch; `0` disables. |
| `enable_gdelt` | `ENABLE_GDELT` | `bool` | no | `true` | truthy set `{1,true,yes}` | Enables/disables GDELT source. |
| `gdelt_query_window_minutes` | `GDELT_QUERY_WINDOW_MINUTES` | `int` | no | `180` | `int(...)` | GDELT time window (`timespan`). |
| `rss_feeds` | `RSS_FEEDS` | `list[str]` | no | `DEFAULT_RSS_FEEDS` | `_parse_list_env` | Instantiates `RssSource` entries. |
| `google_news_queries` | `GOOGLE_NEWS_QUERIES` | `list[str]` | no | `DEFAULT_GOOGLE_NEWS_QUERIES` | `_parse_list_env` | Instantiates `GoogleNewsRssSource` entries. |
| `min_victim_confidence` | `MIN_VICTIM_CONFIDENCE` | `float` | no | `0.65` | `float(...)` | Threshold for immediate-channel eligibility. |
| `incident_dedupe_window_hours` | `INCIDENT_DEDUPE_WINDOW_HOURS` | `int` | no | `48` | `int(...)` | Time window for incident-key suppression. |
| `near_duplicate_enabled` | `NEAR_DUPLICATE_ENABLED` | `bool` | no | `true` | truthy set | Enables TF-IDF cosine near-duplicate skips. |
| `near_duplicate_threshold` | `NEAR_DUPLICATE_THRESHOLD` | `float` | no | `0.78` | `float(...)` | Minimum cosine score for near-duplicate skip. |
| `near_duplicate_lookback_hours` | `NEAR_DUPLICATE_LOOKBACK_HOURS` | `int \| None` | no | fallback to incident window | optional `int(...)` | Time window for candidate comparison. |
| `near_duplicate_max_comparisons` | `NEAR_DUPLICATE_MAX_COMPARISONS` | `int` | no | `500` | `int(...)` | Max recent articles loaded for similarity comparison. |
| `suppress_out_of_scope_digest` | `SUPPRESS_OUT_OF_SCOPE_DIGEST` | `bool` | no | `true` | truthy set | Stores but does not send out-of-scope digest items. |
| `digest_enabled` | `DIGEST_ENABLED` | `bool` | no | `true` | truthy set | Enables final digest flush/send. |
| `digest_recipient_email` | `DIGEST_RECIPIENT_EMAIL` | `str` | conditional | fallback to `RECIPIENT_EMAIL` | strip + fallback | Recipient for digest alerts. |
| `digest_max_items_per_run` | `DIGEST_MAX_ITEMS_PER_RUN` | `int` | no | `100` | `int(...)` | Cap on queued digest items. |
| `digest_topic_dedupe_enabled` | `DIGEST_TOPIC_DEDUPE_ENABLED` | `bool` | no | `true` | truthy set | Enables topic-level duplicate skips for digest-bound items. |
| `digest_topic_dedupe_threshold` | `DIGEST_TOPIC_DEDUPE_THRESHOLD` | `float` | no | `0.30` | `float(...)` | Minimum title+abstract+text cosine score for digest-topic duplicate candidates. |
| `digest_topic_dedupe_lookback_hours` | `DIGEST_TOPIC_DEDUPE_LOOKBACK_HOURS` | `int` | no | fallback to `MAX_ARTICLE_AGE_HOURS` | `int(...)` | Time window for stored digest-topic comparisons. |
| `abstract_max_chars` | `ABSTRACT_MAX_CHARS` | `int` | no | `420` | `int(...)` | Max abstract length for article summaries. |
| `max_victim_words` | `MAX_VICTIM_WORDS` | `int` | no | `8` | `int(...)` | Victim extractor candidate/finalization word limit. |

---

## 5. Data Model, Schema, and Persistence

### 5.1 `app/db.py`

#### `Database`

- Purpose: centralized DB engine + session lifecycle manager.
- Constructor: `__init__(settings: Settings) -> None`
  - Creates SQLAlchemy engine with `pool_pre_ping=True`.
  - Builds `sessionmaker(autoflush=False, autocommit=False)`.
- Method: `session() -> Iterator[Session]` (context manager)
  - Yields a transactional `Session`.
  - Commits on normal exit.
  - Rolls back and re-raises on exception.
  - Always closes session in `finally`.

### 5.2 `app/models.py`

#### `Base(DeclarativeBase)`

- Purpose: SQLAlchemy declarative base for all ORM tables.

#### `Article`

- Purpose: normalized article record with analysis outputs and dedupe keys.
- Table: `articles`.
- Key columns:
  - `id` PK autoincrement.
  - `source_name`, `source_type`, `title`, `url`.
  - `canonical_url` unique.
  - `published_at` nullable timezone-aware datetime.
  - `article_text`, `abstract`.
  - `article_type`, `attack_type`, `victim_name`, `victim_category`.
  - `incident_key` nullable indexed string.
  - `content_hash`.
  - `created_at` server default `now()`.
- Relationships:
  - `fingerprints` one-to-many `ArticleFingerprint` (cascade delete-orphan).
  - `alerts` one-to-many `Alert` (cascade delete-orphan).

#### `ArticleFingerprint`

- Purpose: dedupe ledger for title/text fingerprints.
- Table: `article_fingerprints`.
- Constraints:
  - `UniqueConstraint("fingerprint", name="uq_article_fingerprint")`.
- Columns:
  - `id`, `article_id` FK(`articles.id`, cascade delete), `fingerprint`, `created_at`.
- Relationship:
  - `article` many-to-one back-populated.

#### `Alert`

- Purpose: notification history for immediate and digest channels.
- Table: `alerts`.
- Columns:
  - `id`, `article_id` FK(`articles.id`, cascade delete).
  - `recipient_email`.
  - `channel` (`immediate` or `digest`).
  - `routing_reason` nullable.
  - `subject`, `body`.
  - `status` (`pending|queued|skipped|sent|failed` by usage).
  - `error_message` nullable.
  - `sent_at` server default `now()`.
- Relationship:
  - `article` many-to-one back-populated.

### 5.3 `app/schema_init.py`

#### `_add_column_if_missing(conn, table_name, column_name, ddl) -> None`

- Purpose: idempotent backward-compatible column add helper.
- Behavior:
  - Uses `inspect(conn).get_columns(table_name)`.
  - Executes provided DDL only when `column_name` absent.

#### `initialize_schema(database: Database) -> None`

- Purpose: initialize/create schema and apply targeted compatibility changes.
- Flow:
  - `Base.metadata.create_all(checkfirst=True)`.
  - In transaction (`engine.begin()`):
    - PostgreSQL-only widen `articles.source_name` to `VARCHAR(1024)`.
    - Ensure `articles.article_type` exists.
    - Ensure `articles.incident_key` exists.
    - Ensure `alerts.channel` exists.
    - Ensure `alerts.routing_reason` exists.
- Side effects: DDL execution on target DB.

---

## 6. Runtime Module Reference (Exhaustive)

## 6.1 `app/main.py`

#### `logger`

- Object: module logger via `logging.getLogger(__name__)`.
- Used for source fetch warnings and run completion metrics.

#### `_ensure_utc(value: datetime | None) -> datetime | None`

- Purpose: normalize source timestamps for freshness filtering and sorting.
- Output: UTC-aware datetime or `None`.

#### `_filter_fresh_articles(articles, max_age_hours) -> list[SourceArticle]`

- Purpose: drop dated source items older than the configured freshness window before body fetch/classification.
- Behavior: `max_age_hours <= 0` disables filtering; missing timestamps are retained.

#### `gather_articles(settings: object) -> list[SourceArticle]`

- Purpose: construct sources from settings and aggregate articles.
- Inputs:
  - `settings`: either concrete `Settings` or any object; non-`Settings` triggers `load_settings()`.
- Output: list of `SourceArticle` sorted newest-first.
- Side effects:
  - Network calls through source adapters.
  - Optional GDELT query mirrors the scoped social-engineering terms used by Google News defaults and avoids bare `impersonation`.
  - Logs dropped stale item count when source freshness filtering removes items.
  - Warning logs on per-source failure.
- Failure behavior:
  - Individual source exceptions are swallowed with warning.
  - Settings load/type conversion errors propagate.
- Consumers: `main()`.

#### `main() -> int`

- Purpose: application entrypoint and dependency composition root.
- Output: always `0` on successful control path.
- Side effects:
  - Logging setup.
  - DB schema initialization.
  - Network IO (sources/article fetch/SMTP).
  - DB writes.
- Consumers: `if __name__ == "__main__": raise SystemExit(main())` and cron command.

## 6.2 `app/logging_config.py`

#### `configure_logging(level: str) -> None`

- Purpose: configure global Python logging format and threshold.
- Side effects: mutates root logging configuration via `logging.basicConfig`.
- Consumer: `main()`.

## 6.3 `app/pipeline.py`

#### `logger`

- Module logger for exception/error diagnostics.

#### `_clip(value: str, max_len: int) -> str`

- Purpose: hard truncate string to DB-safe length.
- Input: raw `value`, `max_len`.
- Output: original if short else prefix slice.
- Consumers: field preparation before ORM insert.

#### `PipelineMetrics` (`@dataclass(frozen=True)`)

- Fields: `processed`, `alerts_sent`, `digest_sent`, `digest_queued`, `skipped`, `errors`.
- Purpose: immutable run counters returned by `run()`.

#### `_DigestQueueEntry` (`@dataclass(frozen=True)`)

- Fields: `alert_id`, `item: DigestEmailItem`.
- Purpose: binds persisted digest alert row to later digest email payload.

#### `_NearDuplicateResult` (`@dataclass(frozen=True)`)

- Fields: `article_id`, `score`, `title`.
- Purpose: carries the best TF-IDF cosine match for logging and skip decisions.

#### `_TopicDuplicateResult` (`@dataclass(frozen=True)`)

- Fields: `article_id`, `score`, `title`, `shared_title_terms`.
- Purpose: carries the best digest-topic duplicate match for logging and skip decisions.

#### `_FetchedCandidate` (`@dataclass(frozen=True)`)

- Fields: `item`, `content`, `canonical_url`, `fingerprint`, `content_hash`, `similarity_document`, `original_index`.
- Purpose: carries fetched article content and dedupe keys between preparation, current-run dedupe, and survivor processing.

#### `MonitorPipeline`

Constructor:

`__init__(database, fetcher, classifier, victim_extractor, emailer, min_victim_confidence=0.65, incident_dedupe_window_hours=48, near_duplicate_enabled=True, near_duplicate_threshold=0.78, near_duplicate_lookback_hours=None, near_duplicate_max_comparisons=500, suppress_out_of_scope_digest=True, digest_enabled=True, digest_recipient_email=None, digest_max_items_per_run=100, digest_topic_dedupe_enabled=True, digest_topic_dedupe_threshold=0.30, digest_topic_dedupe_lookback_hours=168)`

- Purpose: inject all collaborators and policy controls.

Methods:

- `run(articles: list[SourceArticle]) -> PipelineMetrics`
  - Prepares fetched candidates, dedupes the current run in memory, processes survivors, and flushes digest.
  - Counts every input article as processed; skips DB duplicates, fetch failures, and current-run duplicate losers.
  - Catches unhandled per-item exceptions, increments `errors`, continues run.

- `_prepare_candidate(item, original_index) -> _FetchedCandidate | None`
  - Canonicalizes URL, checks stored canonical duplicates, fetches content, builds dedupe keys, and checks stored content-hash/fingerprint/near-duplicate matches.
  - Returns `None` for skipped candidates before classification or persistence.

- `_dedupe_current_run_candidates(candidates) -> tuple[list[_FetchedCandidate], int]`
  - Groups prepared candidates by exact dedupe keys and optional near-duplicate similarity.
  - Keeps the newest `published_at`; missing timestamps compare older than real timestamps, with input order as tie-breaker.
  - Returns survivor candidates in original input order plus the duplicate loser count.

- `_candidate_survivor_key(candidate) -> tuple[datetime, int]`
  - Builds the current-run survivor priority key from UTC publication time and inverse input index.

- `_within_near_duplicate_window(left, right) -> bool`
  - Applies `near_duplicate_lookback_hours` to current-run near-duplicate pairs when both timestamps are known.

- `_process_prepared(candidate, digest_queue, metrics) -> PipelineMetrics`
  - Full survivor flow (classify, extract, incident dedupe, persist, send/queue).
  - Keeps final canonical/content-hash/fingerprint DB guards for concurrent-run races.
  - Skips duplicate incidents before persistence instead of queueing them into digest.
  - Skips non-immediate digest-topic duplicates before persistence.
  - Stores out-of-scope articles as skipped digest alerts when suppression is enabled.
  - Handles DB duplicate races via `IntegrityError` rollback and skip accounting.
  - Immediate send failures do not increment `errors`; they mark alert row as `failed`.

- `_routing_reason(article_type, attack_type, has_confident_victim, duplicate_incident) -> str`
  - Routing decision helper.
  - Return values: `duplicate_incident`, non-incident article type, `out_of_taxonomy`, `low_victim_confidence`, `qualified_incident`.

- `_has_recent_incident_duplicate(incident_key, candidate_time) -> bool`
  - Finds prior articles with same incident key and compares UTC time delta to configured window.
  - If candidate time is missing but matches exist, returns `True` conservatively.

- `_find_digest_topic_duplicate(title, abstract, text, candidate_time) -> _TopicDuplicateResult | None`
  - Loads recent stored articles up to `near_duplicate_max_comparisons`.
  - Applies `digest_topic_dedupe_lookback_hours` when candidate time is known.
  - Uses `find_topic_duplicate()` over title + abstract + article-text prefix and requires shared salient title terms.

- `_find_near_duplicate(title, abstract, text, candidate_time) -> _NearDuplicateResult | None`
  - Loads recent stored articles up to `near_duplicate_max_comparisons`.
  - Applies `near_duplicate_lookback_hours` when candidate time is known.
  - Uses `build_similarity_document()` and `find_near_duplicate()` to find the best match.

- `_flush_digest_queue(digest_queue, metrics) -> PipelineMetrics`
  - Sends one digest email when enabled and queue non-empty.
  - Updates queued alert rows with final status/body/subject.

- `_published_date(published_at) -> str`
  - Converts datetime to UTC ISO8601 string; returns `unknown` when absent.

- `_ensure_utc(value) -> datetime | None`
  - Normalizes naive datetimes to UTC or converts aware datetimes to UTC.

## 6.4 `app/alerts/emailer.py`

#### `AlertEmail` (`@dataclass(frozen=True)`)

- Fields: `subject`, `body`.
- Purpose: outbound email payload object.

#### `DigestEmailItem` (`@dataclass(frozen=True)`)

- Fields: `title`, `source_name`, `routing_reason`, `link`, `published_date`, optional `attack_type`, optional `victim_name`.
- Purpose: digest-line render input.

#### `SmtpClient(Protocol)`

- Method contract: `send_message(msg: EmailMessage) -> None`.
- Purpose: structural typing hint for SMTP-like clients (not directly injected in current implementation).

#### `Emailer`

Constructor:

`__init__(smtp_host, smtp_port, smtp_username, smtp_password, sender_email, recipient_email)`

- Stores SMTP credentials and default recipient.

Methods:

- `build_subject(victim_name, victim_category, attack_type) -> str`
  - Normalizes inline fields and formats company vs non-company subject style.

- `build_body(abstract, attack_type, victim_name, victim_category, source_name, published_date, link) -> str`
  - Creates structured plaintext body.

- `_normalize_inline(value, max_chars) -> str`
  - Compacts whitespace and clips long text, preferring last-space boundary when feasible.

- `_clean_abstract(abstract) -> str`
  - Whitespace-normalizes abstract; returns fallback sentence if empty.

- `build_digest_subject(item_count) -> str`
  - Format: `Cyber News Digest: {N} queued items`.

- `build_digest_body(items) -> str`
  - Groups entries by `routing_reason` (sorted), emits multi-line plaintext sections.

- `send(email, recipient_email=None) -> None`
  - Builds `EmailMessage`, starts TLS, authenticates, sends via `smtplib.SMTP`.
  - Side effects: external SMTP network call.
  - Failure: propagates SMTP/network exceptions to caller.

## 6.5 `app/dedup/deduplicator.py`

#### `TRACKING_QUERY_PARAMS` (`set[str]`)

- Purpose: query params stripped during canonicalization (`utm_*`, `gclid`, `fbclid`).

#### `SOURCE_SUFFIX_RE`, `SIMILARITY_PUNCT_RE`

- Purpose: normalize source-suffixed titles and punctuation before TF-IDF vectorization.

#### `SimilarityMatch` (`@dataclass(frozen=True)`)

- Fields: `index`, `score`.
- Purpose: reports the matching document index and cosine score for near-duplicate detection.

#### `SimilarityPair` (`@dataclass(frozen=True)`)

- Fields: `left_index`, `right_index`, `score`.
- Purpose: reports a current-run document pair whose cosine score meets the near-duplicate threshold.

#### `normalize_incident_entity(value: str) -> str`

- Lowercases, strips punctuation to spaces, compacts whitespace.
- Used by `build_incident_key()` for stable identity.

#### `build_incident_key(victim_name: str, attack_type: str) -> str`

- Purpose: stable SHA-256 over normalized `victim|attack`.
- Output: 64-char lowercase hex digest.

#### `canonicalize_url(url: str) -> str`

- Normalizes scheme/netloc casing, path slashes/trailing slash, sorted filtered query.
- Removes tracking query params.
- Output consumed as unique DB key.

#### `_normalize_text(text: str) -> str`

- Lowercase + collapse whitespace.
- Internal helper for fingerprint/content hash stability.

#### `build_fingerprint(title: str, text: str) -> str`

- Purpose: dedupe hash from normalized `title + text[:3000]`.
- Output: SHA-256 hex digest.

#### `build_content_hash(text: str) -> str`

- Purpose: normalized full-text hash for exact duplicate skips and audit analysis.
- Output: SHA-256 hex digest.

#### `build_similarity_document(title: str, abstract: str, text: str, text_prefix_chars=4000) -> str`

- Purpose: build the normalized text passed to TF-IDF similarity matching.
- Behavior:
  - Removes common trailing source suffixes from titles.
  - Includes normalized title, abstract, and configurable article-text prefix.

#### `build_topic_document(title: str, abstract: str, text: str = "", text_prefix_chars=4000) -> str`

- Purpose: build the title-weighted normalized text used for digest-topic duplicate matching.
- Behavior: source suffix removal, topic-token normalization, title repetition to weight headlines, and normalized article-text prefix inclusion.

#### `salient_title_tokens(title: str) -> set[str]`

- Purpose: extract non-generic normalized headline terms for topic duplicate evidence.

#### `shared_salient_title_terms(left_title, right_title) -> tuple[str, ...]`

- Purpose: require at least two shared salient terms or sufficient title-token Jaccard overlap before topic duplicate suppression.

#### `find_near_duplicate(candidate_document, existing_documents, threshold) -> SimilarityMatch | None`

- Purpose: detect near-duplicate articles with `TfidfVectorizer` and cosine similarity.
- Behavior:
  - Uses English stop words and unigram/bigram features.
  - Returns the best match only when score is at least `threshold`.
  - Returns `None` for empty corpora or empty vectorizer vocabularies.

#### `find_topic_duplicate(candidate_title, candidate_abstract, candidate_text, existing_items, threshold) -> TopicDuplicateMatch | None`

- Purpose: detect digest-topic duplicates with title+abstract+text similarity plus salient-title overlap.
- Behavior:
  - Uses English stop words and unigram/bigram features over `build_topic_document()`.
  - Checks candidate matches from highest to lowest score.
  - Returns the first score above threshold that also has shared salient title terms.

#### `find_near_duplicate_pairs(documents, threshold) -> list[SimilarityPair]`

- Purpose: detect all current-run document pairs whose TF-IDF cosine score is at least `threshold`.
- Behavior:
  - Uses the same vectorizer settings as `find_near_duplicate()`.
  - Returns an empty list for fewer than two usable documents or empty vectorizer vocabularies.

#### `_normalize_similarity_text(text: str) -> str`

- Purpose: lowercase, remove URLs/punctuation, and compact whitespace for similarity documents.

#### `_normalize_topic_text(text: str) -> str`

- Purpose: apply topic-token aliases such as patch/patching, flaw/vulnerability, and govt/federal normalization.

## 6.6 `app/detection/attack_classifier.py`

#### Constants and Pattern Objects

- `ATTACK_PATTERNS: dict[str, list[re.Pattern]]`
  - In-taxonomy mapping of attack labels to detection regexes.
  - Taxonomy keys:
    - `phishing`
    - `malvertising`
    - `impersonation`
    - `business email compromise`
    - `smishing`
    - `vishing`
    - `fake updates`
    - `seo poisoning`
    - `watering hole`
    - `social media scams`
    - `credential theft`
- `ARTICLE_TYPE: Literal[...]`
  - Closed article type vocabulary:
    - `incident`
    - `campaign_report`
    - `advisory`
    - `press_release`
    - `legal_followup`
    - `opinion`
    - `out_of_scope`
- `SENTENCE_SPLIT_RE`
  - Sentence splitter regex.
- `INCIDENT_PATTERNS`, `CAMPAIGN_PATTERNS`, `ADVISORY_PATTERNS`, `PRESS_RELEASE_PATTERNS`, `LEGAL_FOLLOWUP_PATTERNS`, `OPINION_PATTERNS`
  - Weighted cue families used for article type scoring.
- `OUT_OF_SCOPE_PATTERNS`
  - Explicit false-positive suppressions applied before normal article-type routing.
  - Covers local/offline fraud blotter, community awareness or meeting-agenda items, vendor partnership/product portfolio announcements, administrative identity/authentication stories, generic explainers, school photo warnings, and bare site-index results.
- `CYBER_SCOPE_PATTERNS`
  - Strong cyber/security terms required before article-type routing proceeds.
  - Prevents generic physical/political `attack` stories from entering digest.
  - Does not treat bare `impersonation` or broad `cybersecurity` as sufficient; impersonation must appear with digital threat context such as phishing, credentials, accounts, tech support scams, brand/employee/executive impersonation, deepfakes, voice cloning, BEC, or social engineering.

#### `ClassificationResult` (`@dataclass(frozen=True)`)

- Fields: `article_type`, `attack_type`, `attack_confidence`, `incident_confidence`, `reasons`.
- Property: `is_attack -> bool`
  - True only for incident + recognized in-taxonomy attack.
- Property: `reason -> str`
  - First reason token or `unspecified` fallback.

#### `AttackClassifier`

- `classify(title, text) -> ClassificationResult`
  - Builds lead/body views.
  - Detects best attack type and confidence.
  - Scores article-type cue groups.
  - Applies explicit out-of-scope suppressions before article-type routing.
  - Applies a cyber-scope gate before assigning in-scope article types.
  - Applies ordered decision rules to assign one article type.
  - Adds explanatory reason tokens, including named `out-of-scope:*` or out-of-taxonomy markers.

- `_build_lead(text) -> str`
  - First four sentences, clipped to 1500 chars.

- `_detect_attack_type(title, lead, body) -> tuple[str | None, float]`
  - Weighted scoring per attack taxonomy.
  - Confidence clipped to `<=1.0`; values `<0.25` return `None` attack.

- `_score_patterns(patterns, title, lead, body) -> float`
  - Generic weighted pattern score helper (title=0.5, lead=0.3, body=0.2 per match).

- `_has_cyber_scope(title, lead, body) -> bool`
  - Returns true when strong cyber/security terms are present in title, lead, or early body.

- `_explicit_out_of_scope_reason(title, lead, body) -> str | None`
  - Returns a named `out-of-scope:*` reason for known false-positive families before routing proceeds.

## 6.7 `app/detection/victim_extractor.py`

#### Constants and Pattern Objects

- `ORG_CUES`: category cue keywords for `company|government|university|hospital`.
- `VICTIM_PATTERNS`: regex patterns capturing potential victim phrase spans.
- `STOP_TOKENS`: low-signal banned single-token candidates.
- `GENERIC_ENTITY_TERMS`: generic nouns rejected as victims.
- `PRODUCT_FRAGMENT_TERMS`: product/technology fragments rejected as victims.
- `NOISE_PATTERNS`: navigation/language/domain, sentence-spillover, and reporting-time noise detectors.

#### `VictimResult` (`@dataclass(frozen=True)`)

- Fields: `victim_name`, `victim_category`, `confidence`, `reason`.
- `reason` examples: `matched_title`, `matched_body`, `generic_entity`, `noisy_candidate`, `no_named_org`.

#### `VictimExtractor`

- `__init__(max_words=8)`
  - Sets upper bound for accepted/finalized candidate token count.

- `extract(title, text) -> VictimResult`
  - Collects/ranks title candidates first, then early-body candidates.
  - Returns first acceptable normalized candidate with category + confidence.
  - Falls back to diagnostic no-match reasons.

- `_collect_candidates(content, source_weight, diagnostics) -> list[tuple[str, str, float]]`
  - Applies regex extraction, normalization, noise filtering, org classification, and scoring.

- `_normalize_candidate(raw) -> str | None`
  - Trims punctuation/whitespace, length-checks, rejects stop tokens.

- `_noise_reason(candidate) -> str | None`
  - Rejects candidates for too many words, generic entities, product fragments, nav noise, sentence spillover, reporting-time fragments, dash noise, and digit noise.

- `_score_candidate(name, category, source_weight) -> float`
  - Builds confidence score with bonuses for name shape and non-company category.

- `_finalize_name(name) -> str | None`
  - Applies max-word clipping and final cleanup.

- `_classify_org(name) -> str | None`
  - Cues-based category assignment with capitalized-two-word company heuristic fallback.

## 6.8 `app/fetch/article_fetcher.py`

#### `logger`

- Module logger for download failures.

#### Constants and Pattern Objects

- `SENTENCE_SPLIT_RE`: sentence splitting.
- `MEANINGFUL_SENTENCE_RE`: minimum alpha token check.
- `NOISE_SENTENCE_RE`: navigation/promotional boilerplate filter.
- `BOILERPLATE_ATTR_RE`: DOM id/class attribute boilerplate detector.

#### `ArticleContent` (`@dataclass(frozen=True)`)

- Fields: `full_text`, `abstract`.
- Purpose: parsed article payload returned by `fetch()`.

#### `ArticleFetcher`

- `__init__(timeout_seconds, abstract_max_chars=420)`
  - Stores request timeout and abstract clipping policy.
  - Sets static user agent string.

- `_download(url) -> str`
  - HTTP GET with timeout and UA.
  - Decorated with tenacity retry (3 attempts, exponential backoff, request exceptions only).
  - Raises `requests.RequestException` subclasses on failure.

- `fetch(url) -> ArticleContent | None`
  - Downloads HTML, parses with BeautifulSoup, extracts text and abstract.
  - Returns `None` for fetch failures, empty text, or empty abstract.

- `_extract_text(soup) -> str`
  - Removes script/style/layout/noise tags and boilerplate nodes.
  - Chooses longest meaningful text from selectors (`article`, `main`, `div[itemprop='articleBody']`, `body`) with fallback.
  - Unescapes HTML entities and normalizes whitespace.

- `_extract_metadata_abstract(soup) -> str`
  - Reads `og:description` or `meta[name=description]` when long enough and non-noisy.

- `_extract_abstract(text, metadata_abstract="", max_sentences=3) -> str`
  - Selects up to N high-signal sentences with multiple quality gates.
  - Falls back to metadata abstract when sentence extraction fails.
  - Clips to configured max chars via `_clip_sentence_boundary`.

- `_is_noisy_sentence(sentence) -> bool`
  - Noise heuristics using regex and token structure markers.

- `_has_alpha_density(sentence) -> bool`
  - Requires alphabetic ratio >= 0.55.

- `_clip_sentence_boundary(text, max_chars) -> str`
  - Prefers complete-sentence clipping; falls back to whitespace-aware hard clipping.

## 6.9 `app/sources/base.py`

#### `SourceArticle` (`@dataclass(frozen=True)`)

- Fields: `source_name`, `source_type`, `title`, `url`, `published_at`.
- Purpose: normalized cross-source article descriptor consumed by pipeline.

#### `NewsSource(Protocol)`

- Contract: `fetch() -> list[SourceArticle]`.
- Purpose: structural interface for source adapters.

## 6.10 `app/sources/rss.py`

#### `logger`

- Module logger for decode/fetch diagnostics.

#### `gnewsdecoder` import object

- Dynamic optional dependency imported from `googlenewsdecoder`.
- If unavailable, set to `None` and Google News redirect links are dropped.

#### `RssSource`

- `__init__(feed_url, max_articles, decode_google_news_urls=True, source_name_override=None)`
  - Configures feed adapter and optional Google URL decode behavior.

- `_maybe_decode_google_news_url(url) -> str | None`
  - If non-Google host: returns original URL.
  - If Google host and decoder unavailable or decode failure: returns `None` (drop article).
  - If decoder status + URL present: returns decoded direct URL.

- `fetch() -> list[SourceArticle]`
  - Parses RSS/Atom feed with `feedparser`.
  - Iterates capped entries, validates title/link, optional Google decode, parses published timestamp.
  - Emits `SourceArticle` list with `source_type='rss'`.
  - Logs fetched count.

## 6.11 `app/sources/google_news.py`

#### `GoogleNewsRssSource(RssSource)`

- `__init__(query, max_articles, language='en-US', region='US', recency_window='7d')`
  - Appends `when:<window>` constraint to query.
  - Builds Google News RSS URL with quoted params (`q`, `hl`, `gl`, `ceid`).
  - Calls `RssSource.__init__` with `source_name_override='Google News'`.

## 6.12 `app/sources/gdelt.py`

#### `logger`

- Module logger for fetch summary/errors.

#### `GdeltSource`

- `__init__(query, max_articles, timeout, timespan_minutes)`
  - Stores API query constraints.

- `_fetch_json(url) -> dict[str, Any]`
  - GET + JSON decode with tenacity retry (3 attempts, exponential backoff) on request exceptions.

- `fetch() -> list[SourceArticle]`
  - Builds GDELT Doc API URL (`mode=ArtList`, `sort=DateDesc`, `timespan=<N>min`).
  - Parses payload `articles` list.
  - Converts `seendate` to UTC datetime when possible.
  - Emits `SourceArticle` list with `source_type='gdelt'` and `source_name='GDELT'`.

## 6.13 Package Marker Modules

- `app/__init__.py`: no exported symbols.
- `app/alerts/__init__.py`: no exported symbols.
- `app/detection/__init__.py`: no exported symbols.
- `app/dedup/__init__.py`: no exported symbols.
- `app/fetch/__init__.py`: no exported symbols.
- `app/sources/__init__.py`: no exported symbols.

---

## 7. Test Module Reference and Behavioral Contracts

This section maps each test symbol to the production behavior it validates.

## 7.1 `tests/test_deduplicator.py`

- `test_canonicalize_url_removes_tracking()`
  - Validates `canonicalize_url` strips tracking params and preserves meaningful query keys.
- `test_fingerprint_is_stable_for_whitespace_changes()`
  - Validates whitespace normalization invariance of `build_fingerprint`.
- `test_incident_key_is_stable_for_case_and_punctuation()`
  - Validates case/punctuation invariance of `build_incident_key`.
- `test_content_hash_is_stable_for_whitespace_changes()`
  - Validates exact content duplicate hash stability.
- `test_similarity_matches_exact_repeated_title()`
  - Confirms repeated digest titles are detected as near-duplicates.
- `test_similarity_matches_source_suffix_title_variant()`
  - Confirms source-suffix title variants are detected as near-duplicates.
- `test_similarity_does_not_match_unrelated_advisories()`
  - Confirms unrelated advisory headlines remain distinct at the default threshold.
- `test_topic_duplicate_matches_digest_rewrite_examples()`
  - Confirms digest-topic matching catches representative Meta/NSO, CISA, tax phishing, and UNC3753 rewrites.
- `test_topic_duplicate_requires_salient_title_overlap()`
  - Confirms generic overlap such as shared vendor/security terms is insufficient for topic suppression.

## 7.2 `tests/test_emailer.py`

- `_emailer() -> Emailer`
  - Test factory for deterministic emailer instance.
- `test_company_subject_format()`
  - Validates unbracketed subject for `victim_category='company'`.
- `test_non_company_subject_format()`
  - Validates bracketed subject for non-company categories.
- `test_body_contains_expected_fields()`
  - Validates body includes attack/victim/link fields.
- `test_subject_is_normalized_when_victim_name_is_noisy()`
  - Validates whitespace compaction and newline suppression in subject normalization.
- `test_body_abstract_is_compacted()`
  - Validates abstract compaction in body rendering.
- `test_digest_body_groups_items_by_reason()`
  - Validates grouping and rendering of digest items by routing reason.

## 7.3 `tests/test_attack_classifier.py`

- `test_detects_phishing_incident()`
  - Confirms incident + taxonomy detection path for phishing story.
- `test_classifies_press_release()`
  - Confirms press-release classification and non-attack semantics.
- `test_flags_out_of_taxonomy_incident()`
  - Confirms incident can be detected while `attack_type` is `None` and reason includes `out-of-taxonomy`.
- `test_flags_non_cyber_attack_story_out_of_scope()`
  - Confirms generic non-cyber attack stories are suppressed as out-of-scope.
- `test_flags_physical_war_attack_story_out_of_scope()`
  - Confirms physical/war attack headlines are not treated as cyber news.
- `test_classifies_vulnerability_advisory_as_in_scope()`
  - Confirms vulnerability/zero-day advisories remain in-scope even without an attack taxonomy label.
- `test_digest_false_positives_are_out_of_scope()`
  - Confirms known digest false positives are suppressed: local impersonation/fraud blotter, school photo warnings, vendor identity-security announcements, meeting/awareness items, exam face-authentication stories, site-index entries, and generic explainers.
- `test_digest_cyber_items_remain_in_scope()`
  - Confirms cyber-relevant digest items still pass: tech support impersonation scams, brand/employee impersonation reports, phishing, NSO/Pegasus stories, malware, malicious package/credential stealer reports, and vishing/extortion campaigns.

## 7.4 `tests/test_victim_extractor.py`

- `test_extracts_company_victim()`
  - Confirms extraction, categorization, and confidence floor for company targets.
- `test_extracts_hospital_victim()`
  - Confirms hospital cue classification.
- `test_extracts_targeting_pattern_from_title()`
  - Confirms title-priority extraction and reason `matched_title`.
- `test_rejects_noisy_google_news_style_victim_candidate()`
  - Confirms noisy/generic candidate rejection and null-result reasons.
- `test_rejects_sentence_spillover_victim_candidate()`
  - Confirms candidates crossing sentence boundaries are rejected.
- `test_rejects_reporting_time_fragment_victim_candidate()`
  - Confirms fragments like `on Monday` do not become victims.
- `test_rejects_product_fragment_victim_candidate()`
  - Confirms product/technology names are not promoted to victims.
- `test_rejects_generic_users_as_victim()`
  - Confirms generic user/device targets are rejected.

## 7.5 `tests/test_article_fetcher.py`

- `test_extract_abstract_filters_navigation_noise()`
  - Confirms noisy navigation strings are excluded from extracted abstract.
- `test_extract_abstract_clips_to_max_chars()`
  - Confirms clipping obeys `abstract_max_chars` and sentence punctuation preservation.
- `test_extract_abstract_uses_metadata_fallback_when_text_is_noisy()`
  - Confirms metadata description fallback path.
- `test_extract_text_handles_tag_with_missing_attrs_dict()`
  - Confirms robust text extraction when malformed BeautifulSoup tag attrs are `None`.

## 7.6 `tests/test_pipeline.py`

### Helper Test Doubles

- `FakeFetcher`
  - `__init__(content)` stores fixed `ArticleContent`.
  - `fetch(url)` returns fixed payload.
- `UrlMapFetcher(FakeFetcher)`
  - Returns URL-specific `ArticleContent` to test dedupe behavior across multiple articles.
- `FakeClassifier`
  - Nested dataclass `Result` mirrors production classifier output contract.
  - `classify(title, text)` returns deterministic phishing incident.
- `OutOfTaxonomyClassifier(FakeClassifier)`
  - Overrides `classify` to return incident with `attack_type=None`.
- `OutOfScopeClassifier(FakeClassifier)`
  - Overrides `classify` to return `article_type='out_of_scope'`.
- `FakeVictimExtractor`
  - Nested dataclass `Result` mirrors production victim output contract.
  - `extract(title, text)` returns deterministic high-confidence company victim.
- `LowConfidenceVictimExtractor(FakeVictimExtractor)`
  - Overrides `extract` to return low-confidence/no-victim result.
- `FakeEmailer`
  - `recipient_email` class attribute used by pipeline.
  - `__init__()` initializes send capture list.
  - `build_subject(...)`, `build_body(...)`, `build_digest_subject(...)`, `build_digest_body(...)` supply deterministic rendering.
  - `send(...)` appends outbound payload for assertions.
- `FailingEmailer(FakeEmailer)`
  - `send(...)` raises `RuntimeError("smtp down")` to test failure state persistence.
- `_settings(db_url) -> Settings`
  - Produces deterministic in-memory settings fixture.

### Pipeline Contract Tests

- `test_pipeline_sends_once_for_canonical_duplicates()`
  - Contract: canonical duplicates produce one immediate send, one stored immediate alert marked `sent`.
- `test_pipeline_current_run_canonical_duplicate_keeps_newest()`
  - Contract: current-run canonical duplicates keep the newest published article and store/send only that survivor.
- `test_pipeline_current_run_content_hash_duplicate_keeps_newest()`
  - Contract: current-run exact content duplicates keep the newest published article.
- `test_pipeline_current_run_fingerprint_duplicate_keeps_newest()`
  - Contract: current-run fingerprint duplicates keep the newest published article even when content hashes differ.
- `test_pipeline_current_run_near_duplicate_keeps_newest_when_enabled()`
  - Contract: current-run TF-IDF near-duplicates keep the newest published article when near-duplicate detection is enabled.
- `test_pipeline_current_run_near_duplicates_both_survive_when_disabled()`
  - Contract: current-run near-duplicates both persist when near-duplicate detection is disabled.
- `test_pipeline_current_run_duplicate_loser_is_not_persisted_or_in_digest()`
  - Contract: duplicate losers create no `Article`/`Alert` rows and do not appear in the digest email body.
- `test_pipeline_routes_low_confidence_victim_to_digest()`
  - Contract: low-confidence victim routes to digest with reason `low_victim_confidence`, digest sent once.
- `test_pipeline_skips_duplicate_incident_without_digest()`
  - Contract: second same-incident story within window is skipped without an `Article`/`Alert` row.
- `test_pipeline_skips_digest_topic_duplicate()`
  - Contract: non-immediate same-topic digest rewrites are skipped before persistence.
- `test_pipeline_keeps_digest_items_with_only_generic_title_overlap()`
  - Contract: digest topic dedupe does not suppress unrelated items sharing only generic title terms.
- `test_pipeline_routes_out_of_taxonomy_to_digest()`
  - Contract: incident without taxonomy attack routes to digest reason `out_of_taxonomy`.
- `test_pipeline_marks_alert_failed_when_email_send_fails()`
  - Contract: immediate send exception sets alert status `failed` and stores error text without incrementing pipeline `errors` counter.
- `test_pipeline_skips_exact_content_hash_duplicate()`
  - Contract: identical fetched article bodies are stored/sent once even with different URLs.
- `test_pipeline_skips_near_duplicate_before_digest_or_alert()`
  - Contract: TF-IDF near-duplicates are skipped before immediate or digest routing.
- `test_pipeline_suppresses_out_of_scope_digest_item()`
  - Contract: out-of-scope articles are stored as skipped digest alerts and are not emailed.

---

## 8. Infrastructure and Operations Reference

## 8.1 `requirements.txt`

Pinned dependencies and primary usage:

- `beautifulsoup4`: HTML parsing and DOM cleanup.
- `feedparser`: RSS/Atom parsing.
- `googlenewsdecoder`: decode Google News redirect URLs.
- `psycopg2-binary`: PostgreSQL driver for SQLAlchemy.
- `requests`: HTTP transport.
- `SQLAlchemy`: ORM and DB access.
- `tenacity`: retry policies for network calls.
- `python-dateutil`: robust datetime parsing (`gdelt seendate`).
- `pytest`: tests.
- `scikit-learn`: TF-IDF vectorization and cosine similarity for near-duplicate detection.

## 8.2 `Dockerfile`

Build behavior:

1. Base image: `python:3.11-slim`.
2. Environment flags: `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUNBUFFERED=1`.
3. Creates non-root user `appuser`.
4. Installs Python dependencies from `requirements.txt`.
5. Copies `app/`.
6. Switches to non-root execution.
7. Default command: `python -m app.main`.

## 8.3 Kubernetes and GitOps

- `k8s/base/namespace.yaml`: creates namespace `cyber-news-alert`.
- `k8s/base/configmap.yaml`: non-secret runtime controls and PostgreSQL database/user names.
- `k8s/overlays/prod/secrets.enc.yaml`: SOPS-managed Kubernetes Secret for SMTP, recipient, database URL, and PostgreSQL password.
- `k8s/base/postgres-statefulset.yaml`: PostgreSQL `StatefulSet` using the cluster default storage class.
- `k8s/base/cronjob.yaml`: hourly monitor execution with `concurrencyPolicy: Forbid`.
- `k8s/argocd/application.yaml`: Argo CD Application for automated prune/self-heal sync.

## 8.4 GitHub Actions

- `.github/workflows/pull-request.yml`: installs dependencies, runs tests, and builds the Docker image on pull requests.
- `.github/workflows/deploy.yml`: on `main`, runs tests, pushes the image to GHCR, updates the Kustomize image tag, and commits the GitOps update.

## 8.5 `.gitignore`

- Baseline Python ignore template plus project-specific exclusions (`.env`, `.vscode`, `.codex`, `analysis/`, caches/build artifacts).
- Prevents committing local secrets, local IDE config, runtime caches, and generated artifacts.

## 8.6 `README.md` Relationship

- `README.md` is operational/how-to oriented.
- `README_TECHNICAL.md` is implementation internals and behavioral contract oriented.
- Feature statements in `README.md` are implemented via modules documented in sections 3-7 of this file.

---

## 9. Known Limits and Extension Points

### Known Limits

- Detection and extraction are deterministic heuristic systems; edge-case precision/recall tradeoffs remain.
- Near-duplicate detection is lexical TF-IDF similarity, not semantic embeddings; paraphrases with little token overlap may still pass.
- Schema initializer is compatibility-focused and not a full migration framework.
- Immediate channel intentionally conservative (requires incident + taxonomy + confident victim + non-duplicate).
- Out-of-scope items are skipped from digest by default but are still persisted for audit/dedupe continuity.
- Digest queue truncates beyond `digest_max_items_per_run`; overflow items are stored as digest alerts with `routing_reason='digest_overflow_or_disabled'` and `status='skipped'`.
- Google News entries may be dropped when decode is unavailable/fails to avoid consent/redirect URLs.

### Extension Points

- Add new source adapters implementing `NewsSource.fetch` shape.
- Expand taxonomy by adding `ATTACK_PATTERNS` entries and adjusting classifier thresholds/rules.
- Tune false-positive suppression by adding `OUT_OF_SCOPE_PATTERNS` entries or refining `CYBER_SCOPE_PATTERNS`.
- Improve extraction robustness by tuning `VICTIM_PATTERNS`, noise filters, and confidence heuristics.
- Tune duplicate sensitivity through `NEAR_DUPLICATE_THRESHOLD`, lookback, and comparison-count settings.
- Introduce migration tooling (for example Alembic) to replace ad-hoc schema evolution in `initialize_schema`.
- Add channel integrations by extending `Emailer` abstraction and `MonitorPipeline` alert dispatch branch.

---

## 10. Symbol Coverage Checklist

The symbols below are explicitly covered in this document:

- All top-level classes/functions from `app/` and `tests/` discovered via `rg`.
- All class methods and private helpers (`_...`) in runtime modules.
- Key module objects/constants/pattern lists/regexes used for runtime decisions.
- Empty `__init__.py` modules explicitly documented as no-export package markers.
