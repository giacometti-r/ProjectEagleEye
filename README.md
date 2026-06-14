# Cyber News Alert Monitor

Python 3.11 service that monitors free cybersecurity news sources (RSS, Google News RSS, optional GDELT), classifies social-engineering stories, deduplicates results in PostgreSQL, and sends SMTP alerts. Production deployment is GitOps-based on Kubernetes with GitHub Actions, GHCR, Argo CD, Kustomize, and SOPS-managed secrets.

## Features

- Free sources only: curated RSS feeds, Google News RSS queries, optional GDELT Doc API.
- Closed attack taxonomy for immediate alerts: phishing, malvertising, impersonation, business email compromise, smishing, vishing, fake updates, SEO poisoning, watering hole, social media scams, credential theft.
- Article-type gating: `incident`, `campaign_report`, `advisory`, `press_release`, `legal_followup`, `opinion`, `out_of_scope`.
- Strict immediate alerting: immediate emails only for qualified incidents with in-taxonomy attack type and confident victim extraction.
- Digest channel: one digest email per run for queued non-immediate items; clearly out-of-scope items are suppressed by default.
- Source freshness filtering drops stale dated items before article fetch/classification.
- Source and article HTTP fetches use explicit timeouts and isolated sessions (`trust_env=False`).
- Source queries and cyber-scope filters reject broad `impersonation`/`cybersecurity` matches unless they include digital threat context.
- Cross-source incident dedupe: 48-hour incident-key dedupe to suppress syndicated rewrites in immediate channel.
- TF-IDF cosine near-duplicate and digest-topic duplicate detection to skip syndicated/reworded articles before alerting.
- Boilerplate-resistant article cleanup and improved abstract generation with metadata fallback.
- URL/fingerprint/content-hash dedupe plus conservative victim extraction and robust retries/logging.

## Project Structure

- `app/main.py`: single-run entrypoint
- `app/pipeline.py`: routing/orchestration for immediate + digest channels
- `app/sources/`: RSS, Google News RSS, GDELT source adapters
- `app/fetch/article_fetcher.py`: article extraction and abstract generation
- `app/detection/`: attack classifier and victim extractor
- `app/dedup/deduplicator.py`: canonicalization, hashes, incident key, TF-IDF similarity
- `app/alerts/emailer.py`: SMTP sender and digest formatting
- `app/models.py`: SQLAlchemy models
- `app/schema_init.py`: idempotent schema setup and column backfill
- `k8s/`: Kubernetes base, production overlay, and Argo CD application
- `.github/workflows/`: pull request validation and main-branch image/GitOps pipeline
- `tests/`: unit and integration-lite tests

## Configuration

Runtime configuration is injected by Kubernetes.

Secret values live in `k8s/overlays/prod/secrets.enc.yaml`, which must be encrypted with SOPS before production sync. Non-secret runtime controls live in `k8s/base/configmap.yaml`.

Required secret variables:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SENDER_EMAIL`
- `RECIPIENT_EMAIL`
- `DIGEST_RECIPIENT_EMAIL`
- `POSTGRES_PASSWORD`
- `DATABASE_URL`

Optional runtime controls:

- `LOG_LEVEL`
- `REQUEST_TIMEOUT_SECONDS`
- `MAX_ARTICLES_PER_SOURCE`
- `MAX_ARTICLE_AGE_HOURS` (default: `168`, `0` disables)
- `ENABLE_GDELT`
- `GDELT_QUERY_WINDOW_MINUTES`
- `RSS_FEEDS` (comma-separated or JSON array)
- `GOOGLE_NEWS_QUERIES` (comma-separated or JSON array)
- `MIN_VICTIM_CONFIDENCE` (default: `0.65`)
- `INCIDENT_DEDUPE_WINDOW_HOURS` (default: `48`)
- `NEAR_DUPLICATE_ENABLED` (default: `true`)
- `STORED_NEAR_DUPLICATE_THRESHOLD` (default: `0.38`)
- `CURRENT_RUN_NEAR_DUPLICATE_THRESHOLD` (default: `0.34`)
- `NEAR_DUPLICATE_LOOKBACK_HOURS` (default: fallback to `INCIDENT_DEDUPE_WINDOW_HOURS`)
- `NEAR_DUPLICATE_MAX_COMPARISONS` (default: `500`)
- `SUPPRESS_OUT_OF_SCOPE_DIGEST` (default: `true`)
- `DIGEST_ENABLED` (default: `true`)
- `DIGEST_RECIPIENT_EMAIL` (default: fallback to `RECIPIENT_EMAIL`)
- `DIGEST_MAX_ITEMS_PER_RUN` (default: `100`)
- `DIGEST_TOPIC_DEDUPE_ENABLED` (default: `true`)
- `DIGEST_TOPIC_DEDUPE_THRESHOLD` (default: `0.40`)
- `DIGEST_TOPIC_DEDUPE_LOOKBACK_HOURS` (default: fallback to `MAX_ARTICLE_AGE_HOURS`)
- `ABSTRACT_MAX_CHARS` (default: `420`)
- `MAX_VICTIM_WORDS` (default: `8`)

## Kubernetes Deployment

The production overlay deploys:

- namespace `cyber-news-alert`
- in-cluster PostgreSQL `StatefulSet` with a PVC
- hourly `CronJob` running `python -m app.main`
- app image `ghcr.io/giacometti-r/projecteagleeye`
- SOPS-managed Kubernetes `Secret`

Bootstrap:

```bash
# Replace .sops.yaml with your age public key first.
sops --encrypt --in-place k8s/overlays/prod/secrets.enc.yaml

# Apply once after Argo CD and SOPS/KSOPS support are installed.
kubectl apply -f k8s/argocd/application.yaml
```

Validate rendered manifests:

```bash
kubectl apply --dry-run=client -k k8s/overlays/prod
```

## CI/CD

- Pull requests install development dependencies, run `pytest`, and build the container image locally.
- Pushes to `main` run tests with development dependencies, build and push the runtime-only image to GHCR, update `k8s/overlays/prod/kustomization.yaml` with the commit SHA tag, and commit that GitOps change.
- Argo CD watches `k8s/overlays/prod` on `main` and syncs the cluster with prune/self-heal enabled.

## Security Controls

- **Outbound URL safety**: article and source URLs are restricted to `http/https`, reject embedded credentials, and block localhost/private/link-local/multicast/reserved/non-global targets.
- **Redirect safety**: article fetches use manual redirect handling with URL re-validation on each hop to prevent SSRF via open redirects.
- **Transport hardening**: SMTP delivery uses STARTTLS with explicit certificate-verifying TLS context.
- **Request isolation**: HTTP clients use a dedicated `requests.Session` with `trust_env=False` to avoid `.netrc`/proxy credential leakage through ambient environment settings.
- **Response limits**: article downloads enforce content-type checks and response size limits before parsing.
- **Dependency policy**: pin dependencies and update promptly for security advisories (including transitive/development tooling).

## Hourly Scheduling

Kubernetes owns scheduling through `k8s/base/cronjob.yaml`.

Default cron expression:

- `0 * * * *`

This executes at minute 0 every hour.

## Deduplication Logic

Each candidate article is freshness-filtered and deduplicated by batched stored-key checks, current-run grouping, and cached recent-article similarity comparisons:

1. **Source freshness**: drops dated source items older than `MAX_ARTICLE_AGE_HOURS`; missing dates are retained.
2. **Canonical URL**: strips tracking parameters (`utm_*`, `gclid`, `fbclid`) and normalizes URL parts.
3. **Content hash**: SHA-256 over normalized full text to skip exact body duplicates.
4. **Stored TF-IDF cosine similarity**: compares normalized title + abstract + article-text prefix against recent stored articles using `STORED_NEAR_DUPLICATE_THRESHOLD`.
5. **Fingerprint hash**: SHA-256 over normalized title + article text prefix.
6. **Incident key**: SHA-256 over normalized `(victim + attack type)` with a time window (`INCIDENT_DEDUPE_WINDOW_HOURS`) to skip same-victim incident follow-ups.
7. **Current-run TF-IDF grouping**: groups same-run near duplicates using `CURRENT_RUN_NEAR_DUPLICATE_THRESHOLD`; source priority chooses the survivor before newest-published tie-breaking.
8. **Digest-topic similarity**: compares title + abstract + article-text prefix for non-immediate items using `DIGEST_TOPIC_DEDUPE_THRESHOLD` and requires shared salient headline terms before skipping.

Near-duplicate scores below `0.35` must also share salient headline terms or named entities before the article is skipped. If canonical URL, content hash, near-duplicate similarity, fingerprint, incident key, or digest-topic similarity already matches, the article is skipped.

## Alert Qualification Flow (Two Channels)

1. Fetch article and generate cleaned text + abstract.
2. Classify article type and attack type using weighted title/lead/body scoring.
3. Suppress `out_of_scope` articles from digest when `SUPPRESS_OUT_OF_SCOPE_DIGEST=true`.
4. Extract victim with conservative title-first and body fallback patterns.
5. Immediate channel requires all of:
   - `article_type == incident`
   - in-taxonomy `attack_type` present
   - victim confidence >= `MIN_VICTIM_CONFIDENCE`
   - no incident-key duplicate within `INCIDENT_DEDUPE_WINDOW_HOURS`
6. If immediate criteria fail, skip same-incident and digest-topic duplicates; otherwise route to digest queue with routing reason:
   - `low_victim_confidence`
   - `campaign_report`
   - `advisory`
   - `press_release`
   - `legal_followup`
   - `opinion`
   - `out_of_taxonomy`
7. At end of run, send one digest email (if enabled) with queued items grouped by reason.

## False Positive Controls

- Article-type gating blocks press releases, legal recaps, advisories, and opinion pieces from immediate channel.
- Cyber-scope gating suppresses non-cyber stories that only contain generic words such as `attack`.
- Bare `impersonation` is not enough for cyber scope; it must be tied to phishing, credentials, accounts, tech support scams, brand/employee/executive impersonation, deepfakes, voice cloning, BEC, or social engineering.
- Explicit out-of-scope rules suppress local/offline fraud blotter, community awareness/meeting items, vendor partnership announcements, administrative identity checks, generic explainers, and bare site-index results.
- Confidence thresholds enforce both incident context and victim quality.
- Incident-key, TF-IDF, and digest-topic dedupe suppress syndicated wire rewrites, source-title variants, and repeated digest topics.
- Victim extraction rejects generic users, product fragments, sentence spillover, and reporting-time fragments.
- Digest routing preserves visibility while keeping immediate alerts conservative.

## Sample Outputs

Immediate alert example:

```text
Subject: Acme Corp was attacked using phishing

Abstract:
...

Attack type: phishing
Victim: Acme Corp
Victim category: company
Source: Example News
Published date: 2026-04-29T00:00:00+00:00
Article link: https://example.com/article
```

Digest item example:

```text
Reason: campaign_report (1)
- CTM360 Exposes Global GovTrap Campaign...
  Source: Google News
  Attack type: phishing
  Victim: n/a
  Published date: 2026-04-27T08:01:00+00:00
  Link: https://...
```

## Testing

Run tests locally:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
PYTHONPATH=. pytest -q
```

## Limitations

- Heuristic extraction remains deterministic and can miss edge-case victims by design.
- Abstract quality still depends on source HTML structure and metadata quality.
- Digest-topic dedupe is lexical and conservative; repeated topics with little title/abstract overlap can still appear.
- Schema initialization is idempotent but is not a full migration system.
- Closed taxonomy intentionally routes some real incidents to digest as `out_of_taxonomy`.
- Scope filtering is heuristic; new noisy source patterns may require adding explicit out-of-scope rules.
