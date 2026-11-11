<div align="center">

# Kavach

**Project Security Review · Find risks. Verify evidence.**

![Node.js](https://img.shields.io/badge/Node.js-22%2B-339933?logo=node.js&logoColor=white)
![Docker](https://img.shields.io/badge/Sandbox-Docker-2496ED?logo=docker&logoColor=white)
![SARIF](https://img.shields.io/badge/Export-SARIF%202.1.0-5C2D91)
![Runs](https://img.shields.io/badge/Execution-Local--first-informational)

</div>

Kavach is a local-first, static and model-assisted application security review engine. It audits local repositories or public HTTPS Git checkouts using a six-phase workflow adapted from [Cloudflare's `security-audit` skill](https://github.com/cloudflare/security-audit-skill), can run candidate-specific reproduction probes inside network-isolated, read-only Docker sandboxes, and checks exact dependency versions against [OSV](https://google.github.io/osv.dev/post-v1-querybatch/). Results can be downloaded as SARIF 2.1.0, Markdown, a browser print view that can be saved as PDF, or a ZIP bundle containing validated audit artifacts.

## Contents

- [Quick Start](#quick-start)
- [Objectives](#objectives)
- [Technology Stack](#technology-stack)
- [System Requirements](#system-requirements)
- [Environment Configuration](#environment-configuration)
- [System Architecture](#system-architecture)
- [Key Engineering Highlights](#key-engineering-highlights)
- [Cloudflare Workflow](#cloudflare-workflow)
- [Model Providers](#model-providers)
- [Docker Sandbox](#docker-sandbox)
- [Firebase Auth and Firestore](#firebase-auth-and-firestore)
- [Headless CLI and GitHub Code Scanning](#headless-cli-and-github-code-scanning)
- [Dependency Vulnerability Detection](#dependency-vulnerability-detection)
- [Report Outputs](#report-outputs)
- [Incremental Scans](#incremental-scans)
- [Paired-Fixture Benchmark Suite](#paired-fixture-benchmark-suite)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Scope and Limits](#scope-and-limits)
- [References](#references)

## Objectives

Kavach is intended to make a bounded, evidence-led security review available before a change is merged. Its objectives are to:

- identify deterministic source-pattern leads and exact affected dependency versions;
- use optional model-assisted source review to map coverage, trace candidates, and record unresolved evidence;
- validate findings and coverage records against vendored contracts;
- provide local reports and SARIF for human review and CI policy gates; and
- keep source collection, report history, and model-provider access within explicit local boundaries.

Kavach is a review aid, not a certification service. A clean or complete run does not prove that a project is safe.

## Technology Stack

- Node.js 22 or newer with native ECMAScript modules and npm.
- A dependency-free browser interface served by `server.mjs` using HTML, CSS, and browser JavaScript.
- Firebase Authentication for verified email/password sign-in and Firestore REST calls for per-account preferences.
- Firebase Admin Authentication SDK for server-side ID-token verification.
- PostgreSQL 16, accessed through `pg`, for local review history and coverage reuse.
- Docker Engine or Docker Desktop for optional bounded Node test and candidate-probe execution.
- OSV's batch and vulnerability-detail APIs for optional exact-version dependency matching.
- Optional Ollama, Apple MLX-compatible, Apple Foundation Models-compatible, Codex CLI, or Gemini CLI model providers.
- Vendored Cloudflare findings and coverage-ledger validators, plus SARIF 2.1.0 generation.

There is no application build step, frontend bundler, or separate migration framework in this repository.

## System Requirements

- Node.js 22 or newer and npm.
- A modern browser for the web interface.
- Docker is optional for sandbox checks. When enabled, Kavach requires a local Unix-socket Docker daemon and an already-installed image; it never pulls images automatically.
- PostgreSQL is required by the web interface for saved review history and is provided by `compose.yaml`. Headless CLI scans can run without PostgreSQL unless `--postgres-cache` is selected.
- A Firebase project with Email/Password Authentication enabled is required for the web interface. Firestore is required only for synchronizing workspace preferences.
- Git is required for public Git checkout scans and incremental `--diff` scans.

## Quick Start

**Requirements:** Node.js 22 or newer, Git, Docker Desktop (or a local Docker Engine), and a modern browser.

```sh
# 1. Configure the environment
cp .env.example .env

# 2. Start PostgreSQL
docker compose up -d postgres

# 3. Install dependencies
npm install

# 4. Start the application
npm start
```

1. **Configure.** Open `.env` and fill in your Firebase web-app values. `.env` is git-ignored and must never be committed. If you change `POSTGRES_PASSWORD`, keep the password in `DATABASE_URL` in sync.
2. **Database.** Docker Compose exposes PostgreSQL only on `127.0.0.1:54329`. If a local PostgreSQL server is already running, set `DATABASE_URL` to its loopback address instead.
3. **Sandbox image.** If Docker checks are needed, Kavach never downloads images automatically. Pull the default image once: `docker pull node:22-alpine`.
4. **Open** [http://localhost:4173](http://localhost:4173), create a Firebase account, verify its email, then sign in.

The server binds only to `127.0.0.1`. Firebase Authentication and Firestore are accessed through their REST APIs; no service-account key is required.

## Environment Configuration

Copy `.env.example` to `.env`. The `.env` file is ignored by Git and must not be committed. The web server reads these variables at startup:

| Variable | Purpose | Default or constraint |
|---|---|---|
| `PORT` | Local HTTP port | `4173`; the server may try the next nine ports if it is busy |
| `FIREBASE_PROJECT_ID` | Firebase project used for token verification | Required for web authentication |
| `FIREBASE_API_KEY` | Firebase web client configuration | Required for browser Authentication REST calls; keep it out of Git |
| `FIREBASE_AUTH_DOMAIN` | Firebase web client configuration | Required for a configured web client |
| `FIREBASE_APP_ID` | Firebase web client configuration | Required for a configured web client |
| `POSTGRES_DB` | Local PostgreSQL database name | `fieldnote` in Compose |
| `POSTGRES_USER` | Local PostgreSQL user | `fieldnote` in Compose |
| `POSTGRES_PASSWORD` | Local PostgreSQL password | Required by Compose; use a local secret |
| `DATABASE_URL` | PostgreSQL connection URL | Must resolve to `localhost`, `127.0.0.1`, or `::1` |
| `FIELDNOTE_LOCAL_MODEL_TIMEOUT_MS` | Local model request timeout | 30 seconds to 10 minutes; default 5 minutes |
| `FIELDNOTE_OLLAMA_NUM_CTX` | Ollama context window | 2,048 to 65,536 tokens; default 8,192 |
| `AUDIT_DOCKER_IMAGE` | Optional local Docker image reference | Defaults to `node:22-alpine`; image must already exist locally |

The Firebase web API key is client configuration, not a Firebase Admin service-account credential. It is returned to the local browser by `/api/auth/config` for the Firebase Auth REST calls, but it must not be committed to this repository. Firebase restrictions and credential rotation remain the owner's responsibility.

## System Architecture

```mermaid
flowchart LR
  subgraph Intake["1. Source Intake & Diff Slicing"]
    A["Local Folder (O_NOFOLLOW)<br/>or Shallow Git Snapshot"] --> B["computeDiffScope()<br/>JS/TS Import-Closure Graph"]
    B --> C["Deterministic Scanner<br/>+ Multi-Ecosystem Lockfile Parser"]
  end

  subgraph Workflow["2. Six-Phase Adversarial Audit (runCloudflareWorkflow)"]
    D["Phase 1: 4x Parallel Recon<br/>(Product, Boundaries, Surfaces, Execution)"] --> E["Phase 2: Round-Robin Hunter Waves<br/>+ Coverage Critic Loop"]
    E --> F["Phase 3: Stateless Candidate Refutation<br/>+ Canonical Trace Deduplication"]
    F --> G["Phase 4: Vendored Schema &<br/>Coverage-Ledger Validators"]
    G --> H["Phase 5: Fresh-Eyes Verification<br/>& Material Replacement Check"]
    H --> I["Phase 6: Target-Neutral Report<br/>& SARIF 2.1.0 Generation"]
  end

  subgraph Sandbox["3. Containment & Persistence"]
    J["Isolated Docker Sandbox<br/>Network-Disabled, Read-Only Container<br/>Local-Content-ID-Pinned node:22-alpine"]
    K["Loopback PostgreSQL 16<br/>SHA-256 Hash-Based Ledger Reuse"]
    L["OSV Batch API<br/>Exact Dependency Advisories"]
  end

  C --> D
  C --> L
  B <--> K
  F <--> J
  I --> M["Outputs: SARIF 2.1.0 (FNV-1a),<br/>REPORT.md, coverage-ledger.json, ZIP"]
```

## Key Engineering Highlights

| Subsystem | Implementation | Security and Engineering Invariant |
|---|---|---|
| **Six-Phase Adversarial Pipeline**<br/>[`cloudflare-skill-runner.mjs`](cloudflare-skill-runner.mjs) | Stateless role separation across Reconnaissance, Hunting, Critic Waves, Refutation, Schema/Ledger Validation, and Fresh-Eyes Verification | Source-only hunters can never emit `confirmed` findings. Canonical `entrypoint -> sink` trace hashing deduplicates multi-class hits before Phase 3 refutation. |
| **Contained Candidate Probes**<br/>[`docker-sandbox.mjs`](docker-sandbox.mjs) | Optional local-content-ID-pinned Docker containers: network disabled, read-only rootfs, dropped Linux capabilities, 16 MB scratch `tmpfs`, 256 MB RAM, 32 PIDs | Target code and model-generated probes never reach host networks, credentials, or writable source trees. The parent promotes bounded stdout only after the container exits. |
| **Incremental PR Diff and Import Closure**<br/>[`server.mjs`](server.mjs) | `computeDiffScope()` parses static JS/TS imports and reverse importers across `git diff <base>...<head>` | Reuses SHA-256-verified `covered` ledger units on unchanged paths. Fails closed to `full_reaudit` on config or lockfile changes, deleted files, dynamic imports, or more than 250 impacted files. |
| **TOCTOU-Safe Local Collector**<br/>[`server.mjs`](server.mjs) | `collectLocalDirectory()` opens regular files with `O_NOFOLLOW` and verifies `lstat`/`fstat` `(dev, ino)` parity | Prevents symlink-swap traversal outside the target repository root during local filesystem and CLI scans. |
| **CI/CD and SARIF 2.1.0 Export**<br/>[`kavach-cli.mjs`](kavach-cli.mjs), [`public/sarif.mjs`](public/sarif.mjs), [`action.yml`](action.yml) | Headless CLI (`kavach`), composite GitHub Action, and a [Code Scanning workflow](.github/workflows/kavach-audit.yml) | Emits 64-bit FNV-1a `partialFingerprints` (`kavach/v1`), maps confirmed findings to `error`, deterministic source leads to `warning`, structured unverified records to `note`, and enforces exit codes `0` / `1` / `2` / `3`. |

## Cloudflare Workflow

| Phase | Name | What happens |
|:-:|---|---|
| 1 | **Reconnaissance** | Four fresh selected-model role calls map product and stack, principals and trust boundaries, source entry surfaces and sinks, and safe local checks. Kavach also loads prior runs for the same source, compares per-file SHA-256 hashes, and selects applicable Cloudflare companion guidance. |
| 2 | **Coverage-led hunting** | A ledger is created from source surfaces, boundaries, subsystems, and attack classes. Stateless hunting roles review bounded source context. Coverage critics record gaps and reassign work. Standard and Deep repeat waves until a distinct final-clean critic accepts the ledger or a strict limit leaves it incomplete. Quick uses one wave and one final critic. |
| 3 | **Candidate validation** | A fresh role rereads each candidate and tries to refute its source trace. When Docker is selected and ready, a separate role may generate a bounded Node.js probe for up to eight candidates; the parent captures the result and promotes a report artifact after the container exits. A prior confirmed record is rechecked against current source and local evidence. Quick mode uses the same fresh verifier for Phases 3 and 5, as the Cloudflare profile requires. Unavailable runtime or deployment facts remain explicit blockers. |
| 4 | **Structured output** | Findings are validated against the vendored Cloudflare schema, and Cloudflare's official findings and coverage-ledger validators run after state changes. |
| 5 | **Independent verification** | Standard and Deep use a separate fresh role to check every retained record against current source and evidence. A material replacement receives another fresh verification and schema validation. |
| 6 | **Target-neutral reporting** | The selected model provider writes a posture and coverage summary from validated facts. Kavach generates `run-metadata.json`, `architecture.md`, `coverage-ledger.json`, `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md`. |

### Profiles and call caps

Choose a profile and a strict call cap from 12 to 512. The minimum accepted explicit budget is 12; when no budget is supplied, the profile default is used. The run never exceeds its configured cap. Any deferred unit, unresolved candidate, failed validator, unavailable prior-run comparison, or incomplete phase is reported as incomplete.

| Profile | Default call cap |
|---|---:|
| Quick | 48 |
| Standard | 128 |
| Deep | 256 |

Quick performs one hunting wave and combines candidate validation with final-record verification. Standard repeats coverage work until a distinct final-clean critic accepts the ledger and uses separate Phase 3 and Phase 5 verification. Deep adds a second pass for unchanged coverage carried from a compatible prior run before continuing the standard process. These are audit-review profiles, not vulnerability taxonomies; OSV and Docker checks are separate options.

Previous runs are scoped to the signed-in Firebase user and source identity in PostgreSQL.

### Role model

Reviewer roles are fresh, stateless prompts sent to the same selected model provider. They are not separate delegated model agents. Only candidate-specific Node.js probes and selected existing tests run as target code, inside the bounded Docker configuration described below. Kavach promotes only parent-captured output and metadata; it does not implement the Cloudflare skill's per-role scratch-directory handoff. Source-only leads and checks that need unavailable dependencies or runtime facts remain `needs_validation`.

### Source intake

- **Local folders** are read without following symlinks.
- **Git intake** creates a shallow partial clone without checking out the full repository, reads tree metadata, and fetches only eligible files within the 100 MB review cap. The clone and any Docker source staging share a 100 MB temporary workspace budget. Temporary files are deleted automatically after report generation or when a scan stops with an error.
- **Dependencies:** npm, Python, Rust, Go, Ruby, PHP, Java/Gradle/Maven, and NuGet manifests and lockfiles are parsed. OSV receives package names, ecosystems, and exact versions only when online lookup is selected.

Project source stays on your device, except for selected excerpts sent to the model provider you choose.

## Model Providers

Choose Ollama, Apple MLX, Apple Foundation Models, Codex CLI, or Gemini CLI in the workspace. The local providers require a service already running on loopback; Kavach does not install models or start model servers.

| Provider | Endpoint / invocation | Notes |
|---|---|---|
| **Ollama** | `http://127.0.0.1:11434` | Loopback server; models are listed from it. |
| **Apple MLX** | `http://127.0.0.1:8080` | MLX-compatible OpenAI-style loopback server; models are listed from it. |
| **Apple Foundation Models** | `http://127.0.0.1:11437/v1` | Model `apple-fm`. |
| **Codex CLI** | `codex exec` | Temporary working directory, read-only sandboxing, ephemeral session mode. Run `codex login` and sign in with ChatGPT. Login status is checked before scanning. |
| **Gemini CLI** | `gemini --prompt` | Temporary working directory, plan mode. Run `gemini` and sign in with Google. Installation is checked before scanning; sign-in is checked when a review begins. Kavach requests deletion of its temporary local session after each call, but Gemini CLI may keep local session records until that command completes. |

Codex CLI and Gemini CLI use the sign-in already configured in those tools; Kavach does not request or store model API keys.

> [!WARNING]
> With Ollama, MLX, or Apple Foundation Models, selected source excerpts and audit prompts go to the local loopback model server. With Codex CLI or Gemini CLI, selected excerpts are passed to that tool for processing under its signed-in account. The complete repository is never placed in the CLI working directory. Do not send source to a provider unless its account terms allow it. Each report records which provider was used and where prompts were processed. Provider quotas, terms, and usage limits apply.

### Runtime behavior and tuning

| Variable | Purpose | Range | Default |
|---|---|---|---|
| `FIELDNOTE_LOCAL_MODEL_TIMEOUT_MS` | Model request timeout | 30 s to 10 min | 5 min |
| `FIELDNOTE_OLLAMA_NUM_CTX` | Ollama context window (tokens) | 2,048 to 65,536 | 8,192 |

- Reconnaissance uses Ollama's JSON-schema response format and retries once when a response is malformed or omits required, source-grounded fields. Each retry counts against the selected call cap. The same repair attempt is available for malformed JSON from the CLI providers.
- The six-phase review is marked **incomplete** when the selected CLI or local model is unavailable, not signed in, or fails to complete a phase.
- Kavach does not download models or start model servers.
- CLI use avoids managing an API key in Kavach, but it is not guaranteed to be faster. Startup time, provider load, rate limits, and the multi-call audit all affect duration.

## Docker Sandbox

Kavach checks that Docker is connected to a local Unix socket and pins each run to the locally installed image's content ID. It never pulls an image, runs package installation, project scripts, builds, or arbitrary Git hooks. The Node sandbox does not receive the Docker socket or a mount of the original project folder.

| Setting | Existing tests | Candidate probes |
|---|---|---|
| **Scope** | Up to 8 discovered files: `*.test.{js,mjs,cjs}`, `*.spec.{js,mjs,cjs}`. Each runs on its own. | Up to 8 candidates, one model-generated Node.js probe each |
| **Network** | Disabled | Disabled |
| **Source mount** | Read-only staged tree | Read-only |
| **Root filesystem** | Read-only | Read-only |
| **Scratch `tmpfs`** | 64 MB | 16 MB |
| **Memory / CPU / PIDs** | Bounded | 256 MB / 1 CPU / 32 |
| **Script / output limit** | Per-file and output limits | 16 KB / 96 KB |
| **Time limit** | Bounded | 12 seconds |
| **User / capabilities** | Non-root, no extra Linux capabilities | Non-root, no extra Linux capabilities |
| **Environment** | Empty, allowlisted | Empty, allowlisted |

**Behavior**

- Git's temporary checkout and Docker's staged source share one 100 MB host workspace cap. Docker checks are marked blocked if staging would exceed the remaining space.
- Temporary checkout and staging files are removed after report generation or when the Docker test run finishes.
- In Phase 3, a probe must complete successfully with nonempty, untruncated output before a candidate may be confirmed. The parent process writes a bounded evidence record only after the container exits. Every result still receives the independent Cloudflare workflow review.
- Candidates that need dependencies, other language runtimes, builds, or deployment facts remain `needs_validation`.
- A passing test or probe does not certify that a project is safe.

## Firebase Auth and Firestore

- **Authentication.** Email/password sign-in uses Firebase Authentication for the project configured in `.env`. Accounts must verify their email. The browser keeps the Firebase session for the current browser session only, and the local server verifies Firebase ID tokens before granting access to PostgreSQL history or starting a review.
- **Resuming reviews.** A pending review ID is kept in tab session storage so the same account can resume polling after signing in again. No token or source files are stored there.
- **Firestore.** One small preferences document per account is stored at `fieldnoteProfiles/{uid}`, containing only the selected model settings and review options. Rules allow an email-verified user to read and update only their own document; every other path is denied. Source files, findings, reports, and Git addresses are never written to Firestore.
- **PostgreSQL.** Review reports, findings, coverage, and audit artifacts are stored in a local Docker volume, scoped to the authenticated Firebase UID. Project source files are not saved.

## Headless CLI and GitHub Code Scanning

The CLI uses the same scan pipeline without starting the web server or Firebase authentication.

- PostgreSQL history is off by default. `--postgres-cache` opts local-folder scans into hash-based reuse with a PostgreSQL service on this device.
- Local folders are read without following symlinks, special files are skipped, and the same file-count, file-size, and total-size limits as the workspace apply.
- Model output, OSV package/version requests, and Docker probes are optional and controlled by explicit flags.
- Without a model provider, Kavach still runs deterministic checks and labels the six-phase review **incomplete**. It never presents that as a completed AI review.

```sh
node kavach-cli.mjs scan . --sarif out.sarif.json --fail-on confirmed
node kavach-cli.mjs scan . --provider ollama --model qwen3:8b --docker-probes --output-dir out/kavach
```

### Exit-code gating

- `--fail-on confirmed` fails for verified source findings and for exact affected dependency versions returned by OSV. Deterministic source leads remain SARIF warnings and do not satisfy that threshold.
- `--require-complete` additionally returns exit code `3` when the six-phase workflow did not complete.

### GitHub Action

`action.yml` provides a composite action, and [`.github/workflows/kavach-audit.yml`](.github/workflows/kavach-audit.yml) demonstrates SARIF artifact retention and upload to GitHub Code Scanning.

- Upload requires `security-events: write` and a repository where Code Scanning is available.
- Fork pull requests keep the SARIF artifact but skip upload, because their default token cannot write code-scanning results.
- The workflow does not use `pull_request_target` and does not run repository code in Docker.
- GitHub-hosted runners cannot reach a developer's loopback Ollama or MLX service. For model-assisted CI, configure a self-hosted runner or another explicit provider.

See GitHub's [SARIF upload guide](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file) and [fork workflow restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

## Dependency Vulnerability Detection

When OSV lookup is enabled, Kavach parses supported manifests and lockfiles, sends only package name, ecosystem, and exact version coordinates to `https://api.osv.dev`, and resolves returned advisory details. Queries are sent in batches of up to 100 dependencies. Advisory aliases are used to display CVE identifiers when OSV supplies them; otherwise the OSV advisory ID is retained. A source-file CVE mention is reported separately and is not treated as an affected dependency.

Dependency severity is a broad OSV-derived label. Kavach first uses an advisory or ecosystem severity label and otherwise maps a numeric advisory score to `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` using the thresholds in `server.mjs`. It does not calculate CVSS vectors, normalize CWE categories, or independently prove that a dependency is exploitable in the target project. `--fail-on` applies to exact OSV matches and confirmed source findings, not to deterministic source leads.

## Report Outputs

The web interface provides:

- Markdown report download;
- SARIF 2.1.0 download with source-relative locations and stable `kavach/v1` partial fingerprints;
- a browser print view that the user can save as PDF; and
- a client-generated ZIP containing the validated audit artifacts when a model-assisted audit ran.

The CLI writes text, JSON, or SARIF to standard output and can write an output directory containing `result.json`, `REPORT.md`, `results.sarif.json`, and the audit artifacts returned by the workflow. The CLI does not generate a PDF file itself. Model-assisted artifacts include `run-metadata.json`, `architecture.md`, `coverage-ledger.json`, `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md`; candidate execution files are added only when Docker probes run.

## Incremental Scans

Load prior coverage from either a portable JSON baseline or `--postgres-cache`, then run `--diff <base>...<head>` on a clean local Git checkout whose `HEAD` matches `<head>`.

```sh
# Create a baseline
node kavach-cli.mjs scan . --provider ollama --model qwen3:8b --save-baseline .kavach/baseline.json

# Diff scan against the baseline, then refresh it
node kavach-cli.mjs scan . --provider ollama --model qwen3:8b --diff origin/main...HEAD --baseline .kavach/baseline.json --save-baseline .kavach/baseline.json

# PostgreSQL-backed alternative
node kavach-cli.mjs scan . --provider ollama --model qwen3:8b --postgres-cache
node kavach-cli.mjs scan . --provider ollama --model qwen3:8b --diff origin/main...HEAD --postgres-cache
```

- Kavach reuses unchanged, fully covered units (verified by SHA-256 source hashes and prior coverage records) only when the profile, provider/model, budget, workflow revision, and engine revision all match.
- Changed paths and their JavaScript/TypeScript import closure are re-audited.
- Configuration changes, deleted paths, unresolved or dynamic imports, unsupported changed languages, and large dependency closures fall back to a full re-audit. The report records the selected diff and its fallback reason.
- Baseline files and SARIF output default to the git-ignored `.kavach/` directory, so later scans do not analyze prior artifacts.

## Paired-Fixture Benchmark Suite

[`benchmarks/fixtures.mjs`](benchmarks/fixtures.mjs) and [`benchmarks/run.mjs`](benchmarks/run.mjs) evaluate 25 paired vulnerable/patched JavaScript fixtures (50 files) across five vulnerability classes: `sql-injection`, `ssrf`, `path-traversal`, `command-injection`, and `prototype-pollution`. All six workflow phases appear in the report; precision, recall, F1, false positives, and false negatives are scored only for candidate-detection phases. The goal is to measure how trace attribution in Phases 2, 3, and 5 eliminates false positives that pattern matching produces on patched controls.

| Stage | Candidates | Precision | Recall | F1 | False Positives | False Negatives |
|---|---:|---:|---:|---:|---:|---:|
| **Deterministic regex baseline (Phase 0)** | 17 | 82.4% | 56.0% | 0.667 | 3 | 11 |
| **Reconnaissance (Phase 1)** | n/a | n/a | n/a | n/a | n/a | n/a |
| **Hunt (Phase 2, pilot quick run)** | 2 | 100.0% | 4.0% | 0.077 | 0 | 24 |
| **Refutation (Phase 3, pilot quick run)** | 2 | 100.0% | 4.0% | 0.077 | 0 | 24 |
| **Structured output (Phase 4)** | n/a | n/a | n/a | n/a | n/a | n/a |
| **Independent verification (Phase 5, pilot quick run)** | 2 | 100.0% | 4.0% | 0.077 | 0 | 24 |
| **Target-neutral reporting (Phase 6)** | n/a | n/a | n/a | n/a | n/a | n/a |

Phases 1, 4, and 6 are included for completeness but do not classify fixture sinks, so candidate metrics are not applicable (`n/a`). Their workflow status and raw artifacts remain available in the JSON benchmark result.

- **False positives:** the 3 deterministic false positives on patched fixtures fell to 0 in the pilot quick run. That run surfaced only 2 candidates (4.0% recall), so the reduction reflects very low candidate volume as well as trace-grounded refutation. Treat it as a pilot result, not a measured detection rate. Details: [`codex-quick.md`](benchmarks/results/codex-quick.md) and [`deterministic-baseline.md`](benchmarks/results/deterministic-baseline.md).
- **Scale:** the 25-pair corpus is an initial pilot and is not evidence of broad ecosystem coverage.

**Reproduce**

```sh
npm test
node benchmarks/run.mjs --deterministic-only --out benchmarks/results/deterministic-baseline.json
npm run benchmark -- --provider ollama --model qwen3:8b --runs 3 --out benchmarks/results/qwen3.json
```

The deterministic baseline does not require a model provider. The model-backed benchmark makes real model calls, so run it only with a model/provider you intend to evaluate. Adding `--docker-probes` also runs candidate-specific checks, but only when Docker and the selected local image are already available.

## Project Structure

```text
.
├── server.mjs                         Local web server, source intake, OSV, and job orchestration
├── kavach-cli.mjs                     Headless CLI and exit-code policy
├── cloudflare-skill-runner.mjs        Six-phase model-assisted workflow and artifacts
├── audit-workflow.mjs                 Workflow export used by the server and CLI
├── docker-sandbox.mjs                 Local Docker test and candidate-probe containment
├── database.mjs                       PostgreSQL history and coverage persistence
├── firebase-auth.mjs                  Firebase Admin ID-token verification
├── public/                            Browser UI, Firebase REST client, and SARIF writer
├── benchmarks/                        Paired fixtures, runner, and checked-in pilot results
├── tests/                             Node test suite
├── vendor/cloudflare-security-audit-skill/
│                                      Vendored schemas, guidance, and validators
├── action.yml                         Reusable composite GitHub Action
├── .github/workflows/                 GitHub Code Scanning workflow
├── compose.yaml                       Local PostgreSQL 16 service
├── firestore.rules                    Per-user Firestore preference rules
└── .env.example                       Local configuration template
```

## Troubleshooting

- **PostgreSQL is offline:** run `docker compose up -d postgres`, confirm `DATABASE_URL` points to `127.0.0.1:54329`, and check `curl http://127.0.0.1:4173/api/postgres/status` after starting the server.
- **Firebase is not configured:** verify all four Firebase variables in `.env`, restart `npm start`, and enable Email/Password Authentication in the Firebase project.
- **Email sign-in is rejected:** verify the account's email before signing in. The server rejects unverified Firebase ID tokens.
- **Docker checks are blocked:** start a local Docker daemon and install the selected image with `docker pull node:22-alpine` (or set `AUDIT_DOCKER_IMAGE` to an existing local image). Kavach will not pull it for you.
- **A local model is unavailable:** start the selected loopback service, confirm its model name in the workspace, and use only a direct `127.0.0.1` or `::1` URL. Remote model endpoints are rejected.
- **Codex or Gemini review cannot start:** install the corresponding CLI, sign in in the terminal, and retry. Kavach uses the CLI's existing sign-in and does not manage provider API keys.
- **The review is incomplete:** inspect `incomplete_reasons`, the phase statuses, and `NEEDS-VALIDATION.md`. Incomplete coverage, unavailable runtime facts, failed validators, and exhausted budgets are retained rather than presented as a clean review.
- **GitHub Code Scanning upload fails:** retain the SARIF artifact first. Upload requires `security-events: write`, a public repository with Code Scanning support, and a same-repository pull request or push context. Private repositories still keep the workflow artifact but skip SARIF upload in the included workflow.

## Scope and Limits

- Folder scans read up to 8,000 files and 100 MB, skipping common generated folders, binaries, symlinks, and individual files above 1 MB.
- Git checkout and Docker staging share a temporary workspace capped at 100 MB. Temporary source copies are removed after report generation, including when a review fails.
- Git scans accept public HTTPS repositories from GitHub, GitLab, or Bitbucket and fetch a shallow snapshot without submodules.
- The dependency scanner does not calculate CVSS, assign CWE categories, or perform full transitive resolution for every manifest format; it uses exact versions available in supported manifests and lockfiles.
- The application does not provide a general-purpose generated PDF export; PDF output is the browser's print/save operation.
- A source-only review is not a certification and cannot prove that no vulnerabilities remain.
- A complete six-phase workflow means every procedural phase completed for the reported scope. It does not imply runtime validation or prove safety.

## References

- [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) (vendored at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`)
- [Firebase Authentication](https://firebase.google.com/docs/auth)
- [Firestore security rules](https://firebase.google.com/docs/firestore/security/get-started)
- [Docker container run reference](https://docs.docker.com/engine/containers/run/)
- [Ollama API](https://docs.ollama.com/api/chat)
- [MLX-LM HTTP model server](https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/SERVER.md)
- [Codex CLI non-interactive mode](https://developers.openai.com/blog/codex-as-a-platform)
- [Gemini CLI authentication](https://github.com/google-gemini/gemini-cli/blob/main/docs/get-started/authentication.mdx)
- [Gemini CLI headless mode](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/tutorials/automation.md)
- [OSV batch query API](https://google.github.io/osv.dev/post-v1-querybatch/)
