# Kavach Project Brief (V0.1)

## Purpose

Kavach is a local-first application security review workspace. It combines deterministic source-pattern checks, exact dependency-version matching against OSV, and an optional model-assisted six-phase source review. The result can be consumed by people through Markdown and browser reports or by CI through SARIF 2.1.0.

Kavach is a review aid, not a security certification. A source-only result cannot prove runtime exploitability or that a project is safe.

## How Kavach works

The repository has a web server, a headless CLI, and a shared workflow runner:

1. `server.mjs` serves the local browser workspace, collects a local folder or public HTTPS Git checkout, runs deterministic checks, parses dependencies, optionally queries OSV, and starts the review.
2. `kavach-cli.mjs` runs the same pipeline without Firebase or the web server and can write SARIF, JSON, Markdown, baselines, and audit artifacts.
3. `cloudflare-skill-runner.mjs` runs six fresh, stateless review roles through one selected model provider. These are prompt roles inside the parent process, not independent delegated agents.
4. `docker-sandbox.mjs` optionally runs selected Node tests or candidate-specific probes in a local network-disabled Docker container.
5. `database.mjs` stores per-user review history in local PostgreSQL when the web interface or `--postgres-cache` requests persistence.

## Six phases

1. Reconnaissance maps the product, principals, trust boundaries, source surfaces, sinks, and local checks.
2. Coverage-led hunting assigns source excerpts to stateless review prompts and uses coverage critics.
3. Candidate validation rereads and attempts to refute source-grounded candidates; optional Docker probes provide bounded local evidence.
4. Structured output validates findings and coverage records against vendored contracts.
5. Independent verification checks retained records with fresh evidence. Quick combines this with Phase 3; Standard and Deep use separate verification.
6. Target-neutral reporting writes the final posture summary and structured artifacts from validated facts.

## Profiles and budgets

Profiles change review depth, not vulnerability categories:

| Profile | Default model-call cap | Summary |
|---|---:|---|
| `quick` | 48 | One hunting wave and combined candidate/final verification. |
| `standard` | 128 | Repeated coverage work with separate Phase 3 and Phase 5 verification. |
| `deep` | 256 | Standard behavior plus a second pass for compatible prior coverage. |

An explicit budget must be an integer from 12 through 512. Twelve is the minimum accepted value, not the default. The web UI and CLI default to Standard; the GitHub Action defaults to Quick.

## Inputs and outputs

The CLI accepts a local path or public HTTPS GitHub, GitLab, or Bitbucket URL. Important options include `--profile`, `--budget`, `--provider`, `--model`, `--osv`, `--docker-tests`, `--docker-probes`, `--scope`, `--diff`, `--baseline`, `--postgres-cache`, `--sarif`, `--output-dir`, `--fail-on`, and `--require-complete`.

Exit codes are:

- `0`: the configured policy threshold was not reached;
- `1`: the configured threshold was reached;
- `2`: invalid input or runtime error; and
- `3`: the six-phase workflow was incomplete and `--require-complete` was selected.

The web interface downloads Markdown and SARIF, offers browser print/save-to-PDF, and creates a ZIP of model-assisted audit artifacts. The CLI output directory contains `result.json`, `REPORT.md`, `results.sarif.json`, and any returned workflow artifacts.

## Technology and security boundaries

- Node.js 22 or newer, native ESM, and npm.
- Firebase email/password Authentication for verified web accounts; Firebase Admin verifies ID tokens.
- Firestore stores only per-user model and review preferences.
- PostgreSQL is restricted to localhost and stores review history scoped by Firebase UID or the CLI's local identity.
- OSV receives package coordinates and exact versions only; repository source is not sent to OSV.
- Local model endpoints are restricted to loopback. Codex and Gemini use their existing signed-in CLI sessions with temporary workspaces.
- Docker checks use a preinstalled local image, `--pull=never`, a local content ID, no network, a read-only root filesystem and source mount, dropped capabilities, no-new-privileges, bounded memory/CPU/PIDs, and a scratch `tmpfs`.

The dependency path does not calculate CVSS vectors, assign CWE categories, or guarantee complete transitive resolution. The source path emits leads that require evidence and may remain `needs_validation`.

## Local setup

```sh
cp .env.example .env
docker compose up -d postgres
npm install
npm start
```

Open `http://localhost:4173`. Set the Firebase web configuration and local PostgreSQL values in `.env`; do not commit `.env`. Docker and model providers are optional. For headless scans, use `node kavach-cli.mjs --help`.
