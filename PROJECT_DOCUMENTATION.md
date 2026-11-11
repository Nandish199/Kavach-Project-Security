# Kavach Project Documentation

## 1. Purpose and scope

Kavach is a local-first application security review workspace. It combines deterministic source-pattern checks, exact dependency-version lookup through OSV, and an optional model-assisted six-phase source review. It produces evidence-oriented reports and SARIF 2.1.0 for local review and CI policy gates.

Kavach is not a certification system. A clean scan, a complete workflow, a passing test, or an OSV lookup with no match does not prove that a project is safe or exploitable.

## 2. Actual architecture

Kavach has two execution surfaces:

| Component | File | Responsibility |
|---|---|---|
| Web server and orchestration | `server.mjs` | Serves the browser UI on loopback, collects local folders or public Git checkouts, runs deterministic checks, dependency parsing, OSV lookup, optional Docker checks, and the model workflow. |
| Headless CLI | `kavach-cli.mjs` | Runs the same scan pipeline without the web server or Firebase authentication, writes SARIF/JSON/Markdown artifacts, and applies exit-code thresholds. |
| Six-phase workflow | `cloudflare-skill-runner.mjs` | Runs the local adaptation of the vendored Cloudflare security-audit method, validates structured records, and creates audit artifacts. |
| Workflow export | `audit-workflow.mjs` | Re-exports the workflow used by the server and CLI. |
| Browser application | `public/` | Provides source selection, authentication, progress, report rendering, Markdown/SARIF/ZIP downloads, and browser print-to-PDF. |
| Docker containment | `docker-sandbox.mjs` | Runs only selected existing Node tests and optional candidate-specific Node probes in a local, bounded Docker container. |
| Persistence | `database.mjs` | Creates and accesses the local PostgreSQL review-history table and performs per-user queries. |
| Authentication | `firebase-auth.mjs` | Verifies Firebase ID tokens with the Firebase Admin Authentication SDK. |

The implementation does not create independent delegated analysis agents. The workflow sends fresh, stateless prompts to one selected provider and keeps shared state, files, ledgers, and artifacts in the parent Kavach process. Prompt labels such as `hunter` and `verifier` describe review roles, not separate running agents.

## 3. Six-phase workflow

The workflow is an adaptation of the vendored Cloudflare security-audit guidance:

1. **Reconnaissance:** four fresh model calls map the product, principals and trust boundaries, source surfaces and sinks, and safe local checks. Kavach also builds source hashes and a coverage plan.
2. **Coverage-led hunting:** assigned source excerpts are reviewed by fresh stateless prompts. Coverage critics can add or reassign units. Quick runs one hunting wave; Standard and Deep may repeat waves until a distinct final-clean critic accepts the ledger.
3. **Candidate validation:** a fresh role rereads each candidate and attempts to refute its trace. Optional Docker probes can supply bounded local observations. Source-only candidates remain `needs_validation` unless the required evidence contract is satisfied.
4. **Structured output:** findings and coverage state are validated against the vendored findings and coverage-ledger contracts. Invalid records remain unresolved or are removed from the final finding set.
5. **Independent verification:** Standard and Deep use a separate fresh role for retained records. Quick combines the Phase 3 candidate check and Phase 5 final-record check in one fresh verifier, as implemented by the runner.
6. **Target-neutral reporting:** a report-writing prompt receives only validated records and coverage facts. The parent creates the final Markdown and structured artifacts deterministically.

All phases have explicit status values. If a phase, validator, provider, or budget reservation fails, the run is marked incomplete and the reason is retained in the result.

## 4. Profiles and model-call budgets

Profiles control the workflow review strategy. They do not represent vulnerability categories and do not independently enable OSV or Docker checks.

| Profile | Default model-call cap | Behavior |
|---|---:|---|
| `quick` | 48 | One hunting wave and one final critic; combines candidate validation with final-record verification. |
| `standard` | 128 | Repeats coverage waves as needed and uses separate Phase 3 and Phase 5 verification. |
| `deep` | 256 | Uses Standard behavior and schedules a second pass for compatible prior coverage before accepting reused units. |

An explicit `--budget` or web request budget must be an integer from 12 through 512. The number 12 is the minimum accepted value, not the default. If no explicit budget is supplied, the selected profile default is used. The web UI and headless CLI default to `standard`; the composite GitHub Action defaults to `quick`.

## 5. Source collection and deterministic checks

Local folders are collected without following symlinks and with file-count, per-file, total-byte, and path controls. Public Git scans accept HTTPS repositories from GitHub, GitLab, or Bitbucket, create a shallow partial clone, inspect tree metadata, and read eligible files within the same limits. Private or authenticated Git URLs are not accepted by the collector.

The deterministic source scanner emits `needs_validation` leads for patterns such as dynamic evaluation, shell command construction, shell mode, SQL concatenation, HTML injection sinks, unsafe deserialization/YAML loading, disabled TLS verification, caller-controlled URLs, request-derived filesystem paths, weak hashes, and credential-like values. These are source-pattern leads; surrounding data flow and trust boundaries must be reviewed before treating them as issues.

Incremental scans compute a static JavaScript/TypeScript import closure for `--diff <base>...<head>`. Unchanged coverage can be reused only when source hashes and the profile, provider, model, budget, workflow revision, and engine revision match. Configuration changes, lockfile or dependency changes, deleted paths, unresolved or dynamic imports, unsupported changed languages, and large impact sets fail closed to a full re-audit.

## 6. Dependency vulnerability detection

`server.mjs` parses exact versions from supported npm, Bun, Composer, Pipenv, Cargo, Go, requirements, Poetry/uv, Ruby, pnpm, Yarn, Gradle, NuGet, and Maven files. It does not invent versions from ranges or unresolved workspace/file/git specifications.

When `--osv` or the web OSV option is enabled, Kavach sends only package names, ecosystems, and exact versions to the OSV batch API. Queries are batched in groups of up to 100. Returned advisory details are fetched separately, aliases are used to display CVE identifiers where available, and the original OSV advisory ID is retained. CVE strings merely mentioned in source files are reported separately and are not treated as dependency matches.

Severity is an OSV-derived broad label. Advisory labels are preferred; otherwise numeric scores are mapped to LOW, MEDIUM, HIGH, or CRITICAL by thresholds in `severityOf`. Kavach does not calculate CVSS vectors, assign CWE categories, perform exploitability analysis, or guarantee complete transitive resolution for every ecosystem.

## 7. Model providers

Supported providers are:

| Provider | Transport | Requirement |
|---|---|---|
| `ollama` | `http://127.0.0.1:11434/api/chat` | Ollama must already be running locally. |
| `mlx` | `http://127.0.0.1:8080/v1/chat/completions` | An MLX-compatible OpenAI-style local server must already be running. |
| `apple-fm` | `http://127.0.0.1:11437/v1/chat/completions` | The compatible local Foundation Models service must already be running. |
| `codex` | `codex exec` | Codex CLI must be installed and signed in. Prompts use an ephemeral read-only CLI workspace with MCP disabled. |
| `gemini-cli` | `gemini` | Gemini CLI must be installed and signed in. Kavach requests deletion of the temporary CLI session after each call. |

Only selected source excerpts and structured context are sent to the selected model. Kavach does not manage provider API keys. Local model endpoints are restricted to direct loopback addresses.

## 8. Docker sandbox

Docker execution is optional. Kavach requires a local Unix-socket Docker daemon and an already-installed image. The default image is `node:22-alpine`; `AUDIT_DOCKER_IMAGE` can select another local image reference. Kavach uses `--pull=never`, inspects the image's local content ID, and uses that ID for the run.

Existing Node tests and candidate probes use separate limits:

| Control | Existing tests | Candidate probes |
|---|---:|---:|
| Network | Disabled | Disabled |
| Source | Read-only staged tree | Read-only staged tree |
| Root filesystem | Read-only | Read-only |
| Writable scratch | 64 MB `tmpfs` | 16 MB `tmpfs` |
| Memory | 512 MB | 256 MB |
| CPUs | 1 | 1 |
| Processes | 64 PIDs | 32 PIDs |
| Wall time | 25 seconds per test | 12 seconds per probe |

Capabilities are dropped, `no-new-privileges` is enabled, the container runs as a non-root UID, and the environment is an explicit small allowlist. Kavach does not mount the original project directory, pass the Docker socket, install packages, run builds, run arbitrary project scripts, or run Git hooks. Probe output is bounded, redacted, and promoted by the parent only after the container exits. A passing test or probe does not establish that the project is safe.

## 9. Authentication, Firestore, and PostgreSQL

The web interface uses Firebase email/password Authentication. New accounts must verify their email. Browser session data is held in `sessionStorage`; the server verifies the Firebase ID token and rejects unverified accounts. The local API also checks loopback host/origin rules and requires the authenticated user's token for review, history, cancellation, deletion, and triage operations.

Firestore stores only one preferences document at `fieldnoteProfiles/{uid}`. Rules require an email-verified owner, restrict reads and writes to that document, and allow only the provider, model base, model, local-model flag, OSV flag, and Docker-test flag. Source files, reports, findings, and Git addresses are not written to Firestore.

PostgreSQL is local-only. `database.mjs` creates `fieldnote_scan_runs` on startup and adds the `full_result` column if needed; there is no separate migration framework. Rows are keyed by Firebase UID, and saved reports, findings, coverage, audit artifacts, and the full result are scoped to that UID. Source file contents are not stored as a separate source archive.

The CLI bypasses Firebase. Its PostgreSQL history option uses the fixed local identity `kavach-cli-local` and is available only for local folder scans.

## 10. CLI usage

The CLI entry point is:

```sh
node kavach-cli.mjs scan <path-or-public-https-url> [options]
```

Examples:

```sh
# Deterministic local scan with SARIF output
node kavach-cli.mjs scan . --sarif .kavach/kavach.sarif.json --fail-on confirmed

# Model-assisted scan with optional Docker probes and OSV
node kavach-cli.mjs scan . --profile standard --provider ollama --model qwen3:8b \
  --osv --docker-probes --output-dir .kavach/output

# Public Git checkout at a branch or tag
node kavach-cli.mjs scan https://github.com/owner/repository --ref main --format json

# Incremental local scan using a prior JSON baseline
node kavach-cli.mjs scan . --provider ollama --model qwen3:8b \
  --baseline .kavach/baseline.json --diff origin/main...HEAD \
  --save-baseline .kavach/baseline.json
```

Important options include `--profile quick|standard|deep`, `--budget 12..512`, `--provider`, `--model`, `--model-base`, `--docker-tests`, `--docker-probes`, `--osv`, `--scope`, `--diff`, `--baseline`, `--postgres-cache`, `--save-baseline`, `--sarif`, `--phase-snapshots`, `--output-dir`, `--format text|json|sarif`, `--confirmed-only`, `--fail-on confirmed|high|critical|never`, and `--require-complete`.

Exit code `0` means the configured threshold was not reached. Exit code `1` means it was reached. Exit code `2` represents invalid input or a runtime error. Exit code `3` is returned only when `--require-complete` is set and the six-phase workflow is incomplete. Exact OSV affected-version matches satisfy the `confirmed` threshold; deterministic source leads do not.

## 11. GitHub Actions

`action.yml` is a composite action. It installs the repository runtime with `npm ci --ignore-scripts`, runs the CLI, writes SARIF, and exposes the policy exit code as an action output. The included workflow runs Quick profile with OSV enabled, retains SARIF for 14 days, uploads SARIF only when repository Code Scanning is available for the event, and applies the returned policy exit code.

The action supports local folders inside the checked-out workspace. GitHub-hosted runners cannot reach a developer's loopback model service. Model-assisted CI therefore requires an explicitly configured reachable provider or a self-hosted runner; the included workflow does not provide one.

## 12. Report outputs

The web UI downloads Markdown and SARIF, offers browser print/save-to-PDF, and creates a client-side ZIP of model-assisted audit artifacts. The CLI `--output-dir` writes `result.json`, `REPORT.md`, `results.sarif.json`, and any workflow artifacts. The workflow artifact set is:

- `run-metadata.json`
- `architecture.md`
- `coverage-ledger.json`
- `findings.json`
- `REPORT.md`
- `FINDINGS-DETAIL.md`
- `NEEDS-VALIDATION.md`
- candidate-check files when Docker probes were enabled

SARIF is version 2.1.0. Confirmed structured findings are errors, OSV matches are errors only for `HIGH` or `CRITICAL` severity, deterministic source leads are warnings, and structured `needs_validation` records are notes. `--confirmed-only` excludes unverified source and structured records.

## 13. Installation and configuration

```sh
cp .env.example .env
docker compose up -d postgres
npm install
docker pull node:22-alpine  # only if Docker checks are needed
npm start
```

Open `http://localhost:4173`. Set Firebase web configuration and local PostgreSQL values in `.env`. For a headless scan, `npm install` is sufficient; Firebase and PostgreSQL are not required unless the selected CLI options use them.

## 14. Project structure

```text
.
├── server.mjs                         Web server, source intake, OSV, and orchestration
├── kavach-cli.mjs                     Headless CLI and policy exit codes
├── cloudflare-skill-runner.mjs        Six-phase workflow and audit artifacts
├── audit-workflow.mjs                 Workflow export
├── docker-sandbox.mjs                 Docker test and probe containment
├── database.mjs                       PostgreSQL persistence
├── firebase-auth.mjs                  Firebase Admin token verification
├── public/                            Browser interface and SARIF writer
├── benchmarks/                        Paired fixtures and pilot results
├── tests/                             Node test suite
├── vendor/cloudflare-security-audit-skill/
│                                      Vendored schemas, guidance, and validators
├── action.yml                         Composite GitHub Action
├── .github/workflows/                 Code Scanning workflow
├── compose.yaml                       PostgreSQL 16 service
├── firestore.rules                    Per-user preference rules
└── .env.example                       Local environment template
```

## 15. Known limitations and planned scope

- Source review is static and evidence-led. It does not inspect a running deployment, prove reachability, execute arbitrary project code, or guarantee exploitability.
- Only selected existing Node tests and candidate-specific probes can run in Docker; other language runtimes, builds, installs, and live services are outside the sandbox.
- The dependency path uses exact versions available in supported files. It does not calculate CVSS vectors, assign CWE categories, or guarantee full transitive dependency resolution for every ecosystem.
- Browser PDF output is a print/save operation rather than a server-generated PDF artifact.
- The benchmark corpus is a small pilot and does not establish broad ecosystem coverage or a production detection rate.
- Git intake is limited to public HTTPS repositories on GitHub, GitLab, and Bitbucket.
- No separate database migration framework or account recovery service is implemented beyond Firebase's email reset request.

## 16. Validation commands

```sh
npm test
node kavach-cli.mjs --help
node benchmarks/run.mjs --deterministic-only --out benchmarks/results/deterministic-baseline.json
```

The repository currently defines `start`, `scan`, `benchmark`, and `test` npm scripts. It does not define a separate lint or build script.
