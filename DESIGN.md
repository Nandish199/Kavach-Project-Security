# Kavach design direction

## Reference and capture

The visual reference is Hallmark’s Cobalt theme page: <https://www.usehallmark.com/themes/cobalt/>. It is a developer product example called Relay, not an existing Kavach screen. The page was inspected on 2026-11-03 with a 1280 × 900 viewport and a 1280 × 4945 full-page capture. Its long layout pairs pale surfaces and sparse spacing with crisp blue accents, small code-like labels, hard borders, and a few dark panels. No reference image is bundled because the capture is temporary; the theme page above is the durable source.

The Hallmark repository describes its design approach as building each page around the visitor’s actual task, preserving working content and controls during a redesign, and checking craft details instead of repeating default interface patterns: <https://github.com/Nutlope/hallmark>. Kavach adapts those principles to a project review workspace with a clear source choice, visible privacy boundary, evidence-led findings, and a report path.

The audit flow is adapted from Cloudflare’s six-phase security-audit-skill: <https://github.com/cloudflare/security-audit-skill>. Kavach runs reconnaissance, coverage-led hunting, candidate validation, structured record checks, independent final-record review, and report generation. Reviewer roles are separate stateless prompts sent to the same selected model provider; this is not the skill package’s delegated-agent runtime. Kavach provides a bounded local Docker sandbox for selected existing Node tests and candidate-specific probes, but it does not execute arbitrary project builds, installs, scripts, hooks, live services, or other language runtimes.

## Extracted from the Hallmark Cobalt reference

Firecrawl’s branding extraction reported these reference values:

- Primary blue: `#0462D3`
- Deep blue: `#003D98`
- Dark ink: `#111825`
- Pale surface: `#F8FBFE`
- Body text: `#363E49`
- Heading font: Familjen Grotesk
- Body font: IBM Plex Sans
- Monospace font: JetBrains Mono
- Base spacing unit: 12 px
- Input radius: approximately 6–8 px, with asymmetry on some controls

The screenshot visually confirms a light canvas, blue controls, compact technical labels, wide margins, firm outlines, and alternating pale and ink sections. The exact tokens above are extracted branding values; some component dimensions and spacing in this document are visual estimates.

## Kavach application system

Hallmark's Cobalt palette is retained, with an application-first composition rather than the marketing-page layout. The user arrives at the source picker. Three destinations fit in a compact top navigation; report data uses rows and separators, and a single dark notice calls out the limits of a source review. The available copy and all functional controls remain in the app.

| Role | Token | Value | Use |
|---|---|---|---|
| Canvas | `--canvas` | `#F3F6FA` | Workspace background |
| Paper | `--paper` | `#F8FBFE` | Active navigation and light surfaces |
| Surface | `--surface` | `#FBFDFF` | Inputs and primary work area |
| Ink | `--ink` | `#111825` | Headings and key text |
| Body | `--text` | `#363E49` | Reading copy |
| Primary blue | `--blue` | `#0462D3` | Primary action and current state |
| Deep blue | `--blue-deep` | `#003D98` | Links, focus and selected navigation |
| Rule | `--rule` | `#D6DCE4` | Tables, section dividers and inputs |
| Focus | `--focus` | `#72ADFF` | Keyboard focus ring |
| Local status | `--lime` | `#D5FF52` | Kavach brand mark |

Typography uses the existing local system sans stack for interface text and system monospace for paths, identifiers and source metadata. No hosted fonts are loaded. The app uses a fixed 12–30 px type scale, 4/8/12/16/24/32 px spacing steps, 4–7 px control corners, and 40 px controls with a 44 px interaction target.

## Screens and flow

- **Sign in:** one compact Firebase form, with a clear note about PostgreSQL report storage and Firestore preferences.
- **New review:** a top navigation, connection status, source tabs, local engine options, audit profile, CVE lookup and Docker test switches.
- **Progress:** the six Cloudflare phases, current phase and a live progress message.
- **Report:** source and revision, exports, existing summary figures, CVE matches, deterministic source leads, structured audit candidates, coverage details and validation limits.
- **Reports:** saved review rows and the existing empty and load-error states.
- **Audit method:** all six phases and the product's known adaptation limits.

The source form remains the primary object. Reports favor evidence and source paths over charts. The workflow distinguishes OSV-backed dependency matches, deterministic source-pattern leads, and independently reviewed needs-validation records. The bounded workflow marks uncovered units and unfinished validation as incomplete. Markdown download, print-to-PDF and the ZIP bundle remain available.

## Assets and limits

No photographs or external imagery are used. The Kavach mark remains a small CSS drawing. The reference's web fonts are not bundled, so the implementation retains the project's local system fonts. The app does not inspect a running deployment, execute target code, or validate reachability at runtime; those remain owner-led checks.

## Hallmark redesign record

- Depth: full redesign of the existing app screens.
- Kept: Kavach identity, Cobalt blue and ink, route destinations, source and account flows, every existing scan control, the six-phase record, privacy copy, findings, data and exports.
- Changed: the left rail became top navigation; oversized editorial openings became compact task headings; report cards became evidence rows; labels now use sentence case; findings keep their severity and validation state as text.
- Theme files and reference copy are documented above; this system governs the application UI in `public/index.html`, `public/app.js` and `public/styles.css`.

## Hallmark Cobalt refresh

The November 2026 refresh keeps the extracted Cobalt blue and ink palette, then adds a quiet layered page canvas, generous white work surfaces, softer 8–16 px corners, and restrained elevation to distinguish the scan setup, report sections, and saved reviews. Sign-in uses a paired dark editorial panel with CSS-drawn orbit lines. Navigation, scan progress, findings, report summaries, and the audit-method page share the same blue selection states and rounded evidence surfaces. Mobile layouts collapse the sign-in pair and report columns without removing controls. `public/hallmark-refresh.css` contains these application-side choices; the Hallmark theme screenshot remains the source for the underlying palette and type guidance.

## Hallmark workspace polish

The November 6, 2026 polish narrows the surface system to a more consistent 7–12 px control and panel radius, moves the interface font fallback to the operating-system UI face, and adds a compact, real review path to the sign-in panel so the dark surface explains the product instead of serving as empty decoration. Source controls receive a clearer top accent, selected states and keyboard focus receive more contrast, and the report, method, progress and saved-review surfaces keep their existing content and structure.
