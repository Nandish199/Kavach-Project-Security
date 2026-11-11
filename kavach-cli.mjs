#!/usr/bin/env node
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanProject } from "./server.mjs";
import { buildSarif } from "./public/sarif.mjs";

const CLI_VERSION = "1.0.0";
const MAX_BASELINE_BYTES = 40 * 1024 * 1024;

function usage() {
  return `Kavach source security review\n\nUsage:\n  node kavach-cli.mjs scan <path-or-public-https-url> [options]\n\nOptions:\n  --ref <branch-or-tag>       Git branch or tag for a public HTTPS repository\n  --profile <quick|standard|deep>\n  --budget <12..512>          Maximum model calls for the selected review\n  --provider <ollama|mlx|apple-fm|codex|gemini-cli>\n  --model <name>              Model ID (required with --provider)\n  --model-base <url>           Loopback model server URL for Ollama, MLX, or Apple FM\n  --docker-tests              Run selected existing Node.js tests in Docker\n  --docker-probes             Enable candidate-specific Docker probes\n  --osv                       Query exact dependency versions against OSV\n  --scope <path[,path...]>    Limit the review to the selected source paths\n  --diff <base...head>        Re-review changed paths and their import closure\n  --baseline <file>           Prior Kavach result JSON used for hash-based reuse\n  --postgres-cache            Reuse and save local-folder coverage in local PostgreSQL\n  --save-baseline <file>      Save this result for a later incremental run\n  --sarif <file>              Write SARIF 2.1.0 output\n  --confirmed-only            Exclude unconfirmed source leads from SARIF\n  --phase-snapshots <file>    Write Hunt, Refutation, and Verification snapshots\n  --output-dir <directory>    Write result, report, SARIF, and audit artifacts\n  --format <text|json|sarif>  Select standard-output format (default: text)\n  --fail-on <confirmed|high|critical|never>\n  --require-complete          Exit 3 if the six-phase review is incomplete\n  --version                   Print the CLI version\n  --help                      Show this help\n\nExit codes: 0 no configured threshold was reached; 1 threshold reached;\n2 invalid input or runtime error; 3 --require-complete was set and the\nsix-phase review did not complete. Deterministic leads do not satisfy\n--fail-on confirmed. Exact affected dependency matches from OSV do.\n`;
}

function parseArgs(argv) {
  if (argv.includes("--help") || argv.includes("-h")) return { help: true };
  if (argv.includes("--version")) return { version: true };
  const command = argv[0];
  if (command !== "scan") throw new Error("Expected the `scan` command.");
  const target = argv[1];
  if (!target || target.startsWith("--")) throw new Error("Provide a project folder or public HTTPS Git repository URL.");
  const options = { command, target, format: "text", failOn: "never", confirmedOnly: false };
  const valued = new Map([
    ["--ref", "ref"], ["--profile", "profile"], ["--budget", "budget"], ["--provider", "provider"],
    ["--model", "model"], ["--model-base", "modelBase"], ["--scope", "scope"], ["--diff", "diff"],
    ["--baseline", "baseline"], ["--save-baseline", "saveBaseline"], ["--sarif", "sarif"],
    ["--phase-snapshots", "phaseSnapshots"], ["--output-dir", "outputDir"], ["--format", "format"], ["--fail-on", "failOn"]
  ]);
  const flags = new Map([
    ["--docker-tests", "dockerTests"], ["--docker-probes", "dockerProbes"], ["--osv", "osv"],
    ["--confirmed-only", "confirmedOnly"], ["--require-complete", "requireComplete"], ["--postgres-cache", "postgresCache"]
  ]);
  for (let index = 2; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flags.has(flag)) { options[flags.get(flag)] = true; continue; }
    const key = valued.get(flag);
    if (!key) throw new Error(`Unknown option: ${flag}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`Option ${flag} requires a value.`);
    options[key] = value;
    index += 1;
  }
  if (options.profile && !["quick", "standard", "deep"].includes(options.profile)) throw new Error("Choose a quick, standard, or deep profile.");
  if (options.budget !== undefined && (!/^\d+$/.test(options.budget) || Number(options.budget) < 12 || Number(options.budget) > 512)) throw new Error("The model-call budget must be a whole number from 12 to 512.");
  if (options.failOn && !["confirmed", "high", "critical", "never"].includes(options.failOn)) throw new Error("Choose confirmed, high, critical, or never for --fail-on.");
  if (options.format && !["text", "json", "sarif"].includes(options.format)) throw new Error("Choose text, json, or sarif for --format.");
  if (options.provider && !["ollama", "mlx", "apple-fm", "codex", "gemini-cli"].includes(options.provider)) throw new Error("Choose ollama, mlx, apple-fm, codex, or gemini-cli for --provider.");
  if (options.provider && !options.model) throw new Error("--model is required when --provider is selected.");
  return options;
}

function gitNameOnly(cwd, range) {
  const parts = String(range || "").split("...");
  const validRef = value => value.length > 0 && value.length <= 200 && /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value) && !value.includes("..") && !value.includes("//");
  if (parts.length !== 2 || !validRef(parts[0]) || !validRef(parts[1])) throw new Error("Use --diff <base>...<head> with valid Git branch names or commit IDs.");
  return new Promise((resolve, reject) => {
    const child = spawn("git", ["diff", "--name-only", "-z", `${parts[0]}...${parts[1]}`], { cwd, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stdout = Buffer.alloc(0);
    let stderr = "";
    const timer = setTimeout(() => { child.kill("SIGTERM"); reject(new Error("Git diff exceeded its 30-second limit.")); }, 30000);
    child.stdout.on("data", chunk => {
      if (stdout.length + chunk.length > 4 * 1024 * 1024) { child.kill("SIGTERM"); reject(new Error("Git diff returned too many changed paths.")); return; }
      stdout = Buffer.concat([stdout, chunk]);
    });
    child.stderr.on("data", chunk => { if (stderr.length < 4000) stderr += chunk.toString("utf8").slice(0, 4000 - stderr.length); });
    child.on("error", error => { clearTimeout(timer); reject(error); });
    child.on("close", code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(stderr.trim() || "Git could not compare the requested revisions."));
      resolve({ base: parts[0], head: parts[1], paths: stdout.toString("utf8").split("\0").filter(Boolean) });
    });
  });
}

async function readBaseline(filename) {
  const content = await fs.readFile(path.resolve(filename));
  if (content.length > MAX_BASELINE_BYTES) throw new Error("Baseline file exceeds the 40 MB limit.");
  let result;
  try { result = JSON.parse(content.toString("utf8")); }
  catch { throw new Error("Baseline file must contain valid Kavach result JSON."); }
  if (result?.result && typeof result.result === "object") result = result.result;
  if (!result?.source?.identity || !result?.audit?.metadata?.source_hashes || !Array.isArray(result?.audit?.coverage_ledger)) {
    throw new Error("Baseline JSON is missing source identity or a validated coverage ledger.");
  }
  return [{ id: result.id || result.audit.metadata.run_id || "local-baseline", full_result: result }];
}

async function writeAtomic(filename, content) {
  const target = path.resolve(filename);
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temporary = `${target}.tmp-${process.pid}-${Date.now()}`;
  await fs.writeFile(temporary, content, { mode: 0o600, flag: "wx" });
  await fs.rename(temporary, target);
}

function severityName(finding) {
  const value = finding?.severity?.overall_severity || finding?.severity || "";
  return String(value).toLowerCase();
}

function thresholdReached(result, threshold) {
  if (threshold === "never") return false;
  const confirmed = (result.audit?.findings || []).filter(item => item.verdict === "confirmed");
  const dependencies = result.cveFindings || [];
  if (threshold === "confirmed") return confirmed.length > 0 || dependencies.length > 0;
  const minRank = threshold === "critical" ? 4 : 3;
  const rank = value => ({ low: 1, moderate: 2, medium: 2, high: 3, critical: 4 }[String(value || "").toLowerCase()] || 0);
  return confirmed.some(item => rank(severityName(item)) >= minRank) || dependencies.some(item => rank(item.severity) >= minRank);
}

async function writeOutputDirectory(directory, result, sarif) {
  const root = path.resolve(directory);
  await fs.mkdir(root, { recursive: true });
  const artifacts = result.audit?.artifacts || {};
  const files = new Map([
    ["result.json", JSON.stringify(result, null, 2)],
    ["REPORT.md", result.report || ""],
    ["results.sarif.json", JSON.stringify(sarif, null, 2)]
  ]);
  for (const [name, content] of Object.entries(artifacts)) {
    if (typeof content !== "string" || name.startsWith("/") || name.split(/[\\/]/).includes("..")) continue;
    files.set(name, content);
  }
  for (const [name, content] of files) {
    const target = path.resolve(root, name);
    if (target !== root && !target.startsWith(root + path.sep)) throw new Error("An audit artifact path escaped the output directory.");
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, content, { mode: 0o600 });
  }
  return root;
}

async function run(options) {
  let priorRuns = [];
  let postgresHistory = null;
  if (options.postgresCache) {
    if (/^https:\/\//i.test(options.target)) throw new Error("--postgres-cache currently supports local folder scans only.");
    if (options.baseline) throw new Error("Choose either --baseline or --postgres-cache for prior coverage.");
    const { initializePostgres, listPriorScanRuns, postgresConfigured, saveScanRun } = await import("./database.mjs");
    if (!postgresConfigured()) throw new Error("--postgres-cache requires DATABASE_URL for PostgreSQL on localhost.");
    const initialized = await initializePostgres();
    if (initialized.state !== "connected") throw new Error(initialized.message || "Local PostgreSQL is unavailable.");
    const projectRoot = path.resolve(options.target);
    const source = { kind: "folder", label: path.basename(projectRoot), identity: `local:${projectRoot}` };
    const userUid = "kavach-cli-local";
    priorRuns = await listPriorScanRuns(userUid, source);
    postgresHistory = { userUid, saveScanRun };
  }
  if (options.baseline) priorRuns = await readBaseline(options.baseline);
  let gitDiff = null;
  if (options.diff) {
    if (/^https:\/\//i.test(options.target)) throw new Error("--diff currently requires a local Git checkout.");
    if (!options.baseline && !options.postgresCache) throw new Error("--diff requires --baseline or --postgres-cache so unchanged coverage can be checked against source hashes.");
    gitDiff = await gitNameOnly(path.resolve(options.target), options.diff);
  }
  const snapshots = [];
  let lastStage = "";
  const result = await scanProject({
    target: options.target,
    ref: options.ref,
    profile: options.profile || "standard",
    budget: options.budget === undefined ? undefined : Number(options.budget),
    provider: options.provider || "",
    model: options.model || "",
    modelBase: options.modelBase || "",
    dockerTests: options.dockerTests === true,
    dockerProbes: options.dockerProbes === true,
    osv: options.osv === true,
    scope: options.scope || "",
    diff: options.diff || "",
    diffScope: gitDiff ? { base: gitDiff.base, head: gitDiff.head, changed_paths: gitDiff.paths } : null,
    diffPaths: gitDiff?.paths,
    priorRuns,
    onProgress: progress => {
      if (progress.stage !== lastStage) {
        lastStage = progress.stage;
        process.stderr.write(`[${progress.stage}] ${progress.message}\n`);
      }
    },
    onPhaseSnapshot: snapshot => snapshots.push(snapshot)
  });
  if (postgresHistory) {
    await postgresHistory.saveScanRun(postgresHistory.userUid, result);
    result.history = { state: "saved", message: "Local PostgreSQL coverage history updated." };
  }
  const sarif = buildSarif(result, { includeUnverified: !options.confirmedOnly, category: "kavach" });
  if (options.sarif) await writeAtomic(options.sarif, JSON.stringify(sarif, null, 2) + "\n");
  if (options.phaseSnapshots) await writeAtomic(options.phaseSnapshots, JSON.stringify({ run_id: result.id, snapshots }, null, 2) + "\n");
  if (options.outputDir) await writeOutputDirectory(options.outputDir, result, sarif);
  if (options.saveBaseline) await writeAtomic(options.saveBaseline, JSON.stringify(result, null, 2) + "\n");

  if (options.format === "json") process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  else if (options.format === "sarif") process.stdout.write(JSON.stringify(sarif, null, 2) + "\n");
  else {
    const confirmed = (result.audit?.findings || []).filter(item => item.verdict === "confirmed").length;
    const leads = (result.sourceFindings || []).length + (result.audit?.findings || []).filter(item => item.verdict === "needs_validation").length;
    process.stdout.write(`Kavach scan ${result.id}\n`);
    process.stdout.write(`Source: ${result.source?.label || options.target}\n`);
    process.stdout.write(`Files: ${result.coverage?.filesRead ?? 0}; confirmed: ${confirmed}; leads: ${leads}; OSV advisories: ${result.cveFindings?.length ?? 0}\n`);
    process.stdout.write(`Six-phase review: ${result.modelReview?.state || "unavailable"}\n`);
    if (result.modelReview?.message) process.stdout.write(`Review status: ${result.modelReview.message}\n`);
    if (gitDiff) {
      const reused = (result.audit?.coverage_ledger || []).filter(unit => unit.prior_status === "prior_covered_same_source" && unit.status === "covered").length;
      const strategy = result.audit?.metadata?.diff_scope;
      process.stdout.write(`Diff: ${gitDiff.paths.length} changed path(s) in ${gitDiff.base}...${gitDiff.head}; ${reused} unchanged coverage unit(s) reused.\n`);
      if (strategy?.fallback_reason) process.stdout.write(`Diff fallback: ${strategy.fallback_reason}\n`);
    }
    if (options.sarif) process.stdout.write(`SARIF: ${path.resolve(options.sarif)}\n`);
    if (options.outputDir) process.stdout.write(`Artifacts: ${path.resolve(options.outputDir)}\n`);
    if (options.saveBaseline) process.stdout.write(`Baseline: ${path.resolve(options.saveBaseline)}\n`);
    if (result.audit?.run_status !== "complete") process.stdout.write("This run is incomplete; inspect the report before treating it as a clean review.\n");
  }
  if (thresholdReached(result, options.failOn)) process.exitCode = 1;
  else if (options.requireComplete && result.audit?.run_status !== "complete") process.exitCode = 3;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === path.resolve(fileURLToPath(import.meta.url))) {
  try {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) process.stdout.write(usage());
    else if (options.version) process.stdout.write(`Kavach ${CLI_VERSION}\n`);
    else await run(options);
  } catch (error) {
    process.stderr.write(`Kavach: ${String(error?.message || error).slice(0, 1000)}\n`);
    if (!process.argv.includes("--help")) process.stderr.write("Run `node kavach-cli.mjs --help` for usage.\n");
    process.exitCode = 2;
  }
}
