#!/usr/bin/env node
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { fingerprint } from "../cloudflare-skill-runner.mjs";
import { scanProject } from "../server.mjs";
import { benchmarkPairs, benchmarkSamples } from "./fixtures.mjs";

function parse(argv) {
  const options = { runs: 1, profile: "quick", dockerProbes: false, deterministicOnly: false, recompute: "" };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "--docker-probes") { options.dockerProbes = true; continue; }
    if (flag === "--deterministic-only") { options.deterministicOnly = true; continue; }
    const values = new Map([
      ["--provider", "provider"], ["--model", "model"], ["--model-base", "modelBase"],
      ["--profile", "profile"], ["--budget", "budget"], ["--runs", "runs"],
      ["--out", "out"], ["--recompute", "recompute"]
    ]);
    const key = values.get(flag);
    if (!key || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error(`Unknown or incomplete option: ${flag}`);
    options[key] = argv[index + 1];
    index += 1;
  }
  if (!options.deterministicOnly && !options.recompute) {
    if (!options.provider || !options.model) throw new Error("A model provider and model are required to run the benchmark (or pass --deterministic-only).");
    if (!["ollama", "mlx", "codex", "gemini-cli"].includes(options.provider)) throw new Error("Choose ollama, mlx, codex, or gemini-cli.");
  }
  if (!["quick", "standard", "deep"].includes(options.profile)) throw new Error("Choose quick, standard, or deep.");
  options.runs = Number(options.runs);
  options.budget = options.budget === undefined ? undefined : Number(options.budget);
  if (!Number.isInteger(options.runs) || options.runs < 1 || options.runs > 10) throw new Error("Choose 1 to 10 repeated runs.");
  if (options.budget !== undefined && (!Number.isInteger(options.budget) || options.budget < 12 || options.budget > 512)) throw new Error("Budget must be a whole number from 12 to 512.");
  return options;
}

export function recordPaths(record) {
  const traceFiles = (record?.trace || []).map(item => item?.file).filter(Boolean);
  if (traceFiles.length) return [...new Set(traceFiles)];
  return [...new Set((record?.evidence || []).map(item => item?.file).filter(Boolean))];
}

export function recordLinesFor(record, targetPath) {
  const traceLines = (record?.trace || [])
    .filter(item => item?.file === targetPath)
    .map(item => Number(item.line))
    .filter(Number.isSafeInteger);
  const evidenceLines = (record?.evidence || [])
    .filter(item => item?.file === targetPath)
    .map(item => Number(item.line))
    .filter(Number.isSafeInteger);
  return traceLines.length ? [...new Set([...traceLines, ...evidenceLines])] : evidenceLines;
}

export function deduplicateRecordsByTrace(records) {
  if (!Array.isArray(records)) return [];
  const byFp = new Map();
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const fp = Array.isArray(record.trace) && record.trace.length
      ? fingerprint(record.claimed_root_cause || record.root_cause || "", "", record.trace)
      : record.fingerprint || `REC-${byFp.size}`;
    if (!byFp.has(fp)) byFp.set(fp, { ...record, fingerprint: fp });
  }
  return [...byFp.values()];
}

export function sourceFindingsToStage(sourceFindings) {
  const records = (Array.isArray(sourceFindings) ? sourceFindings : []).map((item, idx) => ({
    verdict: "needs_validation",
    fingerprint: `STATIC-${idx + 1}-${item.rule || "lead"}`,
    title: item.title || item.rule || "Static lead",
    trace: [{ kind: "sink", file: item.path, line: Number(item.line) || 1, scope: item.rule || "static", description: item.why || "" }],
    evidence: [{ file: item.path, line: Number(item.line) || 1, description: item.evidence || item.title || "" }]
  }));
  return { phase: "deterministic_baseline", records };
}

export function evaluate(stage, samples) {
  if (!stage) return { available: false, candidates: null, true_positives: null, false_positives: null, false_negatives: null, true_negatives: null, precision: null, recall: null, f1: null, by_category: {} };
  const rawRecords = (stage?.records || []).filter(record => record.verdict !== "rejected");
  const records = stage.phase === "deterministic_baseline" ? rawRecords : deduplicateRecordsByTrace(rawRecords);
  const bySample = samples.map(sample => {
    const linked = records.filter(record => recordPaths(record).includes(sample.path));
    const detected = linked.some(record => recordLinesFor(record, sample.path).some(value => Math.abs(value - sample.sink_line) <= 2));
    const anyLead = linked.length > 0;
    return { ...sample, detected, anyLead };
  });
  const vulnerable = bySample.filter(sample => sample.expected);
  const patched = bySample.filter(sample => !sample.expected);
  const truePositives = vulnerable.filter(sample => sample.detected).length;
  const falseNegatives = vulnerable.length - truePositives;
  const falsePositives = patched.filter(sample => sample.anyLead).length + vulnerable.filter(sample => sample.anyLead && !sample.detected).length;
  const trueNegatives = patched.length - patched.filter(sample => sample.anyLead).length;
  const precision = truePositives + falsePositives ? truePositives / (truePositives + falsePositives) : 0;
  const recall = vulnerable.length ? truePositives / vulnerable.length : 0;
  const f1 = precision + recall ? 2 * precision * recall / (precision + recall) : 0;
  const categories = [...new Set(samples.map(sample => sample.category))].sort();
  const byCategory = Object.fromEntries(categories.map(category => {
    const members = bySample.filter(sample => sample.category === category);
    const positives = members.filter(sample => sample.expected);
    const negatives = members.filter(sample => !sample.expected);
    const tp = positives.filter(sample => sample.detected).length;
    const fp = negatives.filter(sample => sample.anyLead).length + positives.filter(sample => sample.anyLead && !sample.detected).length;
    const p = tp + fp ? tp / (tp + fp) : 0;
    const r = positives.length ? tp / positives.length : 0;
    return [category, { true_positives: tp, false_positives: fp, false_negatives: positives.length - tp, precision: p, recall: r, f1: p + r ? 2 * p * r / (p + r) : 0 }];
  }));
  return { available: true, candidates: records.length, true_positives: truePositives, false_positives: falsePositives, false_negatives: falseNegatives, true_negatives: trueNegatives, precision, recall, f1, by_category: byCategory };
}

function summarizeRun(run, samples) {
  const staticStage = run.staticStage || sourceFindingsToStage(run.result?.sourceFindings || []);
  const phases = {
    deterministic_baseline: evaluate(staticStage, samples),
    ...Object.fromEntries(["hunt", "refutation", "independent_verification"].map(name => {
      const snapshot = run.snapshots.find(item => item.phase === name);
      return [name, evaluate(snapshot, samples)];
    }))
  };
  const huntFp = phases.hunt.false_positives;
  const staticFp = phases.deterministic_baseline.false_positives;
  const finalFp = phases.independent_verification.false_positives;
  const huntReduction = Number.isFinite(huntFp) && huntFp > 0 && Number.isFinite(finalFp) ? (huntFp - finalFp) / huntFp : null;
  const baselineReduction = Number.isFinite(staticFp) && staticFp > 0 && Number.isFinite(finalFp) ? (staticFp - finalFp) / staticFp : null;
  return {
    run_id: run.result?.id || run.run_id,
    run_status: run.result?.audit?.run_status || run.run_status || "unavailable",
    model_review: run.result?.modelReview?.state || run.model_review || "unavailable",
    phase_statuses: run.result?.audit?.phases
      ? run.result.audit.phases.map(phase => ({ phase: phase.phase || phase.name || phase.id, status: phase.status }))
      : (run.phase_statuses || []),
    duration_ms: run.durationMs ?? run.duration_ms ?? 0,
    phases,
    hunt_to_final_false_positive_reduction: huntReduction,
    baseline_to_final_false_positive_reduction: baselineReduction,
    snapshots: run.snapshots.map(snap => ({
      ...snap,
      records: deduplicateRecordsByTrace(snap.records || [])
    }))
  };
}

function mean(values) {
  const present = values.filter(Number.isFinite);
  return present.length ? present.reduce((sum, value) => sum + value, 0) / present.length : null;
}

function markdownReport(output) {
  const lines = [
    "# Kavach paired-fixture benchmark", "",
    `- Corpus: ${output.corpus.pairs} vulnerable/patched pairs (${output.corpus.samples} files)`,
    `- Provider/model: ${output.configuration.provider || "deterministic-only"} / ${output.configuration.model || "static-rules"}`,
    `- Profile/budget: ${output.configuration.profile} / ${output.configuration.budget ?? "profile default"}`,
    `- Repeated runs: ${output.runs.length}`, "",
    "This is a pilot corpus. A retained lead is counted against its expected vulnerable sink; any lead on a patched fixture counts as a false positive. Refuted records are excluded after Refutation. Review the fixture labels and raw snapshots before making a public claim.", "",
    "| Stage | Candidates | Precision | Recall | F1 | False positives | False negatives |",
    "|---|---:|---:|---:|---:|---:|---:|"
  ];
  const stageRows = [
    ["Deterministic regex baseline (Phase 0)", "deterministic_baseline"],
    ["Hunt (Phase 2)", "hunt"],
    ["Refutation (Phase 3)", "refutation"],
    ["Independent verification (Phase 5)", "independent_verification"]
  ];
  for (const [label, key] of stageRows) {
    const metrics = output.aggregate[key];
    if (!metrics) continue;
    lines.push(`| ${label} | ${Number.isFinite(metrics.candidates) ? metrics.candidates : "n/a"} | ${metrics.precision === null ? "n/a" : (metrics.precision * 100).toFixed(1) + "%"} | ${metrics.recall === null ? "n/a" : (metrics.recall * 100).toFixed(1) + "%"} | ${metrics.f1 === null ? "n/a" : metrics.f1.toFixed(3)} | ${Number.isFinite(metrics.false_positives) ? metrics.false_positives : "n/a"} | ${Number.isFinite(metrics.false_negatives) ? metrics.false_negatives : "n/a"} |`);
  }
  const reduction = output.aggregate.hunt_to_final_false_positive_reduction;
  const baselineReduction = output.aggregate.baseline_to_final_false_positive_reduction;
  lines.push(
    "",
    `Mean deterministic-to-Phase-5 false-positive reduction: ${baselineReduction === null || baselineReduction === undefined ? "n/a" : (baselineReduction * 100).toFixed(1) + "%"}.`,
    `Mean Hunt-to-Phase-5 false-positive reduction: ${reduction === null ? "n/a (0 Hunt false positives after trace attribution)" : (reduction * 100).toFixed(1) + "%"}.`,
    "",
    "## Limits",
    "",
    "The corpus contains 25 small JavaScript/TypeScript-style pairs across five classes. It does not represent all frameworks or production systems. Model/provider, run status, phase snapshots, and per-class scores are included in the JSON output. Candidate probes are Node.js-only; use `--docker-probes` only when Docker and the pinned image are already available.",
    ""
  );
  return lines.join("\n");
}

function buildAggregate(runs) {
  const aggregate = Object.fromEntries(["deterministic_baseline", "hunt", "refutation", "independent_verification"].map(stage => {
    const values = runs.map(run => run.phases[stage]).filter(Boolean);
    return [stage, {
      candidates: mean(values.map(value => value.candidates)),
      precision: mean(values.map(value => value.precision)),
      recall: mean(values.map(value => value.recall)),
      f1: mean(values.map(value => value.f1)),
      false_positives: mean(values.map(value => value.false_positives)),
      false_negatives: mean(values.map(value => value.false_negatives)),
      per_run: values
    }];
  }));
  aggregate.hunt_to_final_false_positive_reduction = mean(runs.map(run => run.hunt_to_final_false_positive_reduction));
  aggregate.baseline_to_final_false_positive_reduction = mean(runs.map(run => run.baseline_to_final_false_positive_reduction));
  return aggregate;
}

async function main() {
  const options = parse(process.argv.slice(2));
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "kavach-benchmark-"));
  try {
    for (const sample of benchmarkSamples) {
      const target = path.join(root, ...sample.path.split("/"));
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, sample.source, { mode: 0o600, flag: "wx" });
    }
    const staticScanResult = await scanProject({ target: root, profile: "quick" });
    const staticStage = sourceFindingsToStage(staticScanResult.sourceFindings);

    if (options.recompute) {
      const existingPath = path.resolve(options.recompute);
      const existing = JSON.parse(await fs.readFile(existingPath, "utf8"));
      const runs = (existing.runs || []).map(run => summarizeRun({ ...run, staticStage }, benchmarkSamples));
      const output = {
        ...existing,
        aggregate: buildAggregate(runs),
        runs
      };
      const outPath = options.out ? path.resolve(options.out) : existingPath;
      await fs.writeFile(outPath, JSON.stringify(output, null, 2) + "\n", { mode: 0o600 });
      await fs.writeFile(outPath.replace(/\.json$/i, "") + ".md", markdownReport(output), { mode: 0o600 });
      process.stdout.write(`Benchmark recomputed: ${outPath}\n`);
      return;
    }

    const runs = [];
    for (let index = 0; index < options.runs; index += 1) {
      const snapshots = [];
      const started = Date.now();
      const result = options.deterministicOnly
        ? staticScanResult
        : await scanProject({
            target: root,
            label: `Kavach benchmark run ${index + 1}`,
            profile: options.profile,
            budget: options.budget,
            provider: options.provider,
            model: options.model,
            modelBase: options.modelBase,
            dockerProbes: options.dockerProbes,
            onPhaseSnapshot: snapshot => snapshots.push(snapshot),
            onProgress: progress => {
              if (["audit-hunt", "audit-candidate-validation", "audit-record-verification"].includes(progress.stage)) {
                process.stderr.write(`[${index + 1}/${options.runs}] ${progress.message}\n`);
              }
            }
          });
      runs.push(summarizeRun({ result, snapshots, staticStage, durationMs: Date.now() - started }, benchmarkSamples));
    }
    const aggregate = buildAggregate(runs);
    const output = {
      schema_version: "1.0",
      corpus: { name: "kavach-paired-source-v1", pairs: benchmarkPairs.length, samples: benchmarkSamples.length, categories: [...new Set(benchmarkSamples.map(sample => sample.category))].sort() },
      configuration: { provider: options.provider || null, model: options.model || null, profile: options.profile, budget: options.budget ?? null, docker_probes: options.dockerProbes },
      aggregate,
      runs
    };
    const json = JSON.stringify(output, null, 2) + "\n";
    if (options.out) {
      const target = path.resolve(options.out);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, json, { mode: 0o600 });
      await fs.writeFile(target.replace(/\.json$/i, "") + ".md", markdownReport(output), { mode: 0o600 });
      process.stdout.write(`Benchmark results: ${target}\n`);
    } else process.stdout.write(markdownReport(output) + "\n");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  try { await main(); }
  catch (error) {
    process.stderr.write(`Benchmark failed: ${String(error?.message || error).slice(0, 1200)}\n`);
    process.exitCode = 2;
  }
}
