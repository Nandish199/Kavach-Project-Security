import test from "node:test";
import assert from "node:assert/strict";
import { benchmarkPairs, benchmarkSamples } from "../benchmarks/fixtures.mjs";
import { evaluate, recordLinesFor, recordPaths } from "../benchmarks/run.mjs";
import { fingerprint, interleaveHunterQueue, runCloudflareWorkflow, sanitizeReconTaskResult } from "../cloudflare-skill-runner.mjs";

test("benchmark corpus contains 25 paired vulnerable and patched fixtures", () => {
  assert.equal(benchmarkPairs.length, 25);
  assert.equal(benchmarkSamples.length, 50);
  assert.equal(new Set(benchmarkSamples.map(item => item.path)).size, 50);
  assert.deepEqual([...new Set(benchmarkSamples.map(item => item.category))].sort(), [
    "command-injection", "path-traversal", "prototype-pollution", "sql-injection", "ssrf"
  ]);
  for (const pair of benchmarkPairs) {
    assert.equal(pair.samples.length, 2);
    assert.deepEqual(pair.samples.map(item => item.expected), [true, false]);
    for (const sample of pair.samples) {
      assert.ok(sample.source.includes("\n"));
      assert.ok(sample.sink_line > 0);
      assert.ok(sample.path.endsWith(".js"));
    }
  }
});

test("benchmark evaluator does not count sibling patched control evidence as a false positive", () => {
  const record = {
    verdict: "needs_validation",
    fingerprint: "SRC-116fa993714560b9303eff7e",
    trace: [
      { kind: "entrypoint", file: "command-injection/cmd-01/vulnerable.js", line: 2 },
      { kind: "sink", file: "command-injection/cmd-01/vulnerable.js", line: 3 }
    ],
    evidence: [
      { file: "command-injection/cmd-01/vulnerable.js", line: 3, description: "exec receives concatenated input" },
      { file: "command-injection/cmd-01/patched.js", line: 3, description: "sibling control uses spawn with shell:false" }
    ]
  };
  assert.deepEqual(recordPaths(record), ["command-injection/cmd-01/vulnerable.js"]);
  assert.deepEqual(recordLinesFor(record, "command-injection/cmd-01/vulnerable.js"), [2, 3]);
  const cmd01Samples = benchmarkSamples.filter(sample => sample.pair_id === "cmd-01");
  const score = evaluate({ records: [record] }, cmd01Samples);
  assert.equal(score.true_positives, 1);
  assert.equal(score.false_positives, 0);
  assert.equal(score.precision, 1);
  assert.equal(score.recall, 1);
});

test("canonical trace fingerprint deduplicates identical entrypoint-to-sink traces across attack classes", () => {
  const trace = [
    { kind: "entrypoint", file: "command-injection/cmd-01/vulnerable.js", line: 2 },
    { kind: "sink", file: "command-injection/cmd-01/vulnerable.js", line: 3 }
  ];
  const fpA = fingerprint("Caller-controlled file value enters shell command text", "Injection", trace);
  const fpB = fingerprint("Request filename is concatenated into exec command string", "Broken Access Control", trace);
  assert.equal(fpA, fpB);
});

test("hunter queue interleaves distinct starting_paths before repeating secondary attack classes on the same file", () => {
  const units = [
    { coverage_id: "u1", prior_status: "none", starting_paths: ["a.js"], attack_class: "Class 1", ordinary_attack_class_block: "b1" },
    { coverage_id: "u2", prior_status: "none", starting_paths: ["a.js"], attack_class: "Class 2", ordinary_attack_class_block: "b2" },
    { coverage_id: "u3", prior_status: "none", starting_paths: ["b.js"], attack_class: "Class 1", ordinary_attack_class_block: "b1" },
    { coverage_id: "u4", prior_status: "none", starting_paths: ["c.js"], attack_class: "Class 1", ordinary_attack_class_block: "b1" }
  ];
  const ordered = interleaveHunterQueue(units);
  assert.deepEqual(ordered.slice(0, 3).map(u => u.starting_paths[0]), ["a.js", "b.js", "c.js"]);
  assert.equal(ordered[3].starting_paths[0], "a.js");
});

test("recon sanitizer strips out-of-inventory paths while retaining valid entries", () => {
  const fileMap = new Map([["src/app.js", { path: "src/app.js", content: "line1\nline2\nline3\n" }]]);
  const product = sanitizeReconTaskResult("product", {
    product: "Demo",
    subsystems: [
      { name: "app", paths: ["src/app.js", "src/missing.js"] },
      { name: "ghost", paths: ["src/missing.js"] }
    ],
    source_paths: [
      { file: "src/app.js", line: 2, role: "entry" },
      { file: "src/missing.js", line: 1, role: "missing" }
    ],
    build_commands: []
  }, fileMap, true);
  assert.equal(product.subsystems.length, 1);
  assert.deepEqual(product.subsystems[0].paths, ["src/app.js"]);
  assert.equal(product.source_paths.length, 1);
});

test("six-phase workflow seeds uncovered files, interleaves hunters, and deduplicates identical sink traces", async () => {
  const files = [
    { path: "src/exec.js", content: "import { exec } from \"node:child_process\";\nexport function runCmd(req) {\n  return exec(\"ls \" + req.query.dir);\n}\n" },
    { path: "src/safe.js", content: "export const ping = () => \"pong\";\n" }
  ];
  const snapshots = [];
  let execHunterCount = 0;
  const wf = await runCloudflareWorkflow({
    files,
    source: { kind: "folder", label: "e2e-target", identity: "folder:e2e" },
    provider: "ollama",
    model: "qwen2.5-coder:7b",
    profile: "quick",
    budget: 24,
    onPhaseSnapshot: snap => snapshots.push(snap),
    askModel: async (prompt) => {
      if (prompt.includes("PHASE 1 — PRODUCT")) {
        return JSON.stringify({
          product: "E2E demo service",
          principals: ["caller"],
          stack: ["Node.js"],
          subsystems: [{ name: "src", paths: ["src/exec.js", "src/safe.js"] }],
          source_paths: [{ file: "src/exec.js", line: 2, role: "command runner" }],
          build_commands: [],
          comparable: "CLI helper",
          toolchain_gaps: []
        });
      }
      if (prompt.includes("PHASE 1 — BOUNDARIES")) {
        return JSON.stringify({
          principals: ["caller"],
          trust_boundaries: [{ id: "b1", file: "src/exec.js", line: 2, label: "runCmd", control: "none", principal: "caller", subsystem: "src" }],
          deployment_unknowns: []
        });
      }
      if (prompt.includes("PHASE 1 — SURFACES")) {
        return JSON.stringify({
          entry_surfaces: [{ id: "s1", file: "src/exec.js", line: 2, label: "runCmd", principal: "caller", subsystem: "src" }],
          sinks: [{ file: "src/exec.js", line: 3, label: "exec", subsystem: "src" }],
          lifecycle_modes: [],
          parallel_paths: [],
          selected_companion_files: []
        });
      }
      if (prompt.includes("PHASE 1 — EXECUTION")) {
        return JSON.stringify({
          offline_checks: [],
          prohibited_commands: [],
          deployment_modes: ["node"],
          sandbox_controls: {
            no_external_network: true,
            empty_allowlisted_env: true,
            read_only_source_tools: true,
            scratch_only_writes: true,
            resource_limits: true,
            safe_artifact_promotion: true
          },
          missing_sandbox_controls: [],
          positive_source_patterns: []
        });
      }
      if (prompt.includes("PHASE 2 — COVERAGE-LED HUNTING")) {
        const unitJson = prompt.split("Coverage unit:\n")[1].split("\n\nArchitecture map:")[0];
        const unit = JSON.parse(unitJson);
        const isSafe = unit.starting_paths.includes("src/safe.js");
        if (!isSafe) execHunterCount += 1;
        return JSON.stringify({
          units: [{
            coverage_id: unit.coverage_id,
            disposition: isSafe ? "covered" : "candidate",
            reviewed_paths: [isSafe ? "src/safe.js" : "src/exec.js"],
            checks: [{
              agent_id: unit.agent_id,
              reviewed_paths: [isSafe ? "src/safe.js" : "src/exec.js"],
              invariant: "Command arguments must not be concatenated into shell strings",
              method: "source",
              result: isSafe ? "Constant return value" : "req.query.dir is concatenated into exec()",
              artifact: null
            }],
            candidate_fingerprints: [],
            unresolved: []
          }],
          candidates: isSafe ? [] : [{
            coverage_id: unit.coverage_id,
            proposed_verdict: "needs_validation",
            fingerprint: "SRC-000000000000000000000000",
            title: "Command injection in runCmd",
            description: "req.query.dir is concatenated directly into exec()",
            claimed_root_cause: `Unvalidated query parameter concatenated into child_process.exec (variant ${execHunterCount})`,
            trace: [
              { kind: "entrypoint", file: "src/exec.js", line: 2, scope: "runCmd(req)", description: "Caller supplies req.query.dir" },
              { kind: "sink", file: "src/exec.js", line: 3, scope: "exec", description: "Concatenated string passed to exec" }
            ],
            evidence: [
              { file: "src/exec.js", line: 3, description: "return exec(\"ls \" + req.query.dir);" }
            ],
            blockers: ["Source-only role did not execute target code"],
            validation_plan: { local: "Run in isolated sandbox with dummy marker", deployment: null }
          }],
          hardening: [],
          uncovered: []
        });
      }
      if (prompt.includes("COVERAGE CRITIC")) {
        return JSON.stringify({
          missing_units: [],
          reassign_ids: [],
          resolved_prior_leads: [],
          stop: true,
          reason: "All units covered"
        });
      }
      if (prompt.includes("PHASE 3 — CANDIDATE VALIDATION")) {
        const recJson = prompt.split("Candidate record:\n")[1].split("\n\nLinked ledger units")[0];
        const rec = JSON.parse(recJson);
        return JSON.stringify({
          decision: "needs_validation",
          final_verification: "verified",
          record: {
            ...rec,
            verdict: "needs_validation"
          }
        });
      }
      if (prompt.includes("PHASE 6 — TARGET-NEUTRAL REPORT SUMMARY")) {
        return JSON.stringify({
          posture_summary: "One command-injection candidate requires sandbox validation.",
          coverage_summary: "Reviewed both src/exec.js and src/safe.js.",
          limitations: ["Quick profile pass."],
          positive_patterns: ["src/safe.js returns a constant value without shell execution."]
        });
      }
      return "{}";
    }
  });

  assert.ok(execHunterCount > 1);
  assert.equal(snapshots.length, 3);
  assert.equal(snapshots[0].phase, "hunt");
  assert.equal(snapshots[0].records.length, 1);
  assert.equal(wf.findings.length, 1);
  assert.ok(wf.coverage_ledger.some(u => u.starting_paths.includes("src/safe.js")));
});
