import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scanProject } from "../server.mjs";
import { buildSarif } from "../public/sarif.mjs";

test("headless scan reads a local folder without Firebase or PostgreSQL", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "kavach-cli-test-"));
  try {
    await mkdir(path.join(root, "src"));
    await writeFile(path.join(root, "src", "app.js"), "export function run(input) { return eval(input); }\n");
    const result = await scanProject({ target: root, profile: "quick" });
    assert.equal(result.coverage.filesRead, 1);
    assert.equal(result.sourceFindings.some(item => item.rule === "dynamic-eval"), true);
    assert.equal(result.history.state, "not-saved");
    assert.equal(result.modelReview.state, "incomplete");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("SARIF writer uses stable rules, source-relative locations, and can omit unverified leads", () => {
  const result = {
    sourceFindings: [{ rule: "dynamic-eval", title: "Dynamic code evaluation", path: "src/app.js", line: 7, evidence: "eval(input)" }],
    audit: { findings: [
      { fingerprint: "SRC-abc123", verdict: "confirmed", title: "Confirmed issue", trace: [{ file: "src/app.js", line: 9 }] },
      { fingerprint: "SRC-def456", verdict: "needs_validation", title: "Unverified lead", trace: [{ file: "src/other.js", line: 2 }] }
    ] }
  };
  const all = buildSarif(result);
  assert.equal(all.version, "2.1.0");
  assert.equal(all.runs[0].automationDetails.id, "kavach");
  assert.equal(all.runs[0].results.length, 3);
  assert.equal(all.runs[0].results[1].partialFingerprints["kavach/v1"], "SRC-abc123");
  assert.equal(all.runs[0].results[1].locations[0].physicalLocation.artifactLocation.uri, "src/app.js");
  const confirmedOnly = buildSarif(result, { includeUnverified: false });
  assert.equal(confirmedOnly.runs[0].results.length, 1);
  assert.equal(confirmedOnly.runs[0].results[0].level, "error");
});
