import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("CLI writes SARIF without a web server and distinguishes incomplete reviews", async () => {
  const temp = await mkdtemp(path.join(os.tmpdir(), "kavach-cli-process-"));
  const project = path.join(temp, "project");
  const sarifPath = path.join(temp, "result.sarif.json");
  try {
    await mkdir(project);
    await writeFile(path.join(project, "app.js"), "export function run(input) { return eval(input); }\n");
    const first = spawnSync(process.execPath, [path.join(root, "kavach-cli.mjs"), "scan", project, "--sarif", sarifPath, "--fail-on", "confirmed"], { cwd: root, encoding: "utf8", timeout: 20000 });
    assert.equal(first.status, 0, first.stderr);
    const sarif = JSON.parse(await readFile(sarifPath, "utf8"));
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].results.length, 1);
    const incomplete = spawnSync(process.execPath, [path.join(root, "kavach-cli.mjs"), "scan", project, "--require-complete"], { cwd: root, encoding: "utf8", timeout: 20000 });
    assert.equal(incomplete.status, 3);
    assert.match(incomplete.stdout, /review: incomplete/i);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
