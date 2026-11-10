import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { computeDiffScope } from "../server.mjs";

function git(root, ...args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

test("diff scope includes changed modules and their import closure", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "kavach-diff-test-"));
  try {
    await mkdir(path.join(root, "src"));
    await writeFile(path.join(root, "src", "handler.js"), 'import { load } from "./service.js";\nexport const handler = input => load(input);\n');
    await writeFile(path.join(root, "src", "service.js"), "export const load = value => value;\n");
    await writeFile(path.join(root, "src", "unrelated.js"), "export const stable = true;\n");
    git(root, "init");
    git(root, "config", "user.name", "Kavach Test");
    git(root, "config", "user.email", "kavach-test@example.invalid");
    git(root, "config", "commit.gpgsign", "false");
    git(root, "add", ".");
    git(root, "commit", "-m", "baseline");
    const base = git(root, "rev-parse", "HEAD");
    await writeFile(path.join(root, "src", "service.js"), "export const load = value => String(value).trim();\n");
    git(root, "add", ".");
    git(root, "commit", "-m", "change service");
    const head = git(root, "rev-parse", "HEAD");
    const files = [
      { path: "src/handler.js", content: 'import { load } from "./service.js";\nexport const handler = input => load(input);\n' },
      { path: "src/service.js", content: "export const load = value => String(value).trim();\n" },
      { path: "src/unrelated.js", content: "export const stable = true;\n" }
    ];
    const scope = await computeDiffScope(root, `${base}...${head}`, files);
    assert.deepEqual(scope.changed_paths, ["src/service.js"]);
    assert.deepEqual(scope.impacted_paths, ["src/handler.js", "src/service.js"]);
    assert.equal(scope.strategy, "changed_paths_and_import_closure");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
