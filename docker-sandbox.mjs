import { spawn } from "node:child_process";
import { accessSync, constants as fsConstants, promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const DEFAULT_IMAGE = "node:22-alpine";
const MAX_TEST_FILES = 8;
const MAX_TEST_SECONDS = 25;
const MAX_OUTPUT_BYTES = 96 * 1024;
const MAX_PROBE_BYTES = 16 * 1024;
const MAX_PROBE_SECONDS = 12;
const DEFAULT_STAGE_BYTES = 92 * 1024 * 1024;
const imageRefPattern = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,240}$/;

function dockerEnvironment() {
  const candidates = [
    "/Applications/Docker.app/Contents/Resources/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    ...(process.env.PATH || "/usr/bin:/bin").split(":"),
    "/usr/bin",
    "/bin"
  ];
  const seen = new Set();
  const valid = [];
  for (const dir of candidates) {
    if (!dir || seen.has(dir)) continue;
    try {
      accessSync(dir, fsConstants.R_OK | fsConstants.X_OK);
      seen.add(dir);
      valid.push(dir);
    } catch {}
  }
  return {
    PATH: valid.length ? valid.join(":") : "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
    HOME: process.env.HOME || os.homedir(),
    USER: process.env.USER || "",
    TMPDIR: process.env.TMPDIR || os.tmpdir()
  };
}

function redactOutput(value) {
  return String(value || "")
    .replace(/(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----)/gi, "[private key redacted]")
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[cloud key redacted]")
    .replace(/\b(?:ghp|github_pat|glpat|xox[baprs])[-_][A-Za-z0-9_-]{16,}\b/g, "[token redacted]")
    .replace(/\b(?:sk|rk)-[A-Za-z0-9_-]{20,}\b/g, "[token redacted]")
    .replace(/(\b[\w-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[\w-]*\s*[:=]\s*)(?:["'][^"']*["']|[^,\s;]+)/ig, "$1[redacted]");
}

function dockerImage() {
  const image = String(process.env.AUDIT_DOCKER_IMAGE || DEFAULT_IMAGE).trim();
  if (!imageRefPattern.test(image) || image.startsWith("-") || image.includes("..")) throw new Error("AUDIT_DOCKER_IMAGE is not a valid Docker image reference.");
  return image;
}

function runDocker(args, { timeoutMs = 10000, maxOutput = 5000, containerName = "" } = {}) {
  return new Promise(resolve => {
    const child = spawn("docker", args, { env: dockerEnvironment(), stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let stdout = "";
    let stderr = "";
    let closed = false;
    let timedOut = false;
    let outputTruncated = false;
    const append = (current, chunk) => {
      if (current.length >= maxOutput) { outputTruncated = true; return current; }
      const value = chunk.toString("utf8");
      if (current.length + value.length > maxOutput) outputTruncated = true;
      return current + value.slice(0, maxOutput - current.length);
    };
    child.stdout.on("data", chunk => { stdout = append(stdout, chunk); });
    child.stderr.on("data", chunk => { stderr = append(stderr, chunk); });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      if (containerName) {
        const stopper = spawn("docker", ["stop", "--time", "1", containerName], { env: dockerEnvironment(), stdio: "ignore", windowsHide: true });
        const stopTimer = setTimeout(() => stopper.kill("SIGKILL"), 3000);
        stopper.on("close", () => clearTimeout(stopTimer));
        stopper.on("error", () => clearTimeout(stopTimer));
      }
      const killTimer = setTimeout(() => child.kill("SIGKILL"), 4000);
      killTimer.unref?.();
    }, timeoutMs);
    const finish = (code, error = "") => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr: stderr || error, timedOut, outputTruncated });
    };
    child.on("error", error => finish(null, error.message));
    child.on("close", code => finish(code));
  });
}

export async function dockerSandboxStatus() {
  try {
    const image = dockerImage();
    const endpoint = await runDocker(["context", "inspect", "--format", "{{(index .Endpoints \"docker\").Host}}"], { timeoutMs: 4000, maxOutput: 1000 });
    if (/EPERM|ENOENT/i.test(endpoint.stderr || "")) {
      return { state: "offline", image, message: "Docker CLI is not accessible in this process environment. Run npm start in Terminal to enable Docker checks." };
    }
    const daemonEndpoint = endpoint.stdout.trim();
    if (endpoint.code !== 0 || !daemonEndpoint.startsWith("unix:///")) {
      return { state: "misconfigured", image, message: "Docker is not using a local Unix socket. Kavach will not send project files to a remote Docker host." };
    }
    const daemon = await runDocker(["info", "--format", "{{.ServerVersion}}"], { timeoutMs: 4000, maxOutput: 1000 });
    if (daemon.code !== 0) return { state: "offline", image, message: "Docker Engine is not running. No target code will be executed." };
    const inspected = await runDocker(["image", "inspect", "--format", "{{.Id}}", image], { timeoutMs: 5000, maxOutput: 1000 });
    if (inspected.code !== 0 || !/^sha256:[a-f0-9]{64}\s*$/i.test(inspected.stdout)) {
      return { state: "image-missing", image, message: `Docker is running, but the local ${image} image is not available. Kavach will not pull images.` };
    }
    return { state: "ready", image, imageId: inspected.stdout.trim(), message: "Docker sandbox is ready. The image is pinned by its local content ID; no image pull is allowed." };
  } catch (error) {
    return { state: "misconfigured", image: process.env.AUDIT_DOCKER_IMAGE || DEFAULT_IMAGE, message: error.message.slice(0, 240) };
  }
}

function normalizedProjectPath(value) {
  if (typeof value !== "string" || !value || value.length > 1000 || value.includes("\0")) return null;
  const rel = value.replaceAll("\\", "/").replace(/^\.\//, "");
  if (rel.startsWith("/") || /^[A-Za-z]:/.test(rel) || rel.split("/").some(part => !part || part === "." || part === "..")) return null;
  return rel;
}

function isSensitive(rel) {
  return /(?:^|\/)(?:\.env(?:\.|$)|.*(?:secret|credential).*)|\.(?:pem|key|p12|pfx)$/i.test(rel);
}

function testFilesFrom(files) {
  return files.map(file => ({ path: normalizedProjectPath(file.path), content: file.content }))
    .filter(file => file.path && !isSensitive(file.path) && /\.(?:test|spec)\.(?:js|mjs|cjs)$/i.test(file.path))
    .sort((a, b) => a.path.localeCompare(b.path));
}

async function stageProject(root, files, maxBytes = DEFAULT_STAGE_BYTES) {
  let totalBytes = 0;
  const stagedPaths = [];
  for (const file of files) {
    const rel = normalizedProjectPath(file.path);
    if (!rel || isSensitive(rel) || typeof file.content !== "string") continue;
    const fileBytes = Buffer.byteLength(file.content, "utf8");
    if (totalBytes + fileBytes > maxBytes) throw new Error("Docker staging was stopped to keep all temporary review files under the 100 MB workspace limit.");
    const destination = path.join(root, ...rel.split("/"));
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o755 });
    await fs.writeFile(destination, file.content, { encoding: "utf8", mode: 0o444, flag: "wx" });
    totalBytes += fileBytes;
    stagedPaths.push(rel);
  }
  return { bytes: totalBytes, paths: stagedPaths.sort() };
}

export async function runDockerNodeTests(files, progress = () => {}, pinnedStatus = null, stageBytesLimit = DEFAULT_STAGE_BYTES) {
  const candidates = testFilesFrom(files);
  if (!candidates.length) return { state: "not-run", reason: "No existing JavaScript test files matched the supported Node test format." };
  const status = pinnedStatus?.state === "ready" ? pinnedStatus : await dockerSandboxStatus();
  if (status.state !== "ready") return { state: "blocked", reason: status.message, image: status.image, discovered_tests: candidates.length };
  const selected = candidates.slice(0, MAX_TEST_FILES);
  const omitted = Math.max(0, candidates.length - selected.length);
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "fieldnote-docker-scratch-"));
  const targetRoot = path.join(hostRoot, "target");
  await fs.mkdir(targetRoot, { mode: 0o755 });
  const checks = [];
  try {
    const staging = await stageProject(targetRoot, files, stageBytesLimit);
    await fs.chmod(targetRoot, 0o555);
    for (const [index, test] of selected.entries()) {
      progress(index + 1, selected.length, test.path);
      const containerName = "fieldnote-scan-" + crypto.randomUUID().replaceAll("-", "").slice(0, 20);
      const args = [
        "run", "--rm", "--pull=never", "--name", containerName,
        "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--memory=512m", "--memory-swap=512m", "--cpus=1", "--pids-limit=64",
        "--ulimit", "nofile=128:128", "--ulimit", "fsize=10485760:10485760", "--user=65532:65532",
        "--stop-timeout=1", "--mount", `type=bind,src=${targetRoot},dst=/target,readonly`,
        "--workdir=/target", "--tmpfs", "/scratch:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--entrypoint", "/usr/bin/env", status.imageId,
        "-i", "HOME=/scratch", "TMPDIR=/scratch", "NODE_ENV=test", "PATH=/usr/local/bin:/usr/bin:/bin",
        "node", "--test", "/target/" + test.path
      ];
      const result = await runDocker(args, { timeoutMs: MAX_TEST_SECONDS * 1000, maxOutput: MAX_OUTPUT_BYTES, containerName });
      const output = redactOutput((result.stdout + (result.stderr ? "\n" + result.stderr : "")).trim());
      checks.push({
        path: test.path,
        state: result.timedOut ? "timed-out" : result.code === 0 ? "passed" : "failed",
        exit_code: result.code,
        output: output.slice(0, MAX_OUTPUT_BYTES),
        sandbox_limits: { network: "none", environment: "empty allowlist: HOME, TMPDIR, NODE_ENV, PATH", source: "read-only", staged_source_bytes: staging.bytes, root_filesystem: "read-only", writable_scratch: "64MB noexec tmpfs", memory_mb: 512, cpu: 1, pids: 64, file_size_mb: 10, wall_seconds: MAX_TEST_SECONDS }
      });
    }
    return {
      state: omitted ? "incomplete" : checks.every(item => item.state === "passed") ? "complete" : "completed-with-failures",
      image: status.image,
      image_id: status.imageId,
      discovered_tests: candidates.length,
      executed_tests: checks.length,
      omitted_tests: omitted,
      checks
    };
  } finally {
    await fs.chmod(targetRoot, 0o700).catch(() => {});
    await fs.rm(hostRoot, { recursive: true, force: true }).catch(() => {});
  }
}

export async function runDockerCandidateProbe(files, probe, pinnedStatus = null, progress = () => {}, stageBytesLimit = DEFAULT_STAGE_BYTES) {
  const script = typeof probe?.script === "string" ? probe.script : "";
  const scriptBytes = Buffer.byteLength(script, "utf8");
  if (!script.trim() || scriptBytes > MAX_PROBE_BYTES || script.includes("\0")) {
    return { state: "blocked", reason: `The candidate probe must be valid Node.js source under ${MAX_PROBE_BYTES / 1024} KB.` };
  }
  const status = pinnedStatus?.state === "ready" ? pinnedStatus : await dockerSandboxStatus();
  if (status.state !== "ready") return { state: "blocked", reason: status.message, image: status.image };
  const hostRoot = await fs.mkdtemp(path.join(os.tmpdir(), "fieldnote-candidate-scratch-"));
  const targetRoot = path.join(hostRoot, "target");
  await fs.mkdir(targetRoot, { mode: 0o755 });
  try {
    const paths = new Set(Array.isArray(probe.source_paths) ? probe.source_paths.map(normalizedProjectPath).filter(Boolean) : []);
    const scopedFiles = paths.size ? files.filter(file => paths.has(normalizedProjectPath(file.path))) : [];
    if (!scopedFiles.length) return { state: "blocked", reason: "No valid candidate source files were available to stage read-only." };
    const staging = await stageProject(targetRoot, scopedFiles, stageBytesLimit);
    await fs.chmod(targetRoot, 0o555);
    progress();
    const containerName = "fieldnote-probe-" + crypto.randomUUID().replaceAll("-", "").slice(0, 20);
    const wrapper = 'import { writeFile } from "node:fs/promises"; await writeFile("/scratch/probe.mjs", process.argv[1], { flag: "wx", mode: 0o400 }); await import("file:///scratch/probe.mjs");';
    const args = [
      "run", "--rm", "--pull=never", "--name", containerName,
      "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
      "--memory=256m", "--memory-swap=256m", "--cpus=1", "--pids-limit=32",
      "--ulimit", "nofile=96:96", "--ulimit", "fsize=10485760:10485760", "--ulimit", "core=0:0", "--user=65532:65532",
      "--stop-timeout=1", "--mount", `type=bind,src=${targetRoot},dst=/target,readonly`,
      "--workdir=/target", "--tmpfs", "/scratch:rw,noexec,nosuid,nodev,size=16m,mode=1777",
      "--entrypoint", "/usr/bin/env", status.imageId,
      "-i", "HOME=/scratch", "TMPDIR=/scratch", "NODE_ENV=production", "PATH=/usr/local/bin:/usr/bin:/bin",
      "node", "--no-addons", "--input-type=module", "-e", wrapper, script
    ];
    const result = await runDocker(args, { timeoutMs: MAX_PROBE_SECONDS * 1000, maxOutput: MAX_OUTPUT_BYTES, containerName });
    const output = redactOutput((result.stdout + (result.stderr ? "\n" + result.stderr : "")).trim());
    return {
      state: result.timedOut ? "timed-out" : "executed",
      exit_code: result.code,
      output: output.slice(0, MAX_OUTPUT_BYTES),
      output_truncated: result.outputTruncated,
      sandbox_limits: {
        network: "none", environment: "empty allowlist: HOME, TMPDIR, NODE_ENV, PATH",
        source: "read-only", root_filesystem: "read-only", writable_scratch: "16MB noexec tmpfs",
        memory_mb: 256, cpu: 1, pids: 32, file_size_mb: 10, wall_seconds: MAX_PROBE_SECONDS,
        local_image_id: status.imageId, staged_source_bytes: staging.bytes, staged_source_paths: staging.paths
      }
    };
  } finally {
    await fs.chmod(targetRoot, 0o700).catch(() => {});
    await fs.rm(hostRoot, { recursive: true, force: true }).catch(() => {});
  }
}
