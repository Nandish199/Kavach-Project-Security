function lineFor(source, needle) {
  const index = source.split(/\r?\n/).findIndex(line => line.includes(needle));
  if (index < 0) throw new Error(`Benchmark sink marker was not found: ${needle}`);
  return index + 1;
}

function pair(id, category, vulnerable, patched, vulnerableNeedle, patchedNeedle) {
  return {
    id,
    category,
    samples: [
      { path: `${category}/${id}/vulnerable.js`, expected: true, source: vulnerable, sink_line: lineFor(vulnerable, vulnerableNeedle) },
      { path: `${category}/${id}/patched.js`, expected: false, source: patched, sink_line: lineFor(patched, patchedNeedle) }
    ]
  };
}

export const benchmarkPairs = [
  pair("sql-01", "sql-injection",
    `export async function lookup(req, db) {\n  return db.query("SELECT * FROM users WHERE id = " + req.query.id);\n}\n`,
    `export async function lookup(req, db) {\n  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);\n}\n`, "db.query(", "db.query("),
  pair("sql-02", "sql-injection",
    `export async function findAccount(request, database) {\n  return database.execute("SELECT id FROM account WHERE email = '" + request.body.email + "'");\n}\n`,
    `export async function findAccount(request, database) {\n  return database.execute("SELECT id FROM account WHERE email = ?", [request.body.email]);\n}\n`, "database.execute(", "database.execute("),
  pair("sql-03", "sql-injection",
    `export async function bySlug(ctx, pool) {\n  const sql = "SELECT * FROM pages WHERE slug = '" + ctx.params.slug + "'";\n  return pool.query(sql);\n}\n`,
    `export async function bySlug(ctx, pool) {\n  return pool.query("SELECT * FROM pages WHERE slug = ?", [ctx.params.slug]);\n}\n`, "pool.query(sql)", "pool.query("),
  pair("sql-04", "sql-injection",
    `export async function revoke(req, client) {\n  const token = req.headers.token;\n  return client.query("DELETE FROM sessions WHERE token = '" + token + "'");\n}\n`,
    `export async function revoke(req, client) {\n  const token = req.headers.token;\n  return client.query("DELETE FROM sessions WHERE token = ?", [token]);\n}\n`, "client.query(", "client.query("),
  pair("sql-05", "sql-injection",
    `export async function search(input, adapter) {\n  return adapter.query("SELECT * FROM documents WHERE title LIKE '%" + input.term + "%' ");\n}\n`,
    `export async function search(input, adapter) {\n  return adapter.query("SELECT * FROM documents WHERE title LIKE ?", ["%" + input.term + "%"]);\n}\n`, "adapter.query(", "adapter.query("),

  pair("ssrf-01", "ssrf",
    `export async function preview(req) {\n  return fetch(req.query.url);\n}\n`,
    `const PREVIEW_HOSTS = new Set(["images.example.test"]);\nexport async function preview(req) {\n  const url = new URL(req.query.url);\n  if (!PREVIEW_HOSTS.has(url.hostname)) throw new Error("host not allowed");\n  return fetch(url);\n}\n`, "fetch(req.query.url)", "return fetch(url)"),
  pair("ssrf-02", "ssrf",
    `export async function avatar(ctx, axios) {\n  return axios.get(ctx.body.endpoint);\n}\n`,
    `export async function avatar(ctx, axios) {\n  const url = new URL(ctx.body.endpoint);\n  if (url.origin !== "https://cdn.example.test") throw new Error("origin not allowed");\n  return axios.get(url.href);\n}\n`, "axios.get(ctx.body.endpoint)", "axios.get(url.href)"),
  pair("ssrf-03", "ssrf",
    `export function requestTarget(request, http) {\n  return http.request(new URL(request.url));\n}\n`,
    `const ALLOWED_HOST = "api.example.test";\nexport function requestTarget(request, http) {\n  const url = new URL(request.url);\n  if (url.hostname !== ALLOWED_HOST || url.protocol !== "https:") throw new Error("destination not allowed");\n  return http.request(url);\n}\n`, "http.request(new URL", "return http.request(url)"),
  pair("ssrf-04", "ssrf",
    `export async function pull(params, got) {\n  return got(params.target);\n}\n`,
    `const HOSTS = new Set(["status.example.test"]);\nexport async function pull(params, got) {\n  const url = new URL(params.target);\n  if (!HOSTS.has(url.hostname)) throw new Error("host not allowed");\n  return got(url.href);\n}\n`, "got(params.target)", "return got(url.href)"),
  pair("ssrf-05", "ssrf",
    `export async function next(body) {\n  const url = new URL(body.next, "https://service.example.test");\n  return fetch(url);\n}\n`,
    `export async function next(body) {\n  const url = new URL(body.next, "https://service.example.test");\n  if (url.origin !== "https://service.example.test") throw new Error("origin not allowed");\n  return fetch(url);\n}\n`, "return fetch(url)", "return fetch(url)"),

  pair("path-01", "path-traversal",
    `import { readFile } from "node:fs/promises";\nimport path from "node:path";\nexport function download(req, root) {\n  return readFile(path.join(root, req.params.name));\n}\n`,
    `import { readFile } from "node:fs/promises";\nimport path from "node:path";\nexport function download(req, root) {\n  const target = path.resolve(root, req.params.name);\n  if (!target.startsWith(path.resolve(root) + path.sep)) throw new Error("path outside root");\n  return readFile(target);\n}\n`, "readFile(path.join", "readFile(target)"),
  pair("path-02", "path-traversal",
    `import { sendFile } from "./response.js";\nexport function attachment(body, uploads, response) {\n  return sendFile(response, uploads + "/" + body.file);\n}\n`,
    `import path from "node:path";\nimport { sendFile } from "./response.js";\nexport function attachment(body, uploads, response) {\n  const target = path.join(uploads, path.basename(body.file));\n  return sendFile(response, target);\n}\n`, "sendFile(response", "sendFile(response"),
  pair("path-03", "path-traversal",
    `import { createReadStream } from "node:fs";\nimport path from "node:path";\nexport function exportFile(query, config) {\n  return createReadStream(path.resolve(config.exportDir, query.path));\n}\n`,
    `import { createReadStream } from "node:fs";\nimport path from "node:path";\nexport function exportFile(query, config) {\n  const root = path.resolve(config.exportDir);\n  const target = path.resolve(root, query.path);\n  if (!target.startsWith(root + path.sep)) throw new Error("path outside root");\n  return createReadStream(target);\n}\n`, "createReadStream(path.resolve", "createReadStream(target)"),
  pair("path-04", "path-traversal",
    `import { writeFile } from "node:fs/promises";\nimport path from "node:path";\nexport function save(name, body, store) {\n  return writeFile(path.join(store, name), body.data);\n}\n`,
    `import { writeFile } from "node:fs/promises";\nimport path from "node:path";\nexport function save(name, body, store) {\n  const target = path.join(store, path.basename(name));\n  return writeFile(target, body.data);\n}\n`, "writeFile(path.join", "writeFile(target"),
  pair("path-05", "path-traversal",
    `import { open } from "node:fs/promises";\nimport path from "node:path";\nexport function content(req, root) {\n  return open(path.join(root, req.query.slug), "r");\n}\n`,
    `import { open } from "node:fs/promises";\nimport path from "node:path";\nexport function content(req, root) {\n  const target = path.resolve(root, req.query.slug);\n  if (!target.startsWith(path.resolve(root) + path.sep)) throw new Error("path outside root");\n  return open(target, "r");\n}\n`, "open(path.join", "open(target"),

  pair("cmd-01", "command-injection",
    `import { exec } from "node:child_process";\nexport function convert(req) {\n  return exec("convert " + req.body.file);\n}\n`,
    `import { spawn } from "node:child_process";\nexport function convert(req) {\n  return spawn("convert", [req.body.file], { shell: false });\n}\n`, "exec(\"convert", "spawn(\"convert"),
  pair("cmd-02", "command-injection",
    `import { execSync } from "node:child_process";\nexport function show(request) {\n  return execSync("git show " + request.query.ref);\n}\n`,
    `import { execFileSync } from "node:child_process";\nexport function show(request) {\n  return execFileSync("git", ["show", request.query.ref], { shell: false });\n}\n`, "execSync(\"git show", "execFileSync(\"git"),
  pair("cmd-03", "command-injection",
    `import { spawn } from "node:child_process";\nexport function unpack(body) {\n  return spawn("sh", ["-c", "tar xf " + body.archive]);\n}\n`,
    `import { spawn } from "node:child_process";\nexport function unpack(body) {\n  return spawn("tar", ["xf", body.archive], { shell: false });\n}\n`, "spawn(\"sh\"", "spawn(\"tar\""),
  pair("cmd-04", "command-injection",
    `import { execFile } from "node:child_process";\nexport function run(args) {\n  return execFile("/bin/sh", ["-c", args.command]);\n}\n`,
    `import { execFile } from "node:child_process";\nexport function run(args) {\n  return execFile("/usr/bin/tool", ["--mode", args.mode], { shell: false });\n}\n`, "execFile(\"/bin/sh", "execFile(\"/usr/bin/tool"),
  pair("cmd-05", "command-injection",
    `import { exec } from "node:child_process";\nexport function ping(ctx) {\n  return exec("ping -c 1 " + ctx.params.host);\n}\n`,
    `import { spawn } from "node:child_process";\nexport function ping(ctx) {\n  return spawn("ping", ["-c", "1", ctx.params.host], { shell: false });\n}\n`, "exec(\"ping", "spawn(\"ping"),

  pair("proto-01", "prototype-pollution",
    `export function merge(target, source) {\n  for (const key of Object.keys(source)) target[key] = source[key];\n  return target;\n}\n`,
    `export function merge(target, source) {\n  for (const key of Object.keys(source)) {\n    if (["__proto__", "constructor", "prototype"].includes(key)) continue;\n    target[key] = source[key];\n  }\n  return target;\n}\n`, "target[key] = source[key]", "target[key] = source[key]"),
  pair("proto-02", "prototype-pollution",
    `export function configure(config, body) {\n  Object.assign(config, JSON.parse(body.settings));\n  return config;\n}\n`,
    `export function configure(config, body) {\n  const input = JSON.parse(body.settings);\n  for (const key of Object.keys(input)) {\n    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;\n    config[key] = input[key];\n  }\n  return config;\n}\n`, "Object.assign(config", "config[key] = input[key]"),
  pair("proto-03", "prototype-pollution",
    `export function setPath(target, parts, value) {\n  let cursor = target;\n  for (const part of parts.slice(0, -1)) cursor = cursor[part] ||= {};\n  cursor[parts.at(-1)] = value;\n  return target;\n}\n`,
    `export function setPath(target, parts, value) {\n  if (parts.some(part => ["__proto__", "constructor", "prototype"].includes(part))) throw new Error("unsafe key");\n  let cursor = target;\n  for (const part of parts.slice(0, -1)) cursor = cursor[part] ||= {};\n  cursor[parts.at(-1)] = value;\n  return target;\n}\n`, "cursor[part] ||=", "cursor[part] ||= "),
  pair("proto-04", "prototype-pollution",
    `export function mergeNested(target, source) {\n  for (const key in source) {\n    if (source[key] && typeof source[key] === "object") target[key] = mergeNested(target[key] || {}, source[key]);\n    else target[key] = source[key];\n  }\n  return target;\n}\n`,
    `export function mergeNested(target, source) {\n  for (const key in source) {\n    if (["__proto__", "constructor", "prototype"].includes(key)) continue;\n    if (source[key] && typeof source[key] === "object") target[key] = mergeNested(target[key] || {}, source[key]);\n    else target[key] = source[key];\n  }\n  return target;\n}\n`, "target[key] = source[key]", "target[key] = source[key]"),
  pair("proto-05", "prototype-pollution",
    `export function setOption(name, value, config) {\n  config[name] = value;\n  return config;\n}\n`,
    `export function setOption(name, value) {\n  const config = Object.create(null);\n  config[name] = value;\n  return config;\n}\n`, "config[name] = value", "config[name] = value")
];

export const benchmarkSamples = benchmarkPairs.flatMap(item => item.samples.map(sample => ({ ...sample, pair_id: item.id, category: item.category })));
