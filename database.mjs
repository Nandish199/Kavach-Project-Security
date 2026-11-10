import pg from "pg";

const { Pool } = pg;
let pool;

function localDatabaseUrl(value = process.env.DATABASE_URL) {
  if (!value) return null;
  let url;
  try { url = new URL(value); } catch { throw new Error("DATABASE_URL must be a PostgreSQL connection URL."); }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!/^postgres(?:ql)?$/.test(url.protocol.replace(/:$/, "")) || !["localhost", "127.0.0.1", "::1"].includes(hostname)) {
    throw new Error("For this private workspace, PostgreSQL must be on this device (localhost, 127.0.0.1, or ::1).");
  }
  return value;
}

function getPool() {
  const connectionString = localDatabaseUrl();
  if (!connectionString) return null;
  if (!pool) pool = new Pool({ connectionString, max: 5, idleTimeoutMillis: 10000, connectionTimeoutMillis: 3000, allowExitOnIdle: true });
  return pool;
}

export function postgresConfigured() {
  try { return Boolean(localDatabaseUrl()); } catch { return false; }
}

export async function initializePostgres() {
  const client = getPool();
  if (!client) return { state: "not-configured", message: "Set DATABASE_URL to a PostgreSQL service on this device." };
  await client.query(`
    CREATE TABLE IF NOT EXISTS fieldnote_scan_runs (
      id UUID PRIMARY KEY,
      user_uid TEXT NOT NULL,
      project_name TEXT NOT NULL,
      source_kind TEXT NOT NULL CHECK (source_kind IN ('git', 'folder')),
      source_url TEXT,
      source_ref TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      summary JSONB NOT NULL,
      report_markdown TEXT NOT NULL,
      cve_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
      source_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
      coverage JSONB NOT NULL DEFAULT '{}'::jsonb,
      audit_artifacts JSONB NOT NULL DEFAULT '{}'::jsonb,
      full_result JSONB NOT NULL DEFAULT '{}'::jsonb
    )
  `);
  await client.query("ALTER TABLE fieldnote_scan_runs ADD COLUMN IF NOT EXISTS full_result JSONB NOT NULL DEFAULT '{}'::jsonb");
  await client.query("CREATE INDEX IF NOT EXISTS fieldnote_scan_runs_user_created_idx ON fieldnote_scan_runs (user_uid, created_at DESC)");
  return { state: "connected", message: "Local PostgreSQL is ready." };
}

export async function postgresStatus() {
  try {
    const client = getPool();
    if (!client) return { state: "not-configured", message: "PostgreSQL is not configured." };
    await client.query("SELECT 1");
    return { state: "connected", message: "Local PostgreSQL is connected." };
  } catch (error) {
    return { state: "offline", message: error.message.slice(0, 240) };
  }
}

export async function saveScanRun(userUid, result) {
  const client = getPool();
  if (!client) throw new Error("PostgreSQL is not configured. Add a local DATABASE_URL before saving review history.");
  const source = result.source || {};
  await client.query(
    `INSERT INTO fieldnote_scan_runs
      (id, user_uid, project_name, source_kind, source_url, source_ref, summary, report_markdown,
       cve_findings, source_findings, coverage, audit_artifacts, full_result)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb, $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb)`,
    [
      result.id, userUid, String(source.label || "Project review").slice(0, 180),
      source.kind === "git" ? "git" : "folder", source.kind === "git" ? String(source.url || "").slice(0, 1000) : null,
      String(source.revision || "").slice(0, 180) || null, JSON.stringify(result.summary || {}),
      String(result.report || "").slice(0, 4_000_000), JSON.stringify(result.cveFindings || []),
      JSON.stringify(result.sourceFindings || []), JSON.stringify(result.coverage || {}),
      JSON.stringify(result.audit?.artifacts || {}), JSON.stringify(result)
    ]
  );
}

export async function listScanRuns(userUid, limit = 50) {
  const client = getPool();
  if (!client) throw new Error("PostgreSQL is not configured.");
  const result = await client.query(
    `SELECT id, project_name, source_kind, source_url, source_ref, created_at, summary
     FROM fieldnote_scan_runs WHERE user_uid = $1 ORDER BY created_at DESC LIMIT $2`,
    [userUid, Math.max(1, Math.min(100, Number(limit) || 50))]
  );
  return result.rows;
}

export async function listPriorScanRuns(userUid, source) {
  const client = getPool();
  if (!client) throw new Error("PostgreSQL is not configured.");
  const kind = source?.kind === "git" ? "git" : "folder";
  const url = kind === "git" ? String(source?.url || "").slice(0, 1000) : null;
  const projectName = String(source?.label || "Project review").slice(0, 180);
  const result = await client.query(
    `SELECT id, project_name, source_kind, source_url, source_ref, created_at,
            jsonb_build_object(
              'id', full_result->>'id',
              'source', full_result->'source',
              'audit', jsonb_build_object(
                'metadata', full_result->'audit'->'metadata',
                'coverage_ledger', full_result->'audit'->'coverage_ledger',
                'findings', full_result->'audit'->'findings',
                'artifacts', jsonb_build_object('run-metadata.json', full_result->'audit'->'artifacts'->'run-metadata.json')
              )
            ) AS full_result
     FROM fieldnote_scan_runs
     WHERE user_uid = $1 AND source_kind = $2
       AND (($2 = 'git' AND source_url = $3) OR
            ($2 = 'folder' AND project_name = $4 AND
             ($5::text IS NULL OR full_result->'source'->>'identity' = $5)))
     ORDER BY created_at DESC`,
    [userUid, kind, url, projectName, source?.identity ? String(source.identity).slice(0, 1000) : null]
  );
  return result.rows;
}

export async function getScanRun(userUid, runId) {
  const client = getPool();
  if (!client) throw new Error("PostgreSQL is not configured.");
  const result = await client.query(
    `SELECT id, project_name, source_kind, source_url, source_ref, created_at, summary,
            report_markdown, cve_findings, source_findings, coverage, audit_artifacts, full_result
     FROM fieldnote_scan_runs WHERE user_uid = $1 AND id = $2`,
    [userUid, runId]
  );
  return result.rows[0] || null;
}

export async function deleteScanRun(userUid, runId) {
  const client = getPool();
  if (!client) throw new Error("PostgreSQL is not configured.");
  const result = await client.query(
    `DELETE FROM fieldnote_scan_runs WHERE user_uid = $1 AND id = $2 RETURNING id`,
    [userUid, runId]
  );
  return result.rowCount > 0;
}

export async function updateScanTriage(userUid, runId, findingId, triageEntry) {
  const client = getPool();
  if (!client) throw new Error("PostgreSQL is not configured.");
  const row = await getScanRun(userUid, runId);
  if (!row) return null;
  const fullResult = row.full_result && typeof row.full_result === "object" ? row.full_result : {};
  const triage = fullResult.triage && typeof fullResult.triage === "object" ? { ...fullResult.triage } : {};
  if (!triageEntry || (!triageEntry.status && !triageEntry.note)) {
    delete triage[findingId];
  } else {
    triage[findingId] = {
      status: String(triageEntry.status || "needs_validation").slice(0, 40),
      note: String(triageEntry.note || "").slice(0, 600),
      updatedAt: new Date().toISOString()
    };
  }
  fullResult.triage = triage;
  await client.query(
    `UPDATE fieldnote_scan_runs SET full_result = $1::jsonb WHERE user_uid = $2 AND id = $3`,
    [JSON.stringify(fullResult), userUid, runId]
  );
  return triage;
}
