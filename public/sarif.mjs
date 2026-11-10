function safeText(value, maxLength = 4000, fallback = "") {
  return String(value ?? fallback).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, maxLength);
}

function sourceUri(value, fallback = "unknown") {
  const uri = safeText(value, 2000, fallback).replaceAll("\\", "/").replace(/^\/+/, "");
  if (!uri || uri.split("/").some(part => part === "..")) return fallback;
  return uri;
}

function line(value) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 1;
}

function digest(value) {
  let hash = 0xcbf29ce484222325n;
  for (const byte of new TextEncoder().encode(String(value))) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return hash.toString(16).padStart(16, "0");
}

function location(uri, lineNumber = 1) {
  return {
    physicalLocation: {
      artifactLocation: { uri: sourceUri(uri) },
      region: { startLine: line(lineNumber) }
    }
  };
}

export function buildSarif(result, options = {}) {
  const includeUnverified = options.includeUnverified !== false;
  const category = safeText(options.category || "kavach", 200) || "kavach";
  const rules = new Map();
  const sarifResults = [];
  const addRule = (id, descriptor) => {
    if (!rules.has(id)) rules.set(id, { id, ...descriptor });
  };

  for (const cve of result?.cveFindings || []) {
    const ruleId = safeText(cve.id || cve.advisoryId || "OSV-ADVISORY", 255);
    addRule(ruleId, {
      name: cve.package ? `VulnerableDependency/${safeText(cve.package, 180)}` : ruleId,
      shortDescription: { text: safeText(cve.summary || "Known affected dependency version", 1024) },
      helpUri: safeText(cve.reference || "https://osv.dev", 2048)
    });
    const uri = sourceUri(cve.manifest || "package.json");
    sarifResults.push({
      ruleId,
      level: ["CRITICAL", "HIGH"].includes(String(cve.severity || "").toUpperCase()) ? "error" : "warning",
      message: { text: safeText(`${cve.package} ${cve.version} (${cve.ecosystem}): ${cve.summary}`) },
      locations: [location(uri)],
      partialFingerprints: {
        "kavach/v1": digest([ruleId, cve.package, cve.version, uri].join("\0"))
      }
    });
  }

  if (includeUnverified) {
    for (const finding of result?.sourceFindings || []) {
      const ruleId = safeText(finding.rule || "source-pattern", 255);
      addRule(ruleId, {
        name: safeText(finding.title || ruleId, 255),
        shortDescription: { text: safeText(finding.title || "Source review lead", 1024) },
        fullDescription: { text: safeText(finding.boundary || "Requires human verification.", 1024) }
      });
      const uri = sourceUri(finding.path);
      const startLine = line(finding.line);
      sarifResults.push({
        ruleId,
        level: "warning",
        message: { text: safeText(`${finding.title}: ${finding.boundary} Suggested fix: ${finding.fix}`) },
        locations: [location(uri, startLine)],
        partialFingerprints: {
          "kavach/v1": digest([ruleId, uri, startLine, finding.evidence || ""].join("\0"))
        }
      });
    }
  }

  for (const item of result?.audit?.findings || []) {
    if (item.verdict === "rejected" || (!includeUnverified && item.verdict !== "confirmed")) continue;
    const ruleId = safeText(item.rule || item.category || "kavach-audit-finding", 255);
    const sink = (item.trace || []).at(-1) || (item.evidence || [])[0] || { file: "unknown", line: 1 };
    const uri = sourceUri(sink.file);
    const startLine = line(sink.line);
    addRule(ruleId, {
      name: safeText(item.title || ruleId, 255),
      shortDescription: { text: safeText(item.title || "Structured audit finding", 1024) },
      fullDescription: { text: safeText(item.description || item.claimed_root_cause || "Structured audit finding", 1024) }
    });
    sarifResults.push({
      ruleId,
      level: item.verdict === "confirmed" ? "error" : "note",
      message: { text: safeText(`${item.title} (${item.verdict}): ${item.claimed_root_cause || item.root_cause || item.description}`) },
      locations: [location(uri, startLine)],
      partialFingerprints: {
        "kavach/v1": safeText(item.fingerprint || digest([ruleId, uri, startLine].join("\0")), 255)
      }
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      automationDetails: { id: category },
      tool: {
        driver: {
          name: "Kavach Project Security Review",
          version: "1.0.0",
          informationUri: "https://github.com/cloudflare/security-audit-skill",
          rules: [...rules.values()]
        }
      },
      results: sarifResults
    }]
  };
}
