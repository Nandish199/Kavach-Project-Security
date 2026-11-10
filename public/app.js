import {
  createAccount,
  currentIdToken,
  initializeFirebase,
  loadPreferences,
  onFirebaseUser,
  savePreferences,
  sendPasswordReset,
  signIn,
  signOutUser
} from "/firebase-client.js";
import { buildSarif } from "/sarif.mjs";

const $ = id => document.getElementById(id);
const IGNORED_DIRS = new Set([".git", ".svn", ".hg", "node_modules", ".next", ".nuxt", ".turbo", ".cache", ".venv", "venv", "__pycache__", ".pytest_cache", ".fieldnote-postgres", ".kavach", "dist", "build", "coverage", "out", "pods", "deriveddata"]);
const BINARY_EXTS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".mp3", ".mp4", ".mov", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".dylib", ".so", ".dll", ".exe", ".class", ".jar", ".bin", ".lockb", ".db", ".sqlite", ".wasm", ".pb", ".onnx"]);
const ACTIVE_JOB_SESSION_KEY = "fieldnote.active-job";

let sourceMode = "git";
let selectedFiles = [];
let selectedSkipped = { ignored: 0, large: 0, binary: 0 };
let reports = [];
let currentResult = null;
let currentJobId = null;
let modelRequestNumber = 0;
let previousProvider = "ollama";
let providerSyncReady = false;
let currentUser = null;
let activeUid = "";
let authMode = "signin";
let postgresAvailable = false;
let profileSaveTimer = null;
let authReady = false;

function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
}

async function authorizedFetch(url, options = {}) {
  let token;
  try { token = await currentIdToken(); }
  catch (error) {
    if (/session ended|sign in again/i.test(error.message || "")) error.status = 401;
    throw error;
  }
  if (!token) {
    const error = new Error("Your sign-in session ended. Sign in again to continue.");
    error.status = 401;
    throw error;
  }
  const headers = new Headers(options.headers || {});
  headers.set("authorization", "Bearer " + token);
  return fetch(url, { ...options, headers, cache: options.cache || "no-store" });
}

function servicePill(id, label, state, message) {
  const node = $(id);
  if (!node) return;
  node.textContent = label + ": " + state;
  node.classList.toggle("connected", state === "ready" || state === "connected" || state === "saved");
  node.classList.toggle("error", state === "offline" || state === "blocked" || state === "not-configured" || state === "image-missing" || state === "misconfigured");
  node.classList.toggle("checking", state === "checking" || state === "syncing");
  node.title = message || "";
}

async function refreshInfrastructure() {
  try {
    const [postgresResponse, dockerResponse] = await Promise.all([
      fetch("/api/postgres/status", { cache: "no-store" }),
      fetch("/api/sandbox/status", { cache: "no-store" })
    ]);
    const postgres = await postgresResponse.json();
    const docker = await dockerResponse.json();
    postgresAvailable = postgres.state === "connected";
    servicePill("postgres-status", "PostgreSQL", postgres.state, postgres.message);
    servicePill("docker-status", "Docker", docker.state, docker.message);
  } catch {
    postgresAvailable = false;
    servicePill("postgres-status", "PostgreSQL", "offline", "Could not reach the local PostgreSQL status endpoint.");
    servicePill("docker-status", "Docker", "offline", "Could not reach the local Docker status endpoint.");
  }
}

function setAuthMessage(message, state = "") {
  const node = $("auth-message");
  node.textContent = message;
  node.classList.toggle("error", state === "error");
  node.classList.toggle("success", state === "success");
}

function updateAuthMode() {
  const create = authMode === "create";
  $("auth-title").textContent = create ? "Create your workspace account" : "Sign in to your workspace";
  $("auth-password").autocomplete = create ? "new-password" : "current-password";
  $("auth-submit").textContent = create ? "Create account" : "Continue";
  $("auth-reset").classList.toggle("hidden", create);
  $("auth-mode-toggle").textContent = create ? "Already have an account? Sign in" : "Create an account";
}

function showAuthenticatedWorkspace(user) {
  currentUser = user;
  activeUid = user.uid;
  $("signed-in-email").textContent = user.email || "Signed in";
  $("auth-gate").classList.add("hidden");
  $("app-shell").classList.remove("hidden");
}

function showSignedOutWorkspace(message = "") {
  currentUser = null;
  activeUid = "";
  providerSyncReady = false;
  reports = [];
  currentResult = null;
  postgresAvailable = false;
  $("app-shell").classList.add("hidden");
  $("auth-gate").classList.remove("hidden");
  $("signed-in-email").textContent = "";
  renderReports();
  if (message) setAuthMessage(message, "success");
}

function saveActiveJob(uid, id) {
  if (!uid || !id) return;
  try { sessionStorage.setItem(ACTIVE_JOB_SESSION_KEY, JSON.stringify({ uid, id, createdAt: new Date().toISOString() })); } catch {}
}

function savedActiveJob(uid) {
  try {
    const value = JSON.parse(sessionStorage.getItem(ACTIVE_JOB_SESSION_KEY) || "null");
    return value?.uid === uid && /^[0-9a-f-]{36}$/i.test(value.id || "") ? value.id : "";
  } catch { return ""; }
}

function clearActiveJob(id = "") {
  try {
    const value = JSON.parse(sessionStorage.getItem(ACTIVE_JOB_SESSION_KEY) || "null");
    if (!id || value?.id === id) sessionStorage.removeItem(ACTIVE_JOB_SESSION_KEY);
  } catch { try { sessionStorage.removeItem(ACTIVE_JOB_SESSION_KEY); } catch {} }
}

const MODEL_PROVIDERS = new Set(["ollama", "mlx", "apple-fm", "codex", "gemini-cli"]);
function getProvider() { return MODEL_PROVIDERS.has($("provider-select").value) ? $("provider-select").value : "ollama"; }
function isLocalProvider(provider = getProvider()) { return ["ollama", "mlx", "apple-fm"].includes(provider); }
function providerLabel(provider = getProvider()) {
  return ({ ollama: "Ollama", mlx: "Apple MLX", "apple-fm": "Apple Foundation Models", codex: "Codex CLI", "gemini-cli": "Gemini CLI" })[provider] || "model provider";
}

function showView(view) {
  const target = view === "report" ? "report" : view;
  document.querySelectorAll(".workspace-view").forEach(section => section.classList.add("hidden"));
  const node = $("view-" + target);
  if (node) node.classList.remove("hidden");
  const activeNav = view === "report" ? "review" : view;
  document.querySelectorAll(".nav-item[data-view]").forEach(button => {
    const active = button.dataset.view === activeNav;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  const labels = { review: "New review", report: "Safety report", reports: "Reports", method: "Audit method", progress: "Review in progress" };
  $("breadcrumb-current").textContent = labels[view] || "New review";
  window.scrollTo({ top: 0, behavior: "auto" });
}

function updateScopeSummaryNote() {
  const branch = $("git-branch")?.value.trim() || "";
  const subpaths = $("scope-subpaths")?.value.trim() || "";
  const parts = [];
  if (sourceMode === "git" && branch) parts.push("ref: " + branch);
  if (subpaths) parts.push("paths: " + subpaths);
  if ($("scope-summary-note")) $("scope-summary-note").textContent = parts.length ? parts.join(", ") : "Optional";
}

function setSourceMode(mode) {
  sourceMode = mode;
  document.querySelectorAll("[data-source-tab]").forEach(button => {
    const active = button.dataset.sourceTab === mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  $("source-git").classList.toggle("hidden", mode !== "git");
  $("source-folder").classList.toggle("hidden", mode !== "folder");
  if ($("git-branch-wrap")) $("git-branch-wrap").classList.toggle("hidden", mode !== "git");
  updateScopeSummaryNote();
  hideError();
}

function showError(message) {
  const node = $("scan-error");
  node.textContent = message;
  node.classList.remove("hidden");
}

function hideError() {
  $("scan-error").classList.add("hidden");
}

function modelBaseDefault(provider) {
  if (provider === "mlx") return "http://127.0.0.1:8080";
  if (provider === "apple-fm") return "http://127.0.0.1:11437";
  return "http://127.0.0.1:11434";
}

function updateProviderPresentation() {
  const provider = getProvider();
  const local = isLocalProvider(provider);
  const enabled = $("use-local-model").checked;
  $("local-model-settings").hidden = !local;
  $("model-data-note").classList.toggle("hosted", !local && enabled);
  $("privacy-status").textContent = !enabled ? "Model review off" : local ? "Local model selected" : `${providerLabel(provider)} selected`;
  $("model-data-note").textContent = !enabled
    ? "Model review is turned off. Source excerpts will not be sent to a model provider."
    : local
    ? "Local choice: model prompts and selected source excerpts are sent only to the loopback model server on this device."
    : `CLI choice: selected source excerpts and audit prompts will be processed through your signed-in ${providerLabel(provider)} account. Kavach does not store or pass an API key.`;
  $("engine-note").textContent = local
    ? "Choose a model already available from Ollama, Apple MLX, or Apple Foundation Models on this device. The six-phase audit uses your selected model for review and report writing."
    : `Choose an available model from ${providerLabel(provider)}. Sign in to that CLI on this device; its account quotas and limits apply.`;
  $("model-label").textContent = local ? "Installed model" : "Available model";
  $("model-base").required = local;
}

function updateAddressText() {
  try {
    const url = new URL($("model-base").value);
    $("engine-address").textContent = url.host;
  } catch { $("engine-address").textContent = "local address"; }
}

function setEngineStatus(state, message, provider = getProvider()) {
  const status = $("engine-status");
  status.classList.toggle("connected", state === "connected");
  status.classList.toggle("error", state === "error");
  status.classList.toggle("checking", state === "checking");
  status.dataset.provider = provider;
  const label = status.querySelector("span") || status;
  label.textContent = message;
}

const CLI_FALLBACK_MODELS = {
  codex: [
    { id: "cli-default", label: "Codex CLI default" },
    { id: "gpt-6-astra", label: "GPT-6-Astra" },
    { id: "gpt-6.1-sol", label: "GPT-6.1-Sol" },
    { id: "gpt-6-sol", label: "GPT-6-Sol" },
    { id: "gpt-6-luna", label: "GPT-6-Luna" },
    { id: "gpt-5.6-sol", label: "GPT-5.6-Sol" },
    { id: "gpt-5.6-terra", label: "GPT-5.6-Terra" },
    { id: "gpt-5.6-luna", label: "GPT-5.6 Luna · xhigh" },
    { id: "gpt-5.5", label: "GPT-5.5" }
  ],
  "gemini-cli": [
    { id: "cli-default", label: "Gemini CLI default (Auto)" },
    { id: "pro", label: "Gemini Pro" },
    { id: "flash", label: "Gemini Flash" },
    { id: "flash-lite", label: "Gemini Flash Lite" },
    { id: "gemini-2.5-pro", label: "Gemini 2.5 Pro" },
    { id: "gemini-2.5-flash", label: "Gemini 2.5 Flash" }
  ]
};

async function refreshModels(requestedProvider = getProvider()) {
  const requestNumber = ++modelRequestNumber;
  const provider = requestedProvider;
  const local = isLocalProvider(provider);
  const base = $("model-base").value;
  if (local) updateAddressText();
  setEngineStatus("checking", local ? `Checking ${providerLabel(provider)}` : `Checking ${providerLabel(provider)} CLI`, provider);
  const select = $("model-select");
  const previous = select.value || localStorage.getItem("fieldnote-model") || "";
  try {
    const response = await fetch("/api/models?provider=" + encodeURIComponent(provider) + (local ? "&base=" + encodeURIComponent(base) : ""), { cache: "no-store" });
    const data = await response.json();
    if (requestNumber !== modelRequestNumber || provider !== getProvider()) return;
    if (data.provider && data.provider !== provider) throw new Error("The provider response did not match the selected provider.");
    select.replaceChildren();
    let models = Array.isArray(data.models) ? data.models.map(item => {
      if (typeof item === "string") {
        const label = item === "cli-default"
          ? provider === "gemini-cli" ? "Gemini CLI default (Auto)" : "Codex CLI default"
          : item === "gpt-5.6-luna" ? "GPT-5.6 Luna · xhigh" : item;
        return { id: item, label };
      }
      if (!item || typeof item.id !== "string") return null;
      const label = item.id === "gpt-5.6-luna" && !/xhigh/i.test(item.label || "")
        ? "GPT-5.6 Luna · xhigh"
        : typeof item.label === "string" && item.label ? item.label : item.id;
      return { id: item.id, label };
    }).filter(Boolean) : [];
    if (!models.length && CLI_FALLBACK_MODELS[provider]) {
      models = CLI_FALLBACK_MODELS[provider];
    }
    updateProviderPresentation();
    if (data.error && !CLI_FALLBACK_MODELS[provider]) $("model-data-note").textContent += " " + data.error;
    if (!models.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No models detected";
      select.append(option);
      const statusMessage = data.configured === false
        ? `${providerLabel(provider)} setup needed`
        : data.error
        ? `${providerLabel(provider)} unavailable`
        : `${providerLabel(provider)} has no models`;
      setEngineStatus("error", statusMessage, provider);
    } else {
      for (const model of models) {
        const option = document.createElement("option");
        option.value = model.id;
        option.textContent = model.label;
        select.append(option);
      }
      const preferred = provider === "ollama" ? ["qwen3:4b", "gemma4:e4b", "llama3.2:3b"] : [];
      select.value = models.some(model => model.id === previous) ? previous : models.find(model => preferred.includes(model.id))?.id || models[0].id;
      setEngineStatus("connected", data.statusMessage || `${providerLabel(provider)} ready`, provider);
      localStorage.setItem("fieldnote-model", select.value);
    }
  } catch {
    if (requestNumber !== modelRequestNumber || provider !== getProvider()) return;
    select.replaceChildren();
    const fallback = CLI_FALLBACK_MODELS[provider];
    if (fallback) {
      for (const model of fallback) {
        const option = document.createElement("option");
        option.value = model.id;
        option.textContent = model.label;
        select.append(option);
      }
      select.value = fallback.some(model => model.id === previous) ? previous : fallback[0].id;
      setEngineStatus("connected", `${providerLabel(provider)} ready`, provider);
      localStorage.setItem("fieldnote-model", select.value);
      return;
    }
    const option = document.createElement("option");
    option.value = "";
    option.textContent = isLocalProvider(provider) ? "Start the local server to load models" : "Check provider setup";
    select.append(option);
    setEngineStatus("error", `${providerLabel(provider)} unavailable`, provider);
  }
}

function handleProviderSelection() {
  const provider = getProvider();
  const statusProvider = $("engine-status").dataset.provider;
  if (provider === previousProvider && statusProvider === provider) return;
  const oldBase = $("model-base").value;
  if (provider !== previousProvider && isLocalProvider(provider) && (!oldBase || oldBase === modelBaseDefault(previousProvider))) {
    $("model-base").value = modelBaseDefault(provider);
  }
  previousProvider = provider;
  updateProviderPresentation();
  if (providerSyncReady) rememberSettings();
  const select = $("model-select");
  select.replaceChildren();
  const option = document.createElement("option");
  option.value = "";
  option.textContent = `Checking ${providerLabel(provider)}…`;
  select.append(option);
  setEngineStatus("checking", isLocalProvider(provider) ? `Checking ${providerLabel(provider)}` : `Checking ${providerLabel(provider)} CLI`, provider);
  refreshModels(provider);
}

function syncProviderStatus() {
  if (!providerSyncReady) return;
  const provider = getProvider();
  if (provider !== previousProvider || $("engine-status").dataset.provider !== provider) handleProviderSelection();
}

function rememberSettings() {
  localStorage.setItem("fieldnote-provider", getProvider());
  localStorage.setItem("fieldnote-model-base", $("model-base").value);
  localStorage.setItem("fieldnote-model", $("model-select").value || "");
  localStorage.setItem("fieldnote-use-model", String($("use-local-model").checked));
  localStorage.setItem("fieldnote-check-osv", String($("check-osv").checked));
  localStorage.setItem("fieldnote-run-docker", String($("run-docker-tests").checked));
  localStorage.setItem("fieldnote-audit-profile", $("audit-profile").value);
  localStorage.setItem("fieldnote-audit-budget", String($("audit-budget").value));
  if (currentUser) {
    clearTimeout(profileSaveTimer);
    profileSaveTimer = setTimeout(persistProfileSettings, 700);
  }
}

function loadSettings() {
  let provider = localStorage.getItem("fieldnote-provider");
  if (provider === "openai") provider = "codex";
  if (provider === "gemini") provider = "gemini-cli";
  if (MODEL_PROVIDERS.has(provider)) $("provider-select").value = provider;
  previousProvider = getProvider();
  $("model-base").value = localStorage.getItem("fieldnote-model-base") || modelBaseDefault(getProvider());
  const useModel = localStorage.getItem("fieldnote-use-model");
  if (useModel === "false") $("use-local-model").checked = false;
  const checkOsv = localStorage.getItem("fieldnote-check-osv");
  if (checkOsv === "false") $("check-osv").checked = false;
  const runDocker = localStorage.getItem("fieldnote-run-docker");
  if (runDocker === "false") $("run-docker-tests").checked = false;
  const auditProfile = localStorage.getItem("fieldnote-audit-profile");
  if (["quick", "standard", "deep"].includes(auditProfile)) $("audit-profile").value = auditProfile;
  const auditBudget = Number(localStorage.getItem("fieldnote-audit-budget"));
  if (Number.isInteger(auditBudget) && auditBudget >= 12 && auditBudget <= 512) $("audit-budget").value = String(auditBudget);
  updateProviderPresentation();
  updateAddressText();
}

function readPreferences() {
  return {
    provider: getProvider(),
    modelBase: $("model-base").value.trim(),
    model: $("model-select").value || "",
    useLocalModel: $("use-local-model").checked,
    checkOsv: $("check-osv").checked,
    runDockerTests: $("run-docker-tests").checked
  };
}

function applyPreferences(preferences) {
  if (!preferences) return;
  const providerBeforeApply = getProvider();
  const preferenceProvider = preferences.provider === "openai" ? "codex" : preferences.provider === "gemini" ? "gemini-cli" : preferences.provider;
  if (MODEL_PROVIDERS.has(preferenceProvider)) $("provider-select").value = preferenceProvider;
  if (typeof preferences.modelBase === "string" && preferences.modelBase) $("model-base").value = preferences.modelBase;
  if (typeof preferences.useLocalModel === "boolean") $("use-local-model").checked = preferences.useLocalModel;
  if (typeof preferences.checkOsv === "boolean") $("check-osv").checked = preferences.checkOsv;
  if (typeof preferences.runDockerTests === "boolean") $("run-docker-tests").checked = preferences.runDockerTests;
  const providerAfterApply = getProvider();
  previousProvider = providerBeforeApply;
  updateProviderPresentation();
  updateAddressText();
  if (providerAfterApply !== providerBeforeApply || $("engine-status").dataset.provider !== providerAfterApply) {
    handleProviderSelection();
  }
}

async function persistProfileSettings() {
  if (!currentUser) return;
  servicePill("firestore-status", "Firestore", "syncing", "Saving this account’s review preferences.");
  try {
    await savePreferences(currentUser, readPreferences());
    servicePill("firestore-status", "Firestore", "saved", "Only this account’s preferences are stored in Firestore.");
  } catch (error) {
    servicePill("firestore-status", "Firestore", "blocked", error.message || "Firestore preferences could not be saved.");
  }
}

function shouldSkipDir(name) { return IGNORED_DIRS.has(name.toLowerCase()); }

async function textProjectFiles(fileObjects) {
  const files = [];
  let skippedIgnored = 0;
  let skippedLarge = 0;
  let skippedBinary = 0;
  let totalBytes = 0;
  for (const file of fileObjects) {
    if (!file || !file.name) continue;
    const rel = file.webkitRelativePath || file.name;
    if (rel.split("/").some(shouldSkipDir)) { skippedIgnored += 1; continue; }
    const ext = (file.name.match(/\.[^.]+$/) || [""])[0].toLowerCase();
    if (BINARY_EXTS.has(ext)) { skippedBinary += 1; continue; }
    if (file.size > 1024 * 1024) { skippedLarge += 1; continue; }
    const content = await file.text();
    if (content.slice(0, 4096).includes("\0")) { skippedBinary += 1; continue; }
    totalBytes += new Blob([content]).size;
    if (files.length >= 8000 || totalBytes > 100 * 1024 * 1024) throw new Error("This folder exceeds the 8,000 file or 100 MB review limit. Choose a smaller project folder.");
    files.push({ path: rel, content });
  }
  return { files, skippedIgnored, skippedLarge, skippedBinary, totalBytes };
}

async function walkDirectory(handle, prefix, collected) {
  for await (const [name, entry] of handle.entries()) {
    if (entry.kind === "directory") {
      if (shouldSkipDir(name)) { collected.skippedIgnored += 1; continue; }
      await walkDirectory(entry, prefix ? prefix + "/" + name : name, collected);
      continue;
    }
    const rel = prefix ? prefix + "/" + name : name;
    const ext = (name.match(/\.[^.]+$/) || [""])[0].toLowerCase();
    if (BINARY_EXTS.has(ext)) { collected.skippedBinary += 1; continue; }
    const file = await entry.getFile();
    if (file.size > 1024 * 1024) { collected.skippedLarge += 1; continue; }
    const content = await file.text();
    if (content.slice(0, 4096).includes("\0")) { collected.skippedBinary += 1; continue; }
    collected.totalBytes += new Blob([content]).size;
    if (collected.files.length >= 8000 || collected.totalBytes > 100 * 1024 * 1024) throw new Error("This folder exceeds the 8,000 file or 100 MB review limit. Choose a smaller project folder.");
    collected.files.push({ path: rel, content });
  }
}

async function chooseFolder() {
  hideError();
  selectedFiles = [];
  if (window.showDirectoryPicker) {
    try {
      const directory = await window.showDirectoryPicker({ mode: "read" });
      const collected = { files: [], skippedIgnored: 0, skippedLarge: 0, skippedBinary: 0, totalBytes: 0 };
      $("folder-name").textContent = "Reading " + directory.name + "…";
      $("folder-detail").textContent = "Reading source files on this device. This may take a moment.";
      await walkDirectory(directory, "", collected);
      if (!collected.files.length) throw new Error("No readable text or source files were found in that folder.");
      selectedFiles = collected.files;
      selectedSkipped = { ignored: collected.skippedIgnored, large: collected.skippedLarge, binary: collected.skippedBinary };
      $("folder-name").textContent = directory.name;
      $("folder-detail").textContent = selectedFiles.length.toLocaleString() + " readable files, " + (collected.totalBytes / 1024 / 1024).toFixed(1) + " MB, " + (collected.skippedLarge + collected.skippedBinary + collected.skippedIgnored).toLocaleString() + " paths skipped";
      return;
    } catch (error) {
      if (error && error.name === "AbortError") return;
      if (error && error.name !== "NotAllowedError" && error.name !== "SecurityError") {
        $("folder-name").textContent = "Bring in a project folder";
        $("folder-detail").textContent = "Files are read for this review only. Nothing is executed.";
        showError(error.message || "The folder could not be read.");
        return;
      }
    }
  }
  $("folder-input").click();
}

async function handleFolderInput() {
  try {
    const result = await textProjectFiles(Array.from($("folder-input").files || []));
    if (!result.files.length) throw new Error("No readable text or source files were found in that folder.");
    selectedFiles = result.files;
    selectedSkipped = { ignored: result.skippedIgnored, large: result.skippedLarge, binary: result.skippedBinary };
    const first = result.files[0].path.split("/")[0];
    $("folder-name").textContent = first || "Selected project";
    $("folder-detail").textContent = result.files.length.toLocaleString() + " readable files, " + (result.totalBytes / 1024 / 1024).toFixed(1) + " MB, " + (result.skippedLarge + result.skippedBinary + result.skippedIgnored).toLocaleString() + " paths skipped";
  } catch (error) {
    selectedFiles = [];
    selectedSkipped = { ignored: 0, large: 0, binary: 0 };
    showError(error.message || "The selected folder could not be read.");
  }
}

function updateProgress(job) {
  const progress = job.progress || {};
  const stage = progress.stage || "read";
  const current = Number(progress.current || 0);
  const total = Number(progress.total || 0);
  const ratio = total > 0 ? Math.max(0, Math.min(1, current / total)) : 0;
  let percent = 6;
  let phase = "reconnaissance";
  if (stage === "fetch") { percent = 8; phase = "reconnaissance"; }
  else if (stage === "read") { percent = 12; phase = "reconnaissance"; }
  else if (stage === "source") { percent = 16 + ratio * 15; phase = "reconnaissance"; }
  else if (stage === "sandbox") { percent = 31; phase = "validation"; }
  else if (stage === "candidate-check" || stage.startsWith("audit-candidate")) { percent = 74; phase = "validation"; }
  else if (stage === "cve" || stage === "cve-details") { percent = 32 + ratio * 7; phase = "reconnaissance"; }
  else if (stage === "audit-recon") { percent = 40; phase = "reconnaissance"; }
  else if (stage === "audit-hunt") { percent = 48; phase = "hunting"; }
  else if (stage === "audit-critic" || stage === "audit-clean-critic") { percent = 64; phase = "hunting"; }
  else if (stage === "audit-structured") { percent = 81; phase = "structured"; }
  else if (stage === "audit-record-verification") { percent = 87; phase = "verification"; }
  else if (stage === "audit-report") { percent = 96; phase = "report"; }
  else if (stage === "complete") { percent = 100; phase = "report"; }
  $("progress-fill").value = percent;
  const phaseLabels = { reconnaissance: "Reconnaissance", hunting: "Coverage-led hunt", validation: "Candidate validation", structured: "Structured output", verification: "Record verification", report: "Report ready" };
  $("progress-stage").textContent = phaseLabels[phase] || "Preparing";
  $("progress-count").textContent = total ? Math.min(current, total).toLocaleString() + " / " + total.toLocaleString() : "In progress";
  $("progress-message").textContent = progress.message || "Reviewing project files…";
  document.querySelectorAll(".phase").forEach(node => {
    const order = { reconnaissance: 0, hunting: 1, validation: 2, structured: 3, verification: 4, report: 5 };
    const active = node.dataset.phase === phase;
    node.classList.toggle("active", active);
    node.classList.toggle("done", order[node.dataset.phase] < order[phase]);
  });
}

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function pollJob(id) {
  while (true) {
    const response = await authorizedFetch("/api/scan/" + encodeURIComponent(id));
    const job = await response.json();
    if (!response.ok) { const error = new Error(job.error || "The review is no longer available."); error.status = response.status; throw error; }
    updateProgress(job);
    if (job.status === "complete") return job.result;
    if (job.status === "cancelled") {
      const error = new Error(job.error || "Review cancelled by user.");
      error.cancelled = true;
      throw error;
    }
    if (job.status === "error") throw new Error(job.error || "The review could not be completed.");
    await delay(750);
  }
}

async function cancelActiveScan() {
  if (!currentJobId) return;
  const button = $("cancel-scan");
  if (button) button.disabled = true;
  try {
    await authorizedFetch("/api/scan/" + encodeURIComponent(currentJobId) + "/cancel", { method: "POST" });
    clearActiveJob(currentJobId);
    currentJobId = null;
    showView("review");
    showError("The active review was stopped.");
  } catch (error) {
    showError(error.message || "Could not stop the active review.");
  } finally {
    if (button) button.disabled = false;
  }
}

function finishScanResult(id, result) {
  currentJobId = null;
  clearActiveJob(id);
  currentResult = result;
  reports.unshift({ id, result, createdAt: new Date().toISOString() });
  renderReport(result);
  renderReports();
  showView("report");
}

async function resumeActiveJob(user) {
  const id = savedActiveJob(user.uid);
  if (!id) return;
  currentJobId = id;
  $("progress-source").textContent = "Resuming your saved review";
  showView("progress");
  try {
    const result = await pollJob(id);
    finishScanResult(id, result);
  } catch (error) {
    if (error.cancelled) {
      clearActiveJob(id);
      currentJobId = null;
      showView("review");
      return;
    }
    if (error.status === 401) {
      showSignedOutWorkspace("Your Firebase session ended. Sign in again to continue the saved review.");
      return;
    }
    if (error.status === 404) {
      try { await refreshReports(); } catch {}
      if (reports.some(row => row.id === id)) {
        clearActiveJob(id);
        currentJobId = null;
        await openSavedReport(id);
        return;
      }
      clearActiveJob(id);
      currentJobId = null;
      showView("review");
      showError("The local server restarted before this review was saved. Start a new review to continue.");
      return;
    }
    showView("progress");
    showError(error.message || "The saved review could not reconnect. Sign in again or reload to resume it.");
  }
}

async function startScan() {
  hideError();
  if (!currentUser) { showError("Sign in before starting a review."); return; }
  const modelCallLimit = Number($("audit-budget").value);
  if (!Number.isInteger(modelCallLimit) || modelCallLimit < 12 || modelCallLimit > 512) { showError("Set a whole-number model-call limit from 12 to 512."); $("audit-budget").focus(); return; }
  if (!postgresAvailable) { await refreshInfrastructure(); }
  if (!postgresAvailable) { showError("Local PostgreSQL is not ready. Start it with the Docker instructions in the setup guide, then try again."); return; }
  let payload;
  if (sourceMode === "git") {
    const gitUrl = $("git-url").value.trim();
    if (!gitUrl) { showError("Paste a public HTTPS repository URL to begin."); $("git-url").focus(); return; }
    payload = { sourceType: "git", gitUrl, gitBranch: $("git-branch")?.value.trim() || "" };
  } else {
    if (!selectedFiles.length) { showError("Choose a local project folder to begin."); return; }
    payload = { sourceType: "folder", sourceLabel: $("folder-name").textContent, files: selectedFiles, skipped: selectedSkipped };
  }
  payload.scopeSubpaths = $("scope-subpaths")?.value.trim() || "";
  payload.provider = getProvider();
  payload.model = $("model-select").value || "";
  payload.modelBase = $("model-base").value.trim();
  payload.localModel = $("use-local-model").checked;
  payload.checkOsv = $("check-osv").checked;
  payload.runDockerTests = $("run-docker-tests").checked;
  payload.auditProfile = $("audit-profile").value;
  payload.auditBudget = modelCallLimit;
  rememberSettings();
  $("progress-source").textContent = sourceMode === "git" ? $("git-url").value.trim() : $("folder-name").textContent;
  $("progress-fill").value = 6;
  if ($("cancel-scan")) $("cancel-scan").disabled = false;
  updateProgress({ progress: { stage: "queued", current: 0, total: 1, message: "Preparing your source…" } });
  showView("progress");
  try {
    const response = await authorizedFetch("/api/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    const data = await response.json();
    if (!response.ok) { const error = new Error(data.error || "Could not start the review."); error.status = response.status; throw error; }
    currentJobId = data.id;
    saveActiveJob(activeUid, data.id);
    if (payload.sourceType === "folder") {
      selectedFiles = [];
      payload.files = [];
      $("folder-input").value = "";
    }
    const result = await pollJob(data.id);
    finishScanResult(data.id, result);
  } catch (error) {
    clearActiveJob(currentJobId || "");
    currentJobId = null;
    showView("review");
    if (error.status === 401) showSignedOutWorkspace("Your Firebase session ended. Sign in again to continue.");
    else showError(error.message || "The review stopped before a report was ready.");
  }
}

function severityClass(severity) {
  const value = String(severity || "").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(value) ? value : "unrated";
}

function triageControlMarkup(findingId, currentTriage = {}) {
  const entry = currentTriage[findingId] || {};
  const status = entry.status || "needs_validation";
  const note = entry.note || "";
  return '<div class="triage-bar" data-triage-id="' + escapeHtml(findingId) + '">' +
    '<label class="triage-label">Review decision ' +
    '<select class="select-field triage-select" data-triage-select="' + escapeHtml(findingId) + '">' +
    '<option value="needs_validation"' + (status === "needs_validation" ? " selected" : "") + '>Needs validation</option>' +
    '<option value="verified_safe"' + (status === "verified_safe" ? " selected" : "") + '>Verified safe</option>' +
    '<option value="confirmed_issue"' + (status === "confirmed_issue" ? " selected" : "") + '>Confirmed issue</option>' +
    '<option value="ignored"' + (status === "ignored" ? " selected" : "") + '>Ignored</option>' +
    '</select></label>' +
    '<input type="text" class="text-field triage-note" data-triage-note="' + escapeHtml(findingId) + '" maxlength="400" placeholder="Add verification note…" value="' + escapeHtml(note) + '">' +
    '<button type="button" class="button button-outline triage-save" data-triage-save="' + escapeHtml(findingId) + '">Save note</button>' +
    '</div>';
}

function findingCard(item, isCve, triageMap = {}) {
  const severity = severityClass(item.severity);
  const findingId = item.id || item.fingerprint || `${item.path}:${item.line}`;
  const triageEntry = triageMap[findingId];
  const triageChipLabel = triageEntry?.status === "verified_safe" ? "Verified safe" : triageEntry?.status === "confirmed_issue" ? "Confirmed issue" : triageEntry?.status === "ignored" ? "Ignored" : "Needs validation";
  const triageChipClass = triageEntry?.status === "verified_safe" ? "complete" : triageEntry?.status === "confirmed_issue" ? "high" : "";
  const idMarkup = isCve
    ? '<a class="cve-link" href="' + escapeHtml(item.reference) + '" target="_blank" rel="noreferrer">' + escapeHtml(item.id) + '</a>'
    : escapeHtml(item.path) + ":" + escapeHtml(item.line);
  const chip = isCve
    ? '<span class="severity-chip ' + severity + '">' + escapeHtml(item.severity === "UNRATED" ? "Unrated" : String(item.severity || "Not rated").toLowerCase().replace(/^\w/, letter => letter.toUpperCase())) + '</span>'
    : '<span class="state-chip ' + triageChipClass + '" data-state-chip="' + escapeHtml(findingId) + '">' + escapeHtml(triageChipLabel) + '</span>';
  const heading = isCve
    ? idMarkup + ': ' + escapeHtml(item.summary || "Known affected dependency")
    : escapeHtml(item.title || "Review candidate");
  let detail = "";
  if (isCve) {
    detail = '<div class="finding-detail"><p><strong>Package</strong> ' + escapeHtml(item.ecosystem + ": " + item.package + " " + item.version) + '</p><p><strong>Advisory</strong> ' + escapeHtml(item.advisoryId) + ": " + escapeHtml(item.summary) + '</p><p><strong>Lockfile</strong> ' + escapeHtml(item.manifest) + '</p></div>';
  } else {
    detail = '<div class="finding-detail"><code class="code-evidence">' + escapeHtml(item.evidence || "No source excerpt available") + '</code><p><strong>Boundary</strong> ' + escapeHtml(item.boundary || "Review surrounding code and controls.") + '</p><p><strong>Possible impact</strong> ' + escapeHtml(item.impact || "Depends on the surrounding call path and deployment controls.") + '</p><p><strong>Suggested fix</strong> ' + escapeHtml(item.fix || "Verify the source path and apply the narrowest effective control.") + '</p>' + triageControlMarkup(findingId, triageMap) + '</div>';
  }
  return '<article class="finding-card"><div class="finding-top"><h3>' + heading + '</h3></div><div class="finding-meta">' + (isCve ? '<span>' + escapeHtml(item.package) + ' ' + escapeHtml(item.version) + '</span>' : '<span>' + idMarkup + '</span>') + chip + '</div>' + detail + '</article>';
}

function renderReport(result) {
  const cves = result.cveFindings || [];
  const findings = result.sourceFindings || [];
  const summary = result.summary || {};
  const coverage = result.coverage || {};
  const modelReview = result.modelReview || {};
  const cveLookup = result.cveLookup || {};
  const audit = result.audit || null;
  const triageMap = result.triage || {};
  const sandbox = result.sandbox || { state: "not-requested", reason: "No Docker test result was saved." };
  const cveSection = cves.length ? cves.map(item => findingCard(item, true, triageMap)).join("") : '<div class="finding-empty">' + escapeHtml(cveLookup.state === "complete" ? "No known affected package versions were returned for the exact versions inventoried." : cveLookup.state === "off" ? "Online CVE lookup was turned off for this review." : cveLookup.message || "No CVE matches were returned.") + '</div>';
  const sourceSection = findings.length ? findings.map(item => findingCard(item, false, triageMap)).join("") : '<div class="finding-empty">No source candidates were flagged by the configured checks or selected model.</div>';
  const mentions = result.cveMentions && result.cveMentions.length ? '<div class="report-subsection"><h4>CVEs named in source text</h4><div class="mention-list">' + result.cveMentions.map(item => '<div class="mention-row"><span>' + escapeHtml(item.id) + '</span><span>' + escapeHtml(item.path) + ':' + escapeHtml(item.line) + '</span></div>').join("") + '</div><p class="coverage-gaps">A CVE mentioned in a file is not a dependency match by itself.</p></div>' : "";
  const sourceLabel = result.source && result.source.label || "Project review";
  const sourceAddress = result.source && result.source.kind === "git" ? result.source.url : "Local project folder";
  const skipped = coverage.skipped || {};
  const auditFindings = audit && Array.isArray(audit.findings) ? audit.findings : [];
  const auditUnits = audit && Array.isArray(audit.coverage_ledger) ? audit.coverage_ledger : [];
  const auditPhases = audit && Array.isArray(audit.phases) ? audit.phases : [];
  const auditCounts = Object.fromEntries(["covered", "candidate", "blocked", "deferred", "out_of_scope"].map(state => [state, auditUnits.filter(unit => unit.status === state).length]));
  const auditRecords = auditFindings.length ? auditFindings.map(item => {
    const trace = (item.trace || []).map(step => '<div class="audit-trace-row"><span>' + escapeHtml(step.kind) + '</span><strong>' + escapeHtml(step.file) + ':' + escapeHtml(step.line) + '</strong><small>' + escapeHtml(step.description) + '</small></div>').join("");
    const blockers = item.verdict === "needs_validation" ? '<div class="finding-detail"><p><strong>Why it is unresolved</strong></p><ul>' + (item.blockers || []).map(text => '<li>' + escapeHtml(text) + '</li>').join("") + '</ul><p><strong>Next safe check</strong></p><ul>' + Object.values(item.validation_plan || {}).map(text => '<li>' + escapeHtml(text) + '</li>').join("") + '</ul>' + triageControlMarkup(item.fingerprint, triageMap) + '</div>' : '<div class="finding-detail"><p><strong>Disposition</strong> ' + escapeHtml(item.reason || "Source review did not support this claim.") + '</p></div>';
    return '<article class="finding-card audit-record"><div class="finding-top"><h3>' + escapeHtml(item.title) + '</h3></div><div class="finding-meta"><span>' + escapeHtml(item.fingerprint) + '</span><span class="state-chip" data-state-chip="' + escapeHtml(item.fingerprint) + '">' + escapeHtml((triageMap[item.fingerprint]?.status || item.verdict).replaceAll("_", " ")) + '</span></div><div class="audit-trace">' + trace + '</div>' + blockers + '</article>';
  }).join("") : '<div class="finding-empty">' + (audit ? "No structured candidates were retained by the independent review passes." : "The six-phase workflow did not produce audit artifacts.") + '</div>';
  const providerNames = { ollama: "Ollama", mlx: "Apple MLX", "apple-fm": "Apple Foundation Models", codex: "Codex CLI", "gemini-cli": "Gemini CLI" };
  const modelProviderName = providerNames[modelReview.provider] || providerNames[modelReview.selectedProvider] || "No model selected";
  const modelDisclosure = ["codex", "gemini-cli"].includes(modelReview.provider)
    ? `Reviewer prompts with selected source excerpts were sent through ${modelProviderName} using its sign-in on this device. No Kavach API key was used.`
    : ["ollama", "mlx", "apple-fm"].includes(modelReview.provider)
      ? `Reviewer roles were sent as separate prompts to ${modelProviderName} on this device.`
      : "No model request was sent for this review.";
  const auditSection = audit ? '<section class="report-section audit-section"><div class="report-section-head"><div><span class="section-kicker">Cloudflare skill, local adaptation</span><h2>Six-phase audit record</h2></div><span class="state-chip audit-status ' + (audit.run_status === "complete" ? "complete" : "incomplete") + '">' + escapeHtml(audit.run_status === "complete" ? "Complete" : "Incomplete") + '</span></div><p class="audit-disclosure">' + escapeHtml(modelDisclosure + " Optional existing Node tests use a bounded Docker container; passing tests do not establish that the project is safe.") + '</p><div class="audit-phase-list">' + auditPhases.map(item => '<div class="audit-phase"><strong>' + escapeHtml(item.label) + '</strong><small>' + escapeHtml(item.status) + (item.detail ? ': ' + escapeHtml(item.detail) : '') + '</small></div>').join("") + '</div><div class="audit-counts">' + Object.entries(auditCounts).map(([key, value]) => '<div><span>' + escapeHtml(key.replaceAll("_", " ")) + '</span><strong>' + value + '</strong></div>').join("") + '</div>' + (audit.incomplete_reasons && audit.incomplete_reasons.length ? '<div class="coverage-gaps"><strong>Incomplete run:</strong><ul>' + audit.incomplete_reasons.map(reason => '<li>' + escapeHtml(reason) + '</li>').join("") + '</ul></div>' : '') + '<div class="report-section-head audit-findings-head"><h2>Structured audit candidates</h2><span class="section-count">' + auditFindings.length + ' records</span></div><div class="finding-list">' + auditRecords + '</div></section>' : '';
  const sandboxRows = (sandbox.checks || []).map(check => '<div class="sandbox-check"><span class="state-chip">' + escapeHtml(check.state) + '</span><strong>' + escapeHtml(check.path) + '</strong>' + (check.output ? '<pre>' + escapeHtml(check.output) + '</pre>' : '') + '</div>').join("");
  const sandboxSection = '<section class="report-section sandbox-section"><div class="report-section-head"><div><span class="section-kicker">Isolated Node tests</span><h2>Docker sandbox</h2></div><span class="state-chip ' + (sandbox.state === "complete" ? "complete" : "incomplete") + '">' + escapeHtml(sandbox.state) + '</span></div><p class="audit-disclosure">' + escapeHtml(sandbox.reason || (sandbox.image ? sandbox.image + ", no network, read-only project files, resource-limited" : "Only supported existing Node tests are considered. Builds, installs, and project scripts are never run.")) + '</p><div class="sandbox-check-list">' + (sandboxRows || '<div class="finding-empty">' + escapeHtml(sandbox.reason || "No supported Node test files were run.") + '</div>') + '</div></section>';
  const reportContent = [
    '<div class="report-head"><div><h1>' + escapeHtml(sourceLabel) + ' report</h1><p class="report-source">' + escapeHtml(sourceAddress) + (result.source && result.source.revision ? '<br>Revision ' + escapeHtml(result.source.revision) : "") + (result.source?.subpaths?.length ? ', scope: ' + escapeHtml(result.source.subpaths.join(", ")) : "") + ', created ' + escapeHtml(new Date().toLocaleString()) + '</p></div><div class="report-actions"><button class="button button-outline" type="button" id="download-report">Download Markdown</button><button class="button button-outline" type="button" id="download-sarif">Download SARIF</button>' + (audit ? '<button class="button button-outline" type="button" id="download-audit-bundle">Download audit files (.zip)</button>' : '') + '<button class="button button-outline" type="button" id="print-report">Print / save PDF</button><button class="button button-primary report-to-new" type="button">New review</button></div></div>',
    '<div class="report-history-note" id="report-history-note">' + escapeHtml(result.history?.message || "This report is held in this workspace until it is saved.") + '</div>',
    '<div class="report-summary"><div class="summary-cell"><span>Readable files</span><strong>' + Number(summary.filesRead || 0).toLocaleString() + '</strong><small>within this review’s limits</small></div><div class="summary-cell"><span>Versions inventoried</span><strong>' + Number(summary.dependencies || 0).toLocaleString() + '</strong><small>supported manifests and lockfiles</small></div><div class="summary-cell"><span>Known affected matches</span><strong>' + Number(summary.knownAffected || 0).toLocaleString() + '</strong><small>from OSV advisory data</small></div><div class="summary-cell"><span>Review candidates</span><strong>' + Number(summary.candidates || 0).toLocaleString() + '</strong><small>pattern leads and structured audit leads</small></div></div>',
    '<div class="report-layout"><div class="report-results"><section class="report-section"><div class="report-section-head"><h2>Known affected dependencies</h2><span class="section-count">' + cves.length.toLocaleString() + ' matches</span></div><div class="finding-list">' + cveSection + '</div></section><section class="report-section"><div class="report-section-head"><h2>Deterministic source leads</h2><span class="section-count">' + findings.length.toLocaleString() + ' need validation</span></div><div class="finding-list">' + sourceSection + '</div>' + mentions + '</section></div>',
    '<aside class="report-rail"><div class="report-rail-card dark"><span class="section-kicker">Read this first</span><h3>Not a safety certificate.</h3><p>A source-only pass can surface issues. It cannot establish runtime exploitability or prove that a project is safe.</p><span class="method-status">Cloudflare source-first method, adapted</span></div><div class="report-rail-card"><span class="section-kicker">Coverage ledger</span><h3>What was read</h3><div class="coverage-stat"><span>Readable files</span><strong>' + Number(coverage.filesRead || 0).toLocaleString() + '</strong></div><div class="coverage-stat"><span>Source text</span><strong>' + (Number(coverage.totalBytes || 0) / 1024).toFixed(0) + ' KB</strong></div><div class="coverage-stat"><span>Dependencies</span><strong>' + Number(summary.dependencies || 0).toLocaleString() + '</strong></div><div class="coverage-stat"><span>Binary files skipped</span><strong>' + Number(skipped.binary || 0).toLocaleString() + '</strong></div><div class="coverage-stat"><span>Files above 1 MB</span><strong>' + Number(skipped.large || 0).toLocaleString() + '</strong></div><div class="coverage-stat"><span>Generated/cache paths</span><strong>' + Number(skipped.ignored || 0).toLocaleString() + '</strong></div><div class="coverage-stat"><span>Symlinks or unreadable</span><strong>' + (Number(skipped.links || 0) + Number(skipped.errors || 0)).toLocaleString() + '</strong></div>' + (coverage.truncated ? '<p class="coverage-gaps">The scan hit a local file or byte limit; remaining files are outside this report.</p>' : '<div class="coverage-stat"><span>Scan limits reached</span><strong>no</strong></div>') + '</div><div class="report-rail-card"><span class="section-kicker">Model review: ' + escapeHtml(modelProviderName) + '</span><h3>' + escapeHtml(modelReview.state || "not requested") + '</h3><p>' + escapeHtml(modelReview.message || "Not requested.") + '</p></div><div class="report-rail-card"><span class="section-kicker">CVE database</span><h3>OSV: ' + escapeHtml(cveLookup.state || "unknown") + '</h3><p>' + escapeHtml(cveLookup.message || "No lookup details.") + '</p><div class="coverage-stat"><span>Exact versions checked</span><strong>' + Number(cveLookup.checked || 0).toLocaleString() + '</strong></div><div class="coverage-stat"><span>Advisories found</span><strong>' + Number(cveLookup.advisoryCount || 0).toLocaleString() + '</strong></div></div><div class="report-rail-card"><span class="section-kicker">Docker tests</span><h3>' + escapeHtml(sandbox.state || "unknown") + '</h3><p>' + escapeHtml(sandbox.reason || (sandbox.checks || []).length + " supported Node tests recorded.") + '</p></div><div class="report-restart"><button class="button button-outline report-to-new" type="button">Start another review</button></div></aside></div>',
    auditSection,
    sandboxSection
  ].join("");
  $("report-content").innerHTML = reportContent;
}

function downloadSarif() {
  if (!currentResult) return;
  const label = (currentResult.source && currentResult.source.label || "project-review").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "project-review";
  const sarif = buildSarif(currentResult);
  const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: "application/sarif+json;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = label + ".sarif.json";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function downloadMarkdown() {
  if (!currentResult || !currentResult.report) return;
  const label = (currentResult.source && currentResult.source.label || "project-review").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "project-review";
  const blob = new Blob([currentResult.report], { type: "text/markdown;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = label + "-safety-review.md";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function downloadAuditBundle() {
  if (!currentResult || !currentResult.audit) return;
  const label = (currentResult.source && currentResult.source.label || "project-audit").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "project-audit";
  const blob = makeZip(currentResult.audit.artifacts || {});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = label + "-audit-artifacts.zip";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit += 1) value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function makeZip(files) {
  const encoder = new TextEncoder();
  const entries = Object.entries(files).map(([name, content]) => ({ name: encoder.encode(name), data: encoder.encode(String(content)) }));
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const now = new Date();
  const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | Math.floor(now.getSeconds() / 2);
  const dosDate = ((Math.max(1980, now.getFullYear()) - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  for (const entry of entries) {
    const checksum = crc32(entry.data);
    const local = new Uint8Array(30 + entry.name.length);
    const localView = new DataView(local.buffer);
    localView.setUint32(0, 0x04034b50, true);
    localView.setUint16(4, 20, true);
    localView.setUint16(6, 0x0800, true);
    localView.setUint16(8, 0, true);
    localView.setUint16(10, dosTime, true);
    localView.setUint16(12, dosDate, true);
    localView.setUint32(14, checksum, true);
    localView.setUint32(18, entry.data.length, true);
    localView.setUint32(22, entry.data.length, true);
    localView.setUint16(26, entry.name.length, true);
    local.set(entry.name, 30);
    localParts.push(local, entry.data);

    const central = new Uint8Array(46 + entry.name.length);
    const centralView = new DataView(central.buffer);
    centralView.setUint32(0, 0x02014b50, true);
    centralView.setUint16(4, 20, true);
    centralView.setUint16(6, 20, true);
    centralView.setUint16(8, 0x0800, true);
    centralView.setUint16(10, 0, true);
    centralView.setUint16(12, dosTime, true);
    centralView.setUint16(14, dosDate, true);
    centralView.setUint32(16, checksum, true);
    centralView.setUint32(20, entry.data.length, true);
    centralView.setUint32(24, entry.data.length, true);
    centralView.setUint16(28, entry.name.length, true);
    centralView.setUint32(42, offset, true);
    central.set(entry.name, 46);
    centralParts.push(central);
    offset += local.length + entry.data.length;
  }
  const centralSize = centralParts.reduce((total, part) => total + part.length, 0);
  const end = new Uint8Array(22);
  const endView = new DataView(end.buffer);
  endView.setUint32(0, 0x06054b50, true);
  endView.setUint16(8, entries.length, true);
  endView.setUint16(10, entries.length, true);
  endView.setUint32(12, centralSize, true);
  endView.setUint32(16, offset, true);
  return new Blob([...localParts, ...centralParts, end], { type: "application/zip" });
}

function renderReports() {
  $("report-count").textContent = String(reports.length);
  const container = $("reports-list");
  if (!reports.length) {
    container.innerHTML = '<div class="empty-reports"><span class="empty-mark" aria-hidden="true">F.</span><strong>No saved reports yet.</strong><p>Completed reviews are saved in local PostgreSQL for this Firebase account. Source files are never stored in the report history.</p></div>';
    return;
  }
  container.innerHTML = reports.map((entry, index) => {
    const result = entry.result || {};
    const summary = result.summary || entry.summary || {};
    const source = result.source || entry.source || {};
    return '<div class="report-row"><span class="report-row-index">' + String(index + 1).padStart(2, "0") + '</span><div class="report-row-title"><strong>' + escapeHtml(source.label || "Project review") + '</strong><span>' + escapeHtml(source.kind === "git" ? source.url : "Local project folder") + ', ' + escapeHtml(new Date(entry.createdAt).toLocaleString()) + '</span></div><span class="report-row-count">' + Number(summary.knownAffected || 0) + ' CVEs, ' + Number(summary.candidates || 0) + ' review leads</span><div class="report-row-actions"><button type="button" data-open-report="' + escapeHtml(entry.id) + '">Open report</button><button type="button" class="report-delete-button" data-delete-report="' + escapeHtml(entry.id) + '" aria-label="Delete saved report">Delete</button></div></div>';
  }).join("");
}

async function deleteSavedReport(id) {
  if (!id) return;
  try {
    const response = await authorizedFetch("/api/runs/" + encodeURIComponent(id), { method: "DELETE" });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || "Could not delete the saved report.");
    }
    reports = reports.filter(item => item.id !== id);
    if (currentResult?.id === id) currentResult = null;
    renderReports();
  } catch (error) {
    showError(error.message || "Could not delete the saved report.");
  }
}

async function saveFindingTriage(findingId, button) {
  if (!currentResult?.id || !findingId) return;
  const select = document.querySelector(`[data-triage-select="${CSS.escape(findingId)}"]`);
  const noteInput = document.querySelector(`[data-triage-note="${CSS.escape(findingId)}"]`);
  const status = select ? select.value : "needs_validation";
  const note = noteInput ? noteInput.value.trim() : "";
  if (button) {
    button.disabled = true;
    button.textContent = "Saving…";
  }
  try {
    const response = await authorizedFetch("/api/runs/" + encodeURIComponent(currentResult.id) + "/triage", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ findingId, status, note })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not save triage decision.");
    currentResult.triage = data.triage || {};
    const chip = document.querySelector(`[data-state-chip="${CSS.escape(findingId)}"]`);
    if (chip) {
      const label = status === "verified_safe" ? "Verified safe" : status === "confirmed_issue" ? "Confirmed issue" : status === "ignored" ? "Ignored" : "Needs validation";
      chip.textContent = label;
      chip.classList.toggle("complete", status === "verified_safe");
    }
    if (button) button.textContent = "Saved";
    setTimeout(() => { if (button) button.textContent = "Save note"; }, 1200);
  } catch (error) {
    if ($("report-history-note")) $("report-history-note").textContent = error.message || "Triage note could not be saved.";
    if (button) button.textContent = "Save note";
  } finally {
    if (button) button.disabled = false;
  }
}

async function refreshReports() {
  if (!currentUser) return;
  const response = await authorizedFetch("/api/runs");
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401) { showSignedOutWorkspace("Your Firebase session ended. Sign in again to continue."); return; }
    throw new Error(data.error || "Saved reviews could not be loaded.");
  }
  const cached = new Map(reports.map(item => [item.id, item]));
  reports = (data.runs || []).map(row => cached.get(row.id) || ({
    id: row.id,
    createdAt: row.created_at,
    source: { kind: row.source_kind, label: row.project_name, url: row.source_url, revision: row.source_ref },
    summary: row.summary,
    result: null
  }));
  renderReports();
}

async function openLatestReport() {
  try {
    if (!reports.length) await refreshReports();
    const latest = reports[0];
    if (!latest) {
      showError("There are no saved reports to open yet.");
      return;
    }
    await openSavedReport(latest.id);
  } catch (error) {
    showError(error.message || "The latest saved report could not be opened.");
  }
}

async function openSavedReport(id) {
  const entry = reports.find(row => row.id === id);
  if (!entry) return;
  try {
    let result = entry.result;
    if (!result || !result.report) {
      const response = await authorizedFetch("/api/runs/" + encodeURIComponent(id));
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The saved review could not be opened.");
      result = data.result;
      entry.result = result;
      entry.createdAt = data.createdAt || entry.createdAt;
    }
    currentResult = result;
    renderReport(result);
    showView("report");
  } catch (error) {
    showView("reports");
    const message = error.message || "The saved review could not be opened.";
    const list = $("reports-list");
    if (list) {
      list.insertAdjacentHTML("afterbegin", '<div class="form-error" role="alert">' + escapeHtml(message) + '</div>');
    }
  }
}

document.querySelectorAll("[data-view]").forEach(button => {
  button.addEventListener("click", () => {
    if (button.dataset.view === "review") {
      currentResult = null;
      $("scanner-form").classList.remove("hidden");
      showView("review");
      return;
    }
    showView(button.dataset.view);
    if (button.dataset.view === "reports") refreshReports().catch(error => {
      $("reports-list").innerHTML = '<div class="empty-reports"><strong>Saved reviews are unavailable.</strong><p>' + escapeHtml(error.message) + '</p></div>';
    });
  });
});

document.querySelectorAll("[data-source-tab]").forEach(button => button.addEventListener("click", () => setSourceMode(button.dataset.sourceTab)));
$("choose-folder").addEventListener("click", chooseFolder);
$("folder-input").addEventListener("change", handleFolderInput);
$("start-scan").addEventListener("click", startScan);
if ($("cancel-scan")) $("cancel-scan").addEventListener("click", cancelActiveScan);
if ($("git-branch")) $("git-branch").addEventListener("input", updateScopeSummaryNote);
if ($("scope-subpaths")) $("scope-subpaths").addEventListener("input", updateScopeSummaryNote);
$("refresh-models").addEventListener("click", () => refreshModels());
if ($("open-latest-report")) $("open-latest-report").addEventListener("click", openLatestReport);
$("provider-select").addEventListener("input", handleProviderSelection);
$("provider-select").addEventListener("change", handleProviderSelection);
$("provider-select").addEventListener("focusout", handleProviderSelection);
$("provider-select").addEventListener("pointerup", () => queueMicrotask(handleProviderSelection));
$("provider-select").addEventListener("keyup", () => queueMicrotask(handleProviderSelection));
$("model-base").addEventListener("change", () => { rememberSettings(); refreshModels(); });
$("model-select").addEventListener("change", rememberSettings);
$("use-local-model").addEventListener("change", () => { updateProviderPresentation(); rememberSettings(); });
$("check-osv").addEventListener("change", rememberSettings);
$("run-docker-tests").addEventListener("change", rememberSettings);
$("audit-profile").addEventListener("change", rememberSettings);
$("audit-budget").addEventListener("change", rememberSettings);
$("audit-budget").addEventListener("input", rememberSettings);
$("git-url").addEventListener("keydown", event => { if (event.key === "Enter") startScan(); });

$("auth-mode-toggle").addEventListener("click", () => {
  authMode = authMode === "signin" ? "create" : "signin";
  updateAuthMode();
  setAuthMessage(authMode === "create" ? "A verification email is required before signing in." : "Sign in with your verified Firebase account.");
});

$("auth-reset").addEventListener("click", async () => {
  const email = $("auth-email").value.trim();
  if (!email) { setAuthMessage("Enter your email address first, then request a reset link.", "error"); $("auth-email").focus(); return; }
  try {
    await sendPasswordReset(email);
    setAuthMessage("If Firebase has an account for that address, it will send a password reset email.", "success");
  } catch (error) { setAuthMessage(error.message || "The reset email could not be sent.", "error"); }
});

$("auth-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (!authReady) return;
  const submit = $("auth-submit");
  submit.disabled = true;
  setAuthMessage(authMode === "create" ? "Creating your Firebase account…" : "Signing in…");
  try {
    const email = $("auth-email").value.trim();
    const password = $("auth-password").value;
    if (authMode === "create") {
      await createAccount(email, password);
      setAuthMessage("Account created. Open the verification email Firebase sent, then sign in.", "success");
      $("auth-password").value = "";
    } else {
      await signIn(email, password);
      setAuthMessage("Signed in. Loading your private workspace…", "success");
    }
  } catch (error) {
    setAuthMessage(error.message || "Firebase could not complete that request.", "error");
  } finally {
    submit.disabled = !authReady;
  }
});

$("sign-out").addEventListener("click", async () => {
  await signOutUser();
  showSignedOutWorkspace("You have signed out.");
});

document.addEventListener("click", event => {
  const download = event.target.closest("#download-report");
  if (download) { downloadMarkdown(); return; }
  const sarif = event.target.closest("#download-sarif");
  if (sarif) { downloadSarif(); return; }
  const print = event.target.closest("#print-report");
  if (print) { window.print(); return; }
  const auditBundle = event.target.closest("#download-audit-bundle");
  if (auditBundle) { downloadAuditBundle(); return; }
  const newReview = event.target.closest(".report-to-new");
  if (newReview) {
    currentResult = null;
    $("scanner-form").classList.remove("hidden");
    showView("review");
    return;
  }
  const open = event.target.closest("[data-open-report]");
  if (open) { openSavedReport(open.dataset.openReport); return; }
  const del = event.target.closest("[data-delete-report]");
  if (del) { deleteSavedReport(del.dataset.deleteReport); return; }
  const triageSave = event.target.closest("[data-triage-save]");
  if (triageSave) { saveFindingTriage(triageSave.dataset.triageSave, triageSave); }
});

async function activateFirebaseUser(user) {
  if (!user) {
    if (currentUser) showSignedOutWorkspace();
    else {
      $("app-shell").classList.add("hidden");
      $("auth-gate").classList.remove("hidden");
    }
    return;
  }
  if (!user.emailVerified) {
    await signOutUser();
    showSignedOutWorkspace("Verify your email using the Firebase message before signing in.");
    return;
  }
  if (currentUser?.uid === user.uid) return;
  showAuthenticatedWorkspace(user);
  loadSettings();
  try {
    const response = await authorizedFetch("/api/auth/me");
    if (!response.ok) throw new Error("The local workspace could not verify this Firebase session.");
  } catch (error) {
    await signOutUser();
    showSignedOutWorkspace(error.message || "Please sign in again.");
    return;
  }
  try {
    const preferences = await loadPreferences(user);
    if (preferences) applyPreferences(preferences);
    servicePill("firestore-status", "Firestore", "connected", "Only this account’s preferences are stored in Firestore.");
    if (!preferences) await persistProfileSettings();
  } catch (error) {
    servicePill("firestore-status", "Firestore", "blocked", error.message || "Firestore preferences are unavailable.");
  }
  providerSyncReady = true;
  const modelsPromise = refreshModels();
  await refreshInfrastructure();
  if (postgresAvailable) {
    try { await refreshReports(); }
    catch (error) { renderReports(); }
  } else renderReports();
  await modelsPromise;
  rememberSettings();
  syncProviderStatus();
  await resumeActiveJob(user);
}

(async function startWorkspace() {
  try {
    const result = await initializeFirebase();
    if (!result.configured) {
      setAuthMessage("Firebase is not configured. Set FIREBASE_PROJECT_ID, FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN, and FIREBASE_APP_ID in the local .env file.", "error");
      return;
    }
    authReady = true;
    $("auth-submit").disabled = false;
    $("auth-reset").disabled = false;
    $("auth-mode-toggle").disabled = false;
    setAuthMessage("Sign in with your verified Firebase account.");
    updateAuthMode();
    onFirebaseUser(user => activateFirebaseUser(user).catch(error => {
      showSignedOutWorkspace(error.message || "The private workspace could not be opened.");
    }));
  } catch (error) {
    setAuthMessage(error.message || "Firebase could not be reached. Check the local setup and internet connection.", "error");
  }
})();

loadSettings();
renderReports();
setInterval(syncProviderStatus, 500);
