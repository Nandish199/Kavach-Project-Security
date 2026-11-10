const SESSION_KEY = "fieldnote.firebase.session";
const authMessages = {
  EMAIL_EXISTS: "An account with this email already exists. Sign in instead.",
  INVALID_LOGIN_CREDENTIALS: "The email or password is incorrect.",
  EMAIL_NOT_FOUND: "The email or password is incorrect.",
  INVALID_PASSWORD: "The email or password is incorrect.",
  USER_DISABLED: "This account is disabled. Contact the workspace administrator.",
  OPERATION_NOT_ALLOWED: "Email and password sign-in is not enabled in the Firebase project.",
  TOO_MANY_ATTEMPTS_TRY_LATER: "Firebase temporarily paused sign-in attempts. Try again later.",
  WEAK_PASSWORD: "Choose a stronger password with at least 8 characters.",
  INVALID_EMAIL: "Enter a valid email address.",
  INVALID_ID_TOKEN: "Your Firebase session ended. Sign in again.",
  TOKEN_EXPIRED: "Your Firebase session ended. Sign in again.",
  INVALID_REFRESH_TOKEN: "Your Firebase session ended. Sign in again.",
  PROJECT_NUMBER_MISMATCH: "The Firebase session belongs to a different project. Sign in again.",
  NETWORK_REQUEST_FAILED: "Firebase could not be reached. Check this device’s internet connection and try again."
};

let config = null;
let session = null;
const listeners = new Set();

function readableAuthError(error) {
  const raw = String(error?.error?.message || error?.message || "");
  const code = raw.split(/[ :]/)[0];
  return authMessages[code] || raw || "Firebase could not complete that request.";
}

async function authRequest(action, body) {
  if (!config?.apiKey) throw new Error("Firebase is not configured.");
  let response;
  try {
    response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:${action}?key=${encodeURIComponent(config.apiKey)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(12000)
    });
  } catch {
    throw new Error(authMessages.NETWORK_REQUEST_FAILED);
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(readableAuthError(payload));
  return payload;
}

function savedSession() {
  try {
    const value = JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
    if (value?.idToken && value?.refreshToken && value?.expiresAt && value?.user?.uid) return value;
  } catch {}
  return null;
}

function storeSession(value) {
  session = value;
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(value)); } catch {}
}

function clearSession(notify = true) {
  session = null;
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
  if (notify) for (const listener of listeners) listener(null);
}

async function lookupAccount(idToken) {
  const result = await authRequest("lookup", { idToken });
  const account = result.users?.[0];
  if (!account) throw new Error("Firebase could not find this account.");
  return {
    uid: String(account.localId || ""),
    email: String(account.email || "").slice(0, 320),
    emailVerified: account.emailVerified === true
  };
}

async function refreshSession() {
  if (!session?.refreshToken || !config?.apiKey) throw new Error("Sign in again to continue.");
  let response;
  try {
    response = await fetch(`https://securetoken.googleapis.com/v1/token?key=${encodeURIComponent(config.apiKey)}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: session.refreshToken }),
      signal: AbortSignal.timeout(12000)
    });
  } catch { throw new Error(authMessages.NETWORK_REQUEST_FAILED); }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(readableAuthError(payload));
  session.idToken = payload.id_token;
  session.refreshToken = payload.refresh_token;
  session.expiresAt = Date.now() + Math.max(60, Number(payload.expires_in) || 3600) * 1000;
  storeSession(session);
}

async function usableIdToken() {
  if (!session?.idToken) return "";
  if (session.expiresAt < Date.now() + 120000) {
    try { await refreshSession(); }
    catch (error) { clearSession(); throw error; }
  }
  return session?.idToken || "";
}

export async function initializeFirebase() {
  const response = await fetch("/api/auth/config", { cache: "no-store", signal: AbortSignal.timeout(10000) });
  const value = await response.json();
  if (!response.ok || !value.configured) return { configured: false, config: value };
  config = value;
  session = savedSession();
  if (session) {
    try {
      if (session.expiresAt < Date.now() + 120000) await refreshSession();
      const user = await lookupAccount(session.idToken);
      if (!user.emailVerified || user.uid !== session.user.uid) clearSession(false);
      else { session.user = user; storeSession(session); }
    } catch { clearSession(false); }
  }
  return { configured: true, config };
}

export function onFirebaseUser(callback) {
  listeners.add(callback);
  queueMicrotask(() => callback(session?.user || null));
  return () => listeners.delete(callback);
}

export async function createAccount(email, password) {
  const created = await authRequest("signUp", { email: email.trim(), password, returnSecureToken: true });
  await authRequest("sendOobCode", { requestType: "VERIFY_EMAIL", idToken: created.idToken });
  clearSession(false);
}

export async function signIn(email, password) {
  let result;
  try {
    result = await authRequest("signInWithPassword", { email: email.trim(), password, returnSecureToken: true });
    const user = await lookupAccount(result.idToken);
    if (!user.emailVerified) {
      await authRequest("sendOobCode", { requestType: "VERIFY_EMAIL", idToken: result.idToken }).catch(() => {});
      throw new Error("Verify your email first. Firebase sent a verification link to your inbox.");
    }
    session = {
      idToken: result.idToken,
      refreshToken: result.refreshToken,
      expiresAt: Date.now() + Math.max(60, Number(result.expiresIn) || 3600) * 1000,
      user
    };
    storeSession(session);
    for (const listener of listeners) listener(user);
    return user;
  } catch (error) { throw new Error(readableAuthError(error)); }
}

export async function signOutUser() { clearSession(); }

export async function currentIdToken() { return usableIdToken(); }

function preferencesDocument(preferences) {
  const provider = preferences.provider === "openai" ? "codex" : preferences.provider === "gemini" ? "gemini-cli" : preferences.provider;
  return {
    provider: ["ollama", "mlx", "apple-fm", "codex", "gemini-cli"].includes(provider) ? provider : "ollama",
    modelBase: String(preferences.modelBase || "").slice(0, 512),
    model: String(preferences.model || "").slice(0, 160),
    useLocalModel: Boolean(preferences.useLocalModel),
    checkOsv: Boolean(preferences.checkOsv),
    runDockerTests: Boolean(preferences.runDockerTests)
  };
}

function firestoreDocumentPath(uid) {
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(config.projectId)}/databases/(default)/documents/fieldnoteProfiles/${encodeURIComponent(uid)}`;
}

function decodeFirestoreValue(value) {
  if (!value || typeof value !== "object") return null;
  if ("stringValue" in value) return value.stringValue;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return Number(value.doubleValue);
  if ("timestampValue" in value) return value.timestampValue;
  if ("mapValue" in value) return Object.fromEntries(Object.entries(value.mapValue.fields || {}).map(([key, item]) => [key, decodeFirestoreValue(item)]));
  return null;
}

function encodeFirestoreValue(value) {
  if (typeof value === "boolean") return { booleanValue: value };
  if (typeof value === "number") return Number.isInteger(value) ? { integerValue: String(value) } : { doubleValue: value };
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return { mapValue: { fields: Object.fromEntries(Object.entries(value).map(([key, item]) => [key, encodeFirestoreValue(item)])) } };
  }
  return { stringValue: String(value ?? "") };
}

async function firestoreRequest(method, url, body) {
  const idToken = await usableIdToken();
  if (!idToken) throw new Error("Sign in again before syncing preferences.");
  let response;
  try {
    response = await fetch(url, {
      method,
      headers: { authorization: "Bearer " + idToken, ...(body ? { "content-type": "application/json" } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(12000)
    });
  } catch { throw new Error("Firestore could not be reached. Check this device’s internet connection."); }
  const payload = await response.json().catch(() => ({}));
  if (method === "GET" && response.status === 404) return { _notFound: true };
  if (!response.ok) {
    const message = payload.error?.message || "Firestore rejected this request.";
    if (response.status === 403) throw new Error("Firestore rules did not allow this account to sync its preferences.");
    if (response.status === 401) { clearSession(); throw new Error("Your Firebase session ended. Sign in again."); }
    throw new Error(String(message).slice(0, 240));
  }
  return payload;
}

export async function loadPreferences(user) {
  const payload = await firestoreRequest("GET", firestoreDocumentPath(user.uid));
  if (payload._notFound) return null;
  const preferences = decodeFirestoreValue(payload.fields?.preferences);
  return preferences && typeof preferences === "object" ? preferences : null;
}

export async function savePreferences(user, preferences) {
  const url = new URL(firestoreDocumentPath(user.uid));
  url.searchParams.append("updateMask.fieldPaths", "uid");
  url.searchParams.append("updateMask.fieldPaths", "preferences");
  const data = {
    name: `projects/${config.projectId}/databases/(default)/documents/fieldnoteProfiles/${user.uid}`,
    fields: {
      uid: { stringValue: user.uid },
      preferences: encodeFirestoreValue(preferencesDocument(preferences))
    }
  };
  await firestoreRequest("PATCH", url.toString(), data);
}

export async function sendPasswordReset(email) {
  await authRequest("sendOobCode", { requestType: "PASSWORD_RESET", email: email.trim() });
}
