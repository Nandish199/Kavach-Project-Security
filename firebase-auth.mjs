import { getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";

function settings() {
  return {
    projectId: String(process.env.FIREBASE_PROJECT_ID || "").trim(),
    apiKey: String(process.env.FIREBASE_API_KEY || "").trim(),
    authDomain: String(process.env.FIREBASE_AUTH_DOMAIN || "").trim(),
    appId: String(process.env.FIREBASE_APP_ID || "").trim()
  };
}

export function firebaseClientConfig() {
  const config = settings();
  return {
    configured: Boolean(config.projectId && config.apiKey && config.authDomain && config.appId),
    ...config
  };
}

function authForVerification() {
  const { projectId } = settings();
  if (!projectId) throw new Error("Firebase project is not configured.");
  let app = getApps().find(item => item.name === "fieldnote-token-verification");
  if (!app) app = initializeApp({ projectId }, "fieldnote-token-verification");
  return getAuth(app);
}

export async function verifyFirebaseIdToken(idToken) {
  if (!idToken || idToken.length > 12000) return null;
  try {
    const claims = await authForVerification().verifyIdToken(idToken);
    if (claims.email_verified !== true) return null;
    return {
      uid: String(claims.uid || claims.sub || ""),
      email: String(claims.email || "").slice(0, 320),
      emailVerified: true
    };
  } catch {
    return null;
  }
}
