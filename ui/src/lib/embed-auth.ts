// ui/src/lib/embed-auth.ts
import { setEmbedToken } from "../api/client";

// --- Types ---

export type EmbedTheme = "light" | "dark";

export type EmbedAuthMessage =
  | { type: "BUCKGURU_OPERATIONS_AUTH"; token: string; theme?: EmbedTheme }
  | { type: "BUCKGURU_OPERATIONS_TOKEN_REFRESH"; token: string; theme?: EmbedTheme }
  | { type: "BUCKGURU_OPERATIONS_THEME"; theme: EmbedTheme };

type EmbedAuthState = {
  authenticated: boolean;
  user: { id: string; email: string; name: string } | null;
  theme: EmbedTheme | null;
};

type EmbedAuthListener = (state: EmbedAuthState) => void;

// --- Helpers ---

export function isEmbedded(): boolean {
  try {
    return window.self !== window.top;
  } catch {
    return true;
  }
}

function parseTheme(value: unknown): EmbedTheme | undefined {
  return value === "light" || value === "dark" ? value : undefined;
}

export function parseEmbedMessage(data: unknown): EmbedAuthMessage | null {
  if (!data || typeof data !== "object") return null;
  const msg = data as Record<string, unknown>;
  if (typeof msg.type !== "string") return null;

  if (msg.type === "BUCKGURU_OPERATIONS_THEME") {
    const theme = parseTheme(msg.theme);
    if (!theme) return null;
    return { type: "BUCKGURU_OPERATIONS_THEME", theme };
  }

  if (typeof msg.token !== "string") return null;
  const theme = parseTheme(msg.theme);

  if (msg.type === "BUCKGURU_OPERATIONS_AUTH") {
    return { type: "BUCKGURU_OPERATIONS_AUTH", token: msg.token, theme };
  }
  if (msg.type === "BUCKGURU_OPERATIONS_TOKEN_REFRESH") {
    return { type: "BUCKGURU_OPERATIONS_TOKEN_REFRESH", token: msg.token, theme };
  }
  return null;
}

// --- Token exchange ---

async function exchangeToken(
  buckguruJwt: string,
): Promise<{ embedToken: string; user: { id: string; email: string; name: string } } | null> {
  try {
    const res = await fetch("/api/auth/embed", {
      method: "POST",
      credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: buckguruJwt }),
    });
    if (!res.ok) {
      console.error(`[embed-auth] Token exchange failed: ${res.status}`);
      return null;
    }
    return res.json();
  } catch (err) {
    console.error("[embed-auth] Token exchange error:", err);
    return null;
  }
}

// --- Signals to parent ---

function sendToParent(type: string, extra?: Record<string, unknown>) {
  const origin = trustedParentOrigin ?? "*";
  if (origin === "*") {
    console.warn("[embed-auth] sendToParent using '*' — trustedParentOrigin not yet set");
  }
  try {
    window.parent.postMessage({ type, ...extra }, origin);
  } catch {
    // Silently ignore if parent is inaccessible
  }
}

export function sendReady() {
  sendToParent("PAPERCLIP_READY");
}

export function sendTokenExpired() {
  sendToParent("PAPERCLIP_TOKEN_EXPIRED");
}

// --- Main embed auth controller ---

let initialized = false;
let listeners: EmbedAuthListener[] = [];
let trustedParentOrigin: string | null = null;
let currentState: EmbedAuthState = { authenticated: false, user: null, theme: null };

function notifyListeners() {
  for (const listener of listeners) {
    listener(currentState);
  }
}

async function handleBuckguruToken(buckguruJwt: string, theme?: EmbedTheme): Promise<boolean> {
  const result = await exchangeToken(buckguruJwt);
  if (!result) {
    currentState = { authenticated: false, user: null, theme: theme ?? currentState.theme };
    setEmbedToken(null);
    notifyListeners();
    return false;
  }

  setEmbedToken(result.embedToken);
  currentState = { authenticated: true, user: result.user, theme: theme ?? currentState.theme };
  notifyListeners();
  return true;
}

function handleThemeChange(theme: EmbedTheme) {
  currentState = { ...currentState, theme };
  notifyListeners();
}

export function setTrustedParentOrigin(origin: string) {
  trustedParentOrigin = origin;
}

export function initEmbedAuth(): () => void {
  if (initialized) return () => {};
  initialized = true;

  const handler = async (event: MessageEvent) => {
    if (trustedParentOrigin && event.origin !== trustedParentOrigin) {
      return;
    }

    const msg = parseEmbedMessage(event.data);
    if (!msg) return;

    if (!trustedParentOrigin) {
      trustedParentOrigin = event.origin;
    }

    if (msg.type === "BUCKGURU_OPERATIONS_AUTH") {
      const ok = await handleBuckguruToken(msg.token, msg.theme);
      if (ok) {
        sendReady();
      }
    }

    if (msg.type === "BUCKGURU_OPERATIONS_TOKEN_REFRESH") {
      const ok = await handleBuckguruToken(msg.token, msg.theme);
      if (!ok) {
        sendTokenExpired();
      }
    }

    if (msg.type === "BUCKGURU_OPERATIONS_THEME") {
      handleThemeChange(msg.theme);
    }
  };

  window.addEventListener("message", handler);

  return () => {
    window.removeEventListener("message", handler);
    initialized = false;
  };
}

export function onEmbedAuthChange(listener: EmbedAuthListener): () => void {
  listeners.push(listener);
  return () => {
    listeners = listeners.filter((l) => l !== listener);
  };
}

export function getEmbedAuthState(): EmbedAuthState {
  return currentState;
}
