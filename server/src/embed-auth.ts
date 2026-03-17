// server/src/embed-auth.ts
import { createHmac, timingSafeEqual } from "node:crypto";

const JWT_ALGORITHM = "HS256";
const EMBED_TOKEN_TTL_SECONDS = 600; // 10 minutes

// --- BuckGuru JWT claims ---

export interface BuckguruJwtClaims {
  userId: string;
  email: string;
  role: string;
  exp: number;
  iss: string;
}

// --- Paperclip embed token claims ---

export interface EmbedTokenClaims {
  sub: string;
  email: string;
  role: string;
  type: "embed";
  iat: number;
  exp: number;
  iss: string;
}

// --- Shared JWT helpers (same pattern as agent-auth-jwt.ts) ---

function base64UrlEncode(value: string) {
  return Buffer.from(value, "utf8").toString("base64url");
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, "base64url").toString("utf8");
}

function signPayload(secret: string, signingInput: string) {
  return createHmac("sha256", secret).update(signingInput).digest("base64url");
}

function parseJson(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function safeCompare(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

// --- BuckGuru JWT verification ---

function getBuckguruSecret(): string | null {
  const secret = process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET;
  return secret?.trim() || null;
}

export function verifyBuckguruJwt(token: string): BuckguruJwtClaims | null {
  if (!token) return null;
  const secret = getBuckguruSecret();
  if (!secret) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, claimsB64, signature] = parts;

  const header = parseJson(base64UrlDecode(headerB64));
  if (!header || header.alg !== JWT_ALGORITHM) return null;

  const signingInput = `${headerB64}.${claimsB64}`;
  const expectedSig = signPayload(secret, signingInput);
  if (!safeCompare(signature, expectedSig)) return null;

  const claims = parseJson(base64UrlDecode(claimsB64));
  if (!claims) return null;

  const userId = typeof claims.userId === "string" ? claims.userId : null;
  const email = typeof claims.email === "string" ? claims.email : null;
  const role = typeof claims.role === "string" ? claims.role : null;
  const exp = typeof claims.exp === "number" ? claims.exp : null;
  const iss = typeof claims.iss === "string" ? claims.iss : null;

  if (!userId || !email || !role || !exp || !iss) return null;
  if (iss !== "buckguru") return null;

  const now = Math.floor(Date.now() / 1000);
  if (exp < now) return null;

  return { userId, email, role, exp, iss };
}

// --- Paperclip embed token creation/verification ---

function getEmbedSecret(): string | null {
  const secret = process.env.PAPERCLIP_EMBED_JWT_SECRET ?? process.env.PAPERCLIP_AGENT_JWT_SECRET;
  return secret?.trim() || null;
}

export function createEmbedToken(userId: string, email: string, role: string): string | null {
  const secret = getEmbedSecret();
  if (!secret) return null;

  const now = Math.floor(Date.now() / 1000);
  const claims: EmbedTokenClaims = {
    sub: userId,
    email,
    role,
    type: "embed",
    iat: now,
    exp: now + EMBED_TOKEN_TTL_SECONDS,
    iss: "paperclip",
  };

  const header = { alg: JWT_ALGORITHM, typ: "JWT" };
  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(claims))}`;
  const signature = signPayload(secret, signingInput);

  return `${signingInput}.${signature}`;
}

export function verifyEmbedToken(token: string): EmbedTokenClaims | null {
  if (!token) return null;
  const secret = getEmbedSecret();
  if (!secret) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, claimsB64, signature] = parts;

  const header = parseJson(base64UrlDecode(headerB64));
  if (!header || header.alg !== JWT_ALGORITHM) return null;

  const signingInput = `${headerB64}.${claimsB64}`;
  const expectedSig = signPayload(secret, signingInput);
  if (!safeCompare(signature, expectedSig)) return null;

  const claims = parseJson(base64UrlDecode(claimsB64));
  if (!claims) return null;

  const sub = typeof claims.sub === "string" ? claims.sub : null;
  const email = typeof claims.email === "string" ? claims.email : null;
  const role = typeof claims.role === "string" ? claims.role : null;
  const type = claims.type;
  const iat = typeof claims.iat === "number" ? claims.iat : null;
  const exp = typeof claims.exp === "number" ? claims.exp : null;
  const iss = typeof claims.iss === "string" ? claims.iss : null;

  if (!sub || !email || !role || type !== "embed" || !iat || !exp || !iss) return null;

  const now = Math.floor(Date.now() / 1000);
  if (exp < now) return null;

  return { sub, email, role, type: "embed", iat, exp, iss };
}
