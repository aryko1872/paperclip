# BuckGuru Embed Auth (postMessage JWT) Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow BuckGuru to embed Paperclip in an iframe and auto-authenticate users via postMessage JWT injection — no login form, no cookies.

**Architecture:** BuckGuru sends a signed JWT via `postMessage` to the Paperclip iframe. Paperclip's UI receives the JWT (validating `event.origin` against a configured parent origin), exchanges it for a short-lived Paperclip embed token via a new `POST /api/auth/embed` endpoint. The server validates the BuckGuru JWT against a shared secret, provisions the user (find-or-create), and returns an opaque bearer token. All subsequent API calls from the embedded UI use `Authorization: Bearer <embedToken>` instead of cookies. The auth middleware is extended to verify embed tokens alongside existing agent JWTs. The UI sends `PAPERCLIP_READY` and `PAPERCLIP_TOKEN_EXPIRED` signals back to the parent window using a specific `targetOrigin` (never `"*"`).

**Tech Stack:** Node.js `crypto` for HMAC-SHA256 JWT verification (matching existing `agent-auth-jwt.ts` pattern — no external JWT libraries), Express, React, Vitest.

**Spec (BuckGuru side):** The BuckGuru operations integration spec at `buckguru/docs/superpowers/specs/2026-03-16-paperclip-operations-integration-design.md` defines the postMessage protocol this implementation must conform to.

**Single-tenant assumption:** Each BuckGuru RIA gets its own dedicated Paperclip instance. The embed user provisioning adds users to all active companies in the instance. This is correct for the per-RIA deployment model described in the spec.

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `server/src/embed-auth.ts` | Verify BuckGuru JWTs, create/verify embed tokens (pure functions, no DB) |
| `server/src/services/embed-user-provisioning.ts` | Find-or-create user + company membership for embed auth |
| `server/src/routes/embed-auth.ts` | `POST /api/auth/embed` Express route handler |
| `server/src/__tests__/embed-auth.test.ts` | Unit tests for JWT verification and embed token generation |
| `ui/src/lib/embed-auth.ts` | PostMessage listener, token exchange, ready/expired signals |
| `ui/src/__tests__/embed-auth.test.ts` | Unit tests for postMessage protocol logic |

### Modified Files

| File | Change |
|------|--------|
| `server/src/types/express.d.ts` | Add `"embed_jwt"` to `source` union |
| `server/src/middleware/auth.ts` | Add embed token verification path in Bearer token handling |
| `server/src/app.ts` | Mount embed auth route **before** Better Auth catch-all, pass `embedParentOrigin` to health |
| `server/src/routes/health.ts` | Add `embedAuthEnabled` and `embedParentOrigin` to health response |
| `ui/src/api/client.ts` | Add embed token store and bearer header injection |
| `ui/src/api/health.ts` | Add `embedAuthEnabled` and `embedParentOrigin` to type |
| `ui/src/App.tsx` | Integrate embed auth into `CloudAccessGate` |
| `ui/src/main.tsx` | Initialize embed auth on startup |

---

## Chunk 1: Server-Side JWT Verification + Embed Token

Creates the core crypto functions: verify incoming BuckGuru JWTs and issue short-lived Paperclip embed tokens. Pure functions, no DB access, fully testable.

### Task 1: Add `embed_jwt` source to Express actor types

**Files:**
- Modify: `server/src/types/express.d.ts:15`

- [ ] **Step 1: Add embed_jwt to source union**

In `server/src/types/express.d.ts` line 15, add `"embed_jwt"` to the source union:

```typescript
source?: "local_implicit" | "session" | "agent_key" | "agent_jwt" | "embed_jwt" | "none";
```

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: PASS (no consumers of the new value yet)

- [ ] **Step 3: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add server/src/types/express.d.ts
git commit -m "feat: add embed_jwt actor source type"
```

### Task 2: Create embed JWT verification and token functions

**Files:**
- Create: `server/src/embed-auth.ts`
- Test: `server/src/__tests__/embed-auth.test.ts`

The BuckGuru JWT format (from BuckGuru spec):
- Algorithm: HS256
- Claims: `{ userId: string, email: string, role: string, exp: number, iss: "buckguru" }`
- Signed with a per-instance shared secret

Paperclip embed tokens:
- Algorithm: HS256
- Claims: `{ sub: string, email: string, role: string, type: "embed", exp: number, iss: "paperclip" }`
- Signed with `PAPERCLIP_EMBED_JWT_SECRET` (or falls back to `PAPERCLIP_AGENT_JWT_SECRET`)
- TTL: 10 minutes (longer than BuckGuru's 5-minute JWT, since the UI refreshes proactively)

- [ ] **Step 1: Write failing tests**

```typescript
// server/src/__tests__/embed-auth.test.ts
import { createHmac } from "node:crypto";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  createEmbedToken,
  verifyBuckguruJwt,
  verifyEmbedToken,
} from "../embed-auth.js";

function base64UrlEncode(value: string) {
  return Buffer.from(value, "utf8").toString(
    "base64url",
  );
}

function makeJwt(
  claims: Record<string, unknown>,
  secret: string,
) {
  const header = base64UrlEncode(
    JSON.stringify({ alg: "HS256", typ: "JWT" }),
  );
  const payload = base64UrlEncode(
    JSON.stringify(claims),
  );
  const signingInput = `${header}.${payload}`;
  const signature = createHmac("sha256", secret)
    .update(signingInput)
    .digest("base64url");
  return `${signingInput}.${signature}`;
}

describe("embed-auth", () => {
  const EMBED_SECRET = "test-embed-secret-key";
  const BUCKGURU_SECRET =
    "test-buckguru-shared-secret";

  beforeEach(() => {
    process.env.PAPERCLIP_EMBED_JWT_SECRET =
      EMBED_SECRET;
    process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET =
      BUCKGURU_SECRET;
    vi.useFakeTimers();
    vi.setSystemTime(
      new Date("2026-01-01T00:00:00.000Z"),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    delete process.env.PAPERCLIP_EMBED_JWT_SECRET;
    delete process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET;
  });

  describe("verifyBuckguruJwt", () => {
    it("should verify a valid BuckGuru JWT", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt(
        {
          userId: "user-123",
          email: "admin@ria.com",
          role: "admin",
          exp: now + 300,
          iss: "buckguru",
        },
        BUCKGURU_SECRET,
      );

      const claims = verifyBuckguruJwt(token);
      expect(claims).toMatchObject({
        userId: "user-123",
        email: "admin@ria.com",
        role: "admin",
        iss: "buckguru",
      });
    });

    it("should reject expired tokens", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt(
        {
          userId: "user-123",
          email: "admin@ria.com",
          role: "admin",
          exp: now - 10,
          iss: "buckguru",
        },
        BUCKGURU_SECRET,
      );

      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should reject wrong issuer", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt(
        {
          userId: "user-123",
          email: "admin@ria.com",
          role: "admin",
          exp: now + 300,
          iss: "not-buckguru",
        },
        BUCKGURU_SECRET,
      );

      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should reject wrong signature", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt(
        {
          userId: "user-123",
          email: "admin@ria.com",
          role: "admin",
          exp: now + 300,
          iss: "buckguru",
        },
        "wrong-secret",
      );

      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should reject missing required claims", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt(
        {
          userId: "user-123",
          exp: now + 300,
          iss: "buckguru",
        },
        BUCKGURU_SECRET,
      );

      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should return null when secret is missing", () => {
      delete process.env
        .PAPERCLIP_EMBED_BUCKGURU_SECRET;
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt(
        {
          userId: "user-123",
          email: "admin@ria.com",
          role: "admin",
          exp: now + 300,
          iss: "buckguru",
        },
        BUCKGURU_SECRET,
      );

      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should return null for empty string", () => {
      expect(verifyBuckguruJwt("")).toBeNull();
    });

    it("should return null for malformed token", () => {
      expect(
        verifyBuckguruJwt("not.a.valid.jwt"),
      ).toBeNull();
      expect(
        verifyBuckguruJwt("garbage-input"),
      ).toBeNull();
    });
  });

  describe("createEmbedToken / verifyEmbedToken", () => {
    it("should create and verify an embed token", () => {
      const token = createEmbedToken(
        "user-123",
        "admin@ria.com",
        "admin",
      );
      expect(typeof token).toBe("string");

      const claims = verifyEmbedToken(token!);
      expect(claims).toMatchObject({
        sub: "user-123",
        email: "admin@ria.com",
        role: "admin",
        type: "embed",
        iss: "paperclip",
      });
    });

    it("should reject expired embed tokens", () => {
      const token = createEmbedToken(
        "user-123",
        "admin@ria.com",
        "admin",
      );

      // Advance past 10-minute TTL
      vi.setSystemTime(
        new Date("2026-01-01T00:11:00.000Z"),
      );
      expect(verifyEmbedToken(token!)).toBeNull();
    });

    it("should return null when secret is missing", () => {
      delete process.env.PAPERCLIP_EMBED_JWT_SECRET;
      delete process.env.PAPERCLIP_AGENT_JWT_SECRET;
      expect(
        createEmbedToken(
          "user-123",
          "admin@ria.com",
          "admin",
        ),
      ).toBeNull();
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm vitest run server/src/__tests__/embed-auth.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Create server/src/embed-auth.ts**

This follows the exact same pattern as `server/src/agent-auth-jwt.ts` — native `crypto`, no external deps.

```typescript
// server/src/embed-auth.ts
import {
  createHmac,
  timingSafeEqual,
} from "node:crypto";

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

// --- Shared JWT helpers
// (same pattern as agent-auth-jwt.ts) ---

function base64UrlEncode(value: string) {
  return Buffer.from(value, "utf8").toString(
    "base64url",
  );
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, "base64url").toString(
    "utf8",
  );
}

function signPayload(
  secret: string,
  signingInput: string,
) {
  return createHmac("sha256", secret)
    .update(signingInput)
    .digest("base64url");
}

function parseJson(
  value: string,
): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object"
      ? (parsed as Record<string, unknown>)
      : null;
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
  const secret =
    process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET;
  return secret?.trim() || null;
}

/**
 * Verify a JWT issued by BuckGuru.
 * Returns claims or null if invalid/expired.
 */
export function verifyBuckguruJwt(
  token: string,
): BuckguruJwtClaims | null {
  if (!token) return null;
  const secret = getBuckguruSecret();
  if (!secret) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, claimsB64, signature] = parts;

  const header = parseJson(
    base64UrlDecode(headerB64),
  );
  if (!header || header.alg !== JWT_ALGORITHM)
    return null;

  const signingInput = `${headerB64}.${claimsB64}`;
  const expectedSig = signPayload(
    secret,
    signingInput,
  );
  if (!safeCompare(signature, expectedSig)) return null;

  const claims = parseJson(
    base64UrlDecode(claimsB64),
  );
  if (!claims) return null;

  // Validate required fields
  const userId =
    typeof claims.userId === "string"
      ? claims.userId
      : null;
  const email =
    typeof claims.email === "string"
      ? claims.email
      : null;
  const role =
    typeof claims.role === "string"
      ? claims.role
      : null;
  const exp =
    typeof claims.exp === "number"
      ? claims.exp
      : null;
  const iss =
    typeof claims.iss === "string"
      ? claims.iss
      : null;

  if (!userId || !email || !role || !exp || !iss)
    return null;

  // Must be from BuckGuru
  if (iss !== "buckguru") return null;

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (exp < now) return null;

  return { userId, email, role, exp, iss };
}

// --- Paperclip embed token creation/verification ---

function getEmbedSecret(): string | null {
  const secret =
    process.env.PAPERCLIP_EMBED_JWT_SECRET ??
    process.env.PAPERCLIP_AGENT_JWT_SECRET;
  return secret?.trim() || null;
}

/**
 * Create a short-lived Paperclip embed token.
 * Used as Bearer token for embedded UI API calls.
 */
export function createEmbedToken(
  userId: string,
  email: string,
  role: string,
): string | null {
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
  const signingInput =
    `${base64UrlEncode(JSON.stringify(header))}` +
    `.${base64UrlEncode(JSON.stringify(claims))}`;
  const signature = signPayload(
    secret,
    signingInput,
  );

  return `${signingInput}.${signature}`;
}

/**
 * Verify a Paperclip embed token.
 * Returns claims or null if invalid/expired.
 */
export function verifyEmbedToken(
  token: string,
): EmbedTokenClaims | null {
  if (!token) return null;
  const secret = getEmbedSecret();
  if (!secret) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, claimsB64, signature] = parts;

  const header = parseJson(
    base64UrlDecode(headerB64),
  );
  if (!header || header.alg !== JWT_ALGORITHM)
    return null;

  const signingInput = `${headerB64}.${claimsB64}`;
  const expectedSig = signPayload(
    secret,
    signingInput,
  );
  if (!safeCompare(signature, expectedSig)) return null;

  const claims = parseJson(
    base64UrlDecode(claimsB64),
  );
  if (!claims) return null;

  const sub =
    typeof claims.sub === "string"
      ? claims.sub
      : null;
  const email =
    typeof claims.email === "string"
      ? claims.email
      : null;
  const role =
    typeof claims.role === "string"
      ? claims.role
      : null;
  const type = claims.type;
  const iat =
    typeof claims.iat === "number"
      ? claims.iat
      : null;
  const exp =
    typeof claims.exp === "number"
      ? claims.exp
      : null;
  const iss =
    typeof claims.iss === "string"
      ? claims.iss
      : null;

  if (
    !sub ||
    !email ||
    !role ||
    type !== "embed" ||
    !iat ||
    !exp ||
    !iss
  )
    return null;

  const now = Math.floor(Date.now() / 1000);
  if (exp < now) return null;

  return {
    sub,
    email,
    role,
    type: "embed",
    iat,
    exp,
    iss,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm vitest run server/src/__tests__/embed-auth.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add server/src/embed-auth.ts server/src/__tests__/embed-auth.test.ts
git commit -m "feat: add BuckGuru JWT verification and embed token functions"
```

---

## Chunk 2: User Provisioning + API Route

Creates the user provisioning service (find-or-create in DB) and the `POST /api/auth/embed` API route that ties JWT verification to provisioning and returns an embed token.

### Task 3: Create embed user provisioning service

**Files:**
- Create: `server/src/services/embed-user-provisioning.ts`

This service handles find-or-create for embed-authenticated users. On first embed auth, it creates the user in `authUsers`, adds them to all active companies in the instance (per the single-tenant per-RIA deployment model), and optionally grants instance admin.

- [ ] **Step 1: Create the provisioning service**

```typescript
// server/src/services/embed-user-provisioning.ts
import { eq, and } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import {
  authUsers,
  companies,
  companyMemberships,
  instanceUserRoles,
} from "@paperclipai/db";

export interface EmbedUser {
  id: string;
  email: string;
  name: string;
  isInstanceAdmin: boolean;
  companyIds: string[];
}

/**
 * Find or create a user for embed auth.
 *
 * - Looks up user by email.
 * - If not found, creates user with id `embed:<buckguruUserId>`.
 * - If role is "owner", grants instance_admin.
 * - Adds user to all active companies in the instance.
 *
 * NOTE: Single-tenant assumption — each BuckGuru RIA
 * gets its own Paperclip instance, so adding the user
 * to all companies is correct. If multi-tenant
 * Paperclip instances are ever needed, this must be
 * scoped by a firm/tenant identifier.
 */
export async function provisionEmbedUser(
  db: Db,
  opts: {
    buckguruUserId: string;
    email: string;
    role: string;
  },
): Promise<EmbedUser> {
  const { buckguruUserId, email, role } = opts;
  const isOwner = role === "owner";

  // Find existing user by email
  let user = await db
    .select()
    .from(authUsers)
    .where(eq(authUsers.email, email))
    .then((rows) => rows[0] ?? null);

  const now = new Date();

  if (!user) {
    // Create user. The embed: prefix scopes this to
    // BuckGuru-provisioned users. Since each RIA gets
    // its own Paperclip instance, buckguruUserId
    // collisions across tenants cannot occur.
    const userId = `embed:${buckguruUserId}`;
    const name =
      email.split("@")[0] ?? "Embed User";
    await db.insert(authUsers).values({
      id: userId,
      name,
      email,
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
    });
    user = {
      id: userId,
      name,
      email,
      emailVerified: true,
      image: null,
      createdAt: now,
      updatedAt: now,
    };
  }

  // Ensure instance_admin role if owner
  if (isOwner) {
    const existing = await db
      .select()
      .from(instanceUserRoles)
      .where(
        and(
          eq(instanceUserRoles.userId, user.id),
          eq(
            instanceUserRoles.role,
            "instance_admin",
          ),
        ),
      )
      .then((rows) => rows[0] ?? null);

    if (!existing) {
      await db.insert(instanceUserRoles).values({
        userId: user.id,
        role: "instance_admin",
        createdAt: now,
        updatedAt: now,
      });
    }
  }

  // Ensure membership in all active companies
  const allCompanies = await db
    .select({ id: companies.id })
    .from(companies)
    .where(eq(companies.status, "active"));

  const existingMemberships = await db
    .select({
      companyId: companyMemberships.companyId,
    })
    .from(companyMemberships)
    .where(
      and(
        eq(companyMemberships.principalType, "user"),
        eq(
          companyMemberships.principalId,
          user.id,
        ),
        eq(companyMemberships.status, "active"),
      ),
    );

  const existingCompanyIds = new Set(
    existingMemberships.map((m) => m.companyId),
  );

  for (const company of allCompanies) {
    if (!existingCompanyIds.has(company.id)) {
      await db.insert(companyMemberships).values({
        companyId: company.id,
        principalType: "user",
        principalId: user.id,
        status: "active",
        createdAt: now,
        updatedAt: now,
      });
    }
  }

  const companyIds = allCompanies.map((c) => c.id);

  const isInstanceAdmin =
    isOwner ||
    (await db
      .select()
      .from(instanceUserRoles)
      .where(
        and(
          eq(instanceUserRoles.userId, user.id),
          eq(
            instanceUserRoles.role,
            "instance_admin",
          ),
        ),
      )
      .then((rows) => rows.length > 0));

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    isInstanceAdmin,
    companyIds,
  };
}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add server/src/services/embed-user-provisioning.ts
git commit -m "feat: add embed user provisioning service"
```

### Task 4: Create embed auth API route

**Files:**
- Create: `server/src/routes/embed-auth.ts`
- Modify: `server/src/app.ts` (mount route)

**IMPORTANT:** The embed auth route must be mounted **before** the Better Auth catch-all at `app.all("/api/auth/*authPath", opts.betterAuthHandler)` (line 113 of `app.ts`). The `*authPath` glob matches any sub-path under `/api/auth/`, so if the embed route is mounted after it, requests to `POST /api/auth/embed` would be intercepted by Better Auth and return an error.

- [ ] **Step 1: Create the route handler**

```typescript
// server/src/routes/embed-auth.ts
import { Router } from "express";
import type { Db } from "@paperclipai/db";
import {
  verifyBuckguruJwt,
  createEmbedToken,
} from "../embed-auth.js";
import { provisionEmbedUser } from "../services/embed-user-provisioning.js";
import { logger } from "../middleware/logger.js";

export function embedAuthRoutes(db: Db) {
  const router = Router();

  /**
   * POST /api/auth/embed
   *
   * Exchanges a BuckGuru JWT for a Paperclip embed
   * token. The BuckGuru JWT is sent by the parent
   * window via postMessage, then the UI calls this
   * endpoint to get a bearer token for API calls.
   *
   * Body: { token: string }
   * Returns:
   *   { embedToken: string,
   *     user: { id, email, name } }
   */
  router.post("/", async (req, res) => {
    const { token } = req.body as {
      token?: string;
    };
    if (!token || typeof token !== "string") {
      res.status(400).json({
        error: "Missing token in request body",
      });
      return;
    }

    // Validate BuckGuru JWT
    const claims = verifyBuckguruJwt(token);
    if (!claims) {
      logger.warn(
        "Embed auth: invalid or expired BuckGuru JWT",
      );
      res.status(401).json({
        error: "Invalid or expired token",
      });
      return;
    }

    // Provision user
    let user;
    try {
      user = await provisionEmbedUser(db, {
        buckguruUserId: claims.userId,
        email: claims.email,
        role: claims.role,
      });
    } catch (err) {
      logger.error(
        { err },
        "Embed auth: failed to provision user",
      );
      res.status(500).json({
        error: "Failed to provision user",
      });
      return;
    }

    // Create embed token
    const embedToken = createEmbedToken(
      user.id,
      user.email,
      claims.role,
    );
    if (!embedToken) {
      logger.error(
        "Embed auth: failed to create embed token" +
          " (missing secret)",
      );
      res.status(500).json({
        error: "Embed auth not configured",
      });
      return;
    }

    res.json({
      embedToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
      },
    });
  });

  return router;
}
```

- [ ] **Step 2: Mount the route in app.ts**

In `server/src/app.ts`, add the import at the top (after the other route imports):

```typescript
import { embedAuthRoutes } from "./routes/embed-auth.js";
```

Mount the embed auth route **before** the Better Auth catch-all. Insert this line **before** `if (opts.betterAuthHandler)` (before line 112):

```typescript
  app.use(
    "/api/auth/embed",
    embedAuthRoutes(db),
  );
```

This ensures `/api/auth/embed` is matched before `app.all("/api/auth/*authPath", opts.betterAuthHandler)`.

- [ ] **Step 3: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add server/src/routes/embed-auth.ts server/src/app.ts
git commit -m "feat: add POST /api/auth/embed route for BuckGuru JWT exchange"
```

### Task 5: Add embed token verification to auth middleware

**Files:**
- Modify: `server/src/middleware/auth.ts:90-123` (Bearer token handling)

Currently, when a Bearer token is not found as an API key (line 90), the middleware tries `verifyLocalAgentJwt`. We add `verifyEmbedToken` as a fallback after the agent JWT check.

- [ ] **Step 1: Add the embed token path**

In `server/src/middleware/auth.ts`, add the import at line 6 (after the agent JWT import):

```typescript
import { verifyEmbedToken } from "../embed-auth.js";
```

Then replace the existing `if (!key) { ... }` block (lines 90-123) with the following, which preserves the existing agent JWT path and adds embed token as a fallback:

```typescript
    if (!key) {
      // Try agent JWT first
      const agentClaims = verifyLocalAgentJwt(token);
      if (agentClaims) {
        const agentRecord = await db
          .select()
          .from(agents)
          .where(eq(agents.id, agentClaims.sub))
          .then((rows) => rows[0] ?? null);

        if (
          agentRecord &&
          agentRecord.companyId ===
            agentClaims.company_id &&
          agentRecord.status !== "terminated" &&
          agentRecord.status !== "pending_approval"
        ) {
          req.actor = {
            type: "agent",
            agentId: agentClaims.sub,
            companyId: agentClaims.company_id,
            keyId: undefined,
            runId:
              runIdHeader ||
              agentClaims.run_id ||
              undefined,
            source: "agent_jwt",
          };
          next();
          return;
        }
      }

      // Try embed token
      const embedClaims = verifyEmbedToken(token);
      if (embedClaims) {
        // Resolve company memberships
        const membershipRows = await db
          .select({
            companyId:
              companyMemberships.companyId,
          })
          .from(companyMemberships)
          .where(
            and(
              eq(
                companyMemberships.principalType,
                "user",
              ),
              eq(
                companyMemberships.principalId,
                embedClaims.sub,
              ),
              eq(
                companyMemberships.status,
                "active",
              ),
            ),
          );

        // Check instance admin
        const adminRole = await db
          .select({ id: instanceUserRoles.id })
          .from(instanceUserRoles)
          .where(
            and(
              eq(
                instanceUserRoles.userId,
                embedClaims.sub,
              ),
              eq(
                instanceUserRoles.role,
                "instance_admin",
              ),
            ),
          )
          .then((rows) => rows[0] ?? null);

        req.actor = {
          type: "board",
          userId: embedClaims.sub,
          companyIds: membershipRows.map(
            (r) => r.companyId,
          ),
          isInstanceAdmin: Boolean(adminRole),
          source: "embed_jwt",
        };
        next();
        return;
      }

      next();
      return;
    }
```

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: PASS

- [ ] **Step 3: Run existing auth tests**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm vitest run server/src/__tests__/agent-auth-jwt.test.ts`
Expected: PASS (existing agent JWT tests still pass)

- [ ] **Step 4: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add server/src/middleware/auth.ts
git commit -m "feat: add embed token verification to auth middleware"
```

---

## Chunk 3: Health Endpoint + UI API Client

Exposes embed mode in the health response (including the trusted parent origin for postMessage security) and modifies the API client to support bearer token auth.

### Task 6: Add embed mode flags to health endpoint

**Files:**
- Modify: `server/src/routes/health.ts`
- Modify: `server/src/app.ts` (pass new options)
- Modify: `ui/src/api/health.ts` (add types)

The UI needs two pieces of information:
1. `embedAuthEnabled` — whether embed auth is configured (so the UI knows to wait for postMessage)
2. `embedParentOrigin` — the trusted origin for postMessage validation and replies

- [ ] **Step 1: Add flags to health route**

In `server/src/routes/health.ts`, modify the `opts` type to include the new fields:

```typescript
export function healthRoutes(
  db?: Db,
  opts: {
    deploymentMode: DeploymentMode;
    deploymentExposure: DeploymentExposure;
    authReady: boolean;
    companyDeletionEnabled: boolean;
    embedAuthEnabled?: boolean;
    embedParentOrigin?: string;
  } = {
    deploymentMode: "local_trusted",
    deploymentExposure: "private",
    authReady: true,
    companyDeletionEnabled: true,
  },
) {
```

In the `res.json()` call, add the embed fields:

```typescript
    res.json({
      status: "ok",
      deploymentMode: opts.deploymentMode,
      deploymentExposure: opts.deploymentExposure,
      authReady: opts.authReady,
      bootstrapStatus,
      bootstrapInviteActive,
      embedAuthEnabled:
        opts.embedAuthEnabled ?? false,
      embedParentOrigin:
        opts.embedParentOrigin ?? null,
      features: {
        companyDeletionEnabled:
          opts.companyDeletionEnabled,
      },
    });
```

- [ ] **Step 2: Pass flags from app.ts**

In `server/src/app.ts`, in the `healthRoutes` call (~line 122), add the embed flags:

```typescript
  api.use(
    "/health",
    healthRoutes(db, {
      deploymentMode: opts.deploymentMode,
      deploymentExposure: opts.deploymentExposure,
      authReady: opts.authReady,
      companyDeletionEnabled:
        opts.companyDeletionEnabled,
      embedAuthEnabled: Boolean(
        process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET,
      ),
      embedParentOrigin:
        process.env
          .PAPERCLIP_EMBED_PARENT_ORIGIN ??
        undefined,
    }),
  );
```

- [ ] **Step 3: Update UI health type**

In `ui/src/api/health.ts`, add the new fields to `HealthStatus`:

```typescript
export type HealthStatus = {
  status: "ok";
  deploymentMode?:
    | "local_trusted"
    | "authenticated";
  deploymentExposure?: "private" | "public";
  authReady?: boolean;
  bootstrapStatus?:
    | "ready"
    | "bootstrap_pending";
  bootstrapInviteActive?: boolean;
  embedAuthEnabled?: boolean;
  embedParentOrigin?: string | null;
  features?: {
    companyDeletionEnabled?: boolean;
  };
};
```

- [ ] **Step 4: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add server/src/routes/health.ts server/src/app.ts ui/src/api/health.ts
git commit -m "feat: expose embed auth flags in health endpoint"
```

### Task 7: Add bearer token support to UI API client

**Files:**
- Modify: `ui/src/api/client.ts`

The API client currently uses `credentials: "include"` for cookie auth. For embed mode, we inject an `Authorization: Bearer` header instead and switch to `credentials: "omit"` (no cookies).

- [ ] **Step 1: Add embed token store and injection**

In `ui/src/api/client.ts`, add the embed token store after the `ApiError` class (after line 13):

```typescript
// Embed auth token store.
// When set, all API requests use
// Authorization: Bearer instead of cookies.
let embedToken: string | null = null;

export function setEmbedToken(
  token: string | null,
) {
  embedToken = token;
}

export function getEmbedToken(): string | null {
  return embedToken;
}
```

Then modify the `request` function to inject the token. Replace the `credentials` line and add the header injection. The `request` function body (starting at line 15) should become:

```typescript
async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(
    init?.headers ?? undefined,
  );
  const body = init?.body;
  if (
    !(body instanceof FormData) &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  // Inject embed auth token if available
  if (embedToken && !headers.has("Authorization")) {
    headers.set(
      "Authorization",
      `Bearer ${embedToken}`,
    );
  }

  // Use credentials: "omit" in embed mode
  // (no cookies), "include" for standard auth
  const credentials: RequestCredentials = embedToken
    ? "omit"
    : "include";

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers,
    credentials,
  });
  if (!res.ok) {
    const errorBody = await res
      .json()
      .catch(() => null);
    throw new ApiError(
      (errorBody as { error?: string } | null)
        ?.error ??
        `Request failed: ${res.status}`,
      res.status,
      errorBody,
    );
  }
  return res.json();
}
```

Note: `credentials` is placed **after** `...init` spread to ensure it cannot be accidentally overridden by callers.

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add ui/src/api/client.ts
git commit -m "feat: add embed token support to API client"
```

---

## Chunk 4: UI PostMessage Protocol

Creates the embed auth module that handles the full postMessage protocol: listens for BuckGuru auth messages (with origin validation), exchanges tokens, signals ready/expired (with specific `targetOrigin`), and manages token refresh.

### Task 8: Create embed auth UI module

**Files:**
- Create: `ui/src/lib/embed-auth.ts`
- Test: `ui/src/__tests__/embed-auth.test.ts`

**Security requirements (from BuckGuru spec):**
1. Incoming `postMessage` events must be validated against a trusted parent origin
2. Outgoing `postMessage` signals (`PAPERCLIP_READY`, `PAPERCLIP_TOKEN_EXPIRED`) must use a specific `targetOrigin`, never `"*"`

The trusted parent origin comes from the health endpoint (`embedParentOrigin`), which is set by the `PAPERCLIP_EMBED_PARENT_ORIGIN` environment variable.

- [ ] **Step 1: Write failing tests**

```typescript
// ui/src/__tests__/embed-auth.test.ts
import {
  afterEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  isEmbedded,
  parseEmbedMessage,
} from "../lib/embed-auth";

describe("embed-auth", () => {
  describe("isEmbedded", () => {
    it("should return false in top-level window", () => {
      // In test env, window.parent === window
      expect(isEmbedded()).toBe(false);
    });
  });

  describe("parseEmbedMessage", () => {
    it("should parse BUCKGURU_OPERATIONS_AUTH", () => {
      const msg = parseEmbedMessage({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
      });
      expect(msg).toEqual({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
      });
    });

    it("should parse BUCKGURU_OPERATIONS_TOKEN_REFRESH", () => {
      const msg = parseEmbedMessage({
        type: "BUCKGURU_OPERATIONS_TOKEN_REFRESH",
        token: "jwt-456",
      });
      expect(msg).toEqual({
        type: "BUCKGURU_OPERATIONS_TOKEN_REFRESH",
        token: "jwt-456",
      });
    });

    it("should return null for unknown message types", () => {
      expect(
        parseEmbedMessage({ type: "OTHER" }),
      ).toBeNull();
    });

    it("should return null for non-objects", () => {
      expect(
        parseEmbedMessage("string"),
      ).toBeNull();
      expect(parseEmbedMessage(null)).toBeNull();
    });

    it("should return null when token is missing", () => {
      expect(
        parseEmbedMessage({
          type: "BUCKGURU_OPERATIONS_AUTH",
        }),
      ).toBeNull();
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm vitest run ui/src/__tests__/embed-auth.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Create ui/src/lib/embed-auth.ts**

```typescript
// ui/src/lib/embed-auth.ts
import { setEmbedToken } from "../api/client";

// --- Types ---

export type EmbedAuthMessage =
  | {
      type: "BUCKGURU_OPERATIONS_AUTH";
      token: string;
    }
  | {
      type: "BUCKGURU_OPERATIONS_TOKEN_REFRESH";
      token: string;
    };

type EmbedAuthState = {
  authenticated: boolean;
  user: {
    id: string;
    email: string;
    name: string;
  } | null;
};

type EmbedAuthListener = (
  state: EmbedAuthState,
) => void;

// --- Helpers ---

/**
 * Check if the app is running inside an iframe.
 */
export function isEmbedded(): boolean {
  try {
    return window.self !== window.top;
  } catch {
    // Cross-origin iframe throws on access
    return true;
  }
}

/**
 * Parse a postMessage data payload into a typed
 * embed auth message.
 * Returns null if not a valid embed auth message.
 */
export function parseEmbedMessage(
  data: unknown,
): EmbedAuthMessage | null {
  if (!data || typeof data !== "object") return null;
  const msg = data as Record<string, unknown>;
  if (typeof msg.type !== "string") return null;
  if (typeof msg.token !== "string") return null;

  if (msg.type === "BUCKGURU_OPERATIONS_AUTH") {
    return {
      type: "BUCKGURU_OPERATIONS_AUTH",
      token: msg.token,
    };
  }
  if (
    msg.type === "BUCKGURU_OPERATIONS_TOKEN_REFRESH"
  ) {
    return {
      type: "BUCKGURU_OPERATIONS_TOKEN_REFRESH",
      token: msg.token,
    };
  }
  return null;
}

// --- Token exchange ---

async function exchangeToken(
  buckguruJwt: string,
): Promise<{
  embedToken: string;
  user: {
    id: string;
    email: string;
    name: string;
  };
} | null> {
  try {
    const res = await fetch("/api/auth/embed", {
      method: "POST",
      credentials: "omit",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: buckguruJwt }),
    });
    if (!res.ok) {
      console.error(
        "[embed-auth] Token exchange failed:" +
          ` ${res.status}`,
      );
      return null;
    }
    return res.json();
  } catch (err) {
    console.error(
      "[embed-auth] Token exchange error:",
      err,
    );
    return null;
  }
}

// --- Signals to parent ---

/**
 * Send a message to the parent window using a
 * specific targetOrigin. Never uses "*".
 * Falls back to "*" only if trustedOrigin is not
 * yet configured (should not happen in production).
 */
function sendToParent(
  type: string,
  extra?: Record<string, unknown>,
) {
  const origin = trustedParentOrigin ?? "*";
  if (origin === "*") {
    console.warn(
      "[embed-auth] sendToParent using '*'" +
        " — trustedParentOrigin not yet set",
    );
  }
  try {
    window.parent.postMessage(
      { type, ...extra },
      origin,
    );
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
let currentState: EmbedAuthState = {
  authenticated: false,
  user: null,
};

function notifyListeners() {
  for (const listener of listeners) {
    listener(currentState);
  }
}

async function handleBuckguruToken(
  buckguruJwt: string,
): Promise<boolean> {
  const result = await exchangeToken(buckguruJwt);
  if (!result) {
    currentState = {
      authenticated: false,
      user: null,
    };
    setEmbedToken(null);
    notifyListeners();
    return false;
  }

  setEmbedToken(result.embedToken);
  currentState = {
    authenticated: true,
    user: result.user,
  };
  notifyListeners();
  return true;
}

/**
 * Set the trusted parent origin for postMessage
 * validation. Must be called before initEmbedAuth()
 * or ASAP after health check completes.
 */
export function setTrustedParentOrigin(
  origin: string,
) {
  trustedParentOrigin = origin;
}

/**
 * Initialize embed auth. Call once on app startup.
 * Sets up postMessage listener and waits for
 * BuckGuru auth token.
 *
 * NOTE: This runs optimistically before the health
 * check completes. The message listener is
 * registered immediately so early postMessage
 * events are not lost. If embedAuthEnabled turns
 * out to be false in the health response, the token
 * exchange will have already happened server-side
 * but the CloudAccessGate will fall through to
 * standard auth.
 *
 * Returns a cleanup function.
 */
export function initEmbedAuth(): () => void {
  if (initialized) return () => {};
  initialized = true;

  const handler = async (event: MessageEvent) => {
    // Validate origin if configured
    if (
      trustedParentOrigin &&
      event.origin !== trustedParentOrigin
    ) {
      return;
    }

    const msg = parseEmbedMessage(event.data);
    if (!msg) return;

    // If origin wasn't pre-configured, capture it
    // from first valid message for subsequent
    // replies
    if (!trustedParentOrigin) {
      trustedParentOrigin = event.origin;
    }

    if (msg.type === "BUCKGURU_OPERATIONS_AUTH") {
      const ok = await handleBuckguruToken(
        msg.token,
      );
      if (ok) {
        sendReady();
      }
    }

    if (
      msg.type ===
      "BUCKGURU_OPERATIONS_TOKEN_REFRESH"
    ) {
      const ok = await handleBuckguruToken(
        msg.token,
      );
      if (!ok) {
        sendTokenExpired();
      }
    }
  };

  window.addEventListener("message", handler);

  return () => {
    window.removeEventListener("message", handler);
    initialized = false;
  };
}

/**
 * Subscribe to embed auth state changes.
 * Returns an unsubscribe function.
 */
export function onEmbedAuthChange(
  listener: EmbedAuthListener,
): () => void {
  listeners.push(listener);
  return () => {
    listeners = listeners.filter(
      (l) => l !== listener,
    );
  };
}

/**
 * Get current embed auth state.
 */
export function getEmbedAuthState(): EmbedAuthState {
  return currentState;
}
```

Key security features:
- `sendToParent()` uses `trustedParentOrigin` as the `targetOrigin`, never `"*"` in production
- Incoming messages are validated against `trustedParentOrigin` when configured
- The origin is captured from the first valid message as a fallback (defense-in-depth: even if config is missing, origin consistency is enforced after first auth)
- `exchangeToken()` uses `credentials: "omit"` (no cookies sent to own server)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm vitest run ui/src/__tests__/embed-auth.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add ui/src/lib/embed-auth.ts ui/src/__tests__/embed-auth.test.ts
git commit -m "feat: add embed auth postMessage protocol with origin validation"
```

### Task 9: Integrate embed auth into CloudAccessGate

**Files:**
- Modify: `ui/src/App.tsx:1-107` (CloudAccessGate component)
- Modify: `ui/src/main.tsx` (initialize embed auth)

The integration must:
1. Initialize embed auth listener on app startup (in `main.tsx`)
2. In `CloudAccessGate`, if embedded + embed auth enabled, wait for postMessage auth instead of redirecting to `/auth`
3. When health check returns `embedParentOrigin`, set it on the embed auth module
4. If not embedded, behavior is unchanged

- [ ] **Step 1: Add embed auth init to main.tsx**

In `ui/src/main.tsx`, add the import after `initPluginBridge`:

```typescript
import {
  initEmbedAuth,
  isEmbedded,
} from "./lib/embed-auth";
```

After the `initPluginBridge(React, ReactDOM)` call (line 22), add:

```typescript
if (isEmbedded()) {
  initEmbedAuth();
}
```

- [ ] **Step 2: Modify CloudAccessGate in App.tsx**

In `ui/src/App.tsx`, add `useState` to the React import (line 1):

```typescript
import { useEffect, useRef, useState } from "react";
```

Add the embed auth imports at the top:

```typescript
import {
  isEmbedded,
  getEmbedAuthState,
  onEmbedAuthChange,
  setTrustedParentOrigin,
} from "./lib/embed-auth";
```

Replace the `CloudAccessGate` function (lines 60-107) with:

```typescript
function CloudAccessGate() {
  const location = useLocation();
  const [embedAuth, setEmbedAuth] = useState(
    getEmbedAuthState,
  );
  const embedded = isEmbedded();

  useEffect(() => {
    if (!embedded) return;
    return onEmbedAuthChange(setEmbedAuth);
  }, [embedded]);

  const healthQuery = useQuery({
    queryKey: queryKeys.health,
    queryFn: () => healthApi.get(),
    retry: false,
    refetchInterval: (query) => {
      const data = query.state.data as
        | {
            deploymentMode?:
              | "local_trusted"
              | "authenticated";
            bootstrapStatus?:
              | "ready"
              | "bootstrap_pending";
          }
        | undefined;
      return data?.deploymentMode ===
        "authenticated" &&
        data.bootstrapStatus === "bootstrap_pending"
        ? 2000
        : false;
    },
    refetchIntervalInBackground: true,
  });

  const isAuthenticatedMode =
    healthQuery.data?.deploymentMode ===
    "authenticated";
  const embedAuthEnabled =
    healthQuery.data?.embedAuthEnabled === true;

  // Set trusted parent origin from health response
  useEffect(() => {
    const origin =
      healthQuery.data?.embedParentOrigin;
    if (origin) {
      setTrustedParentOrigin(origin);
    }
  }, [healthQuery.data?.embedParentOrigin]);

  // In embed mode with embed auth enabled,
  // skip session query — auth comes via postMessage
  const useEmbedAuth =
    embedded && embedAuthEnabled;

  const sessionQuery = useQuery({
    queryKey: queryKeys.auth.session,
    queryFn: () => authApi.getSession(),
    enabled:
      isAuthenticatedMode && !useEmbedAuth,
    retry: false,
  });

  if (
    healthQuery.isLoading ||
    (isAuthenticatedMode &&
      !useEmbedAuth &&
      sessionQuery.isLoading)
  ) {
    return (
      <div className="mx-auto max-w-xl py-10 text-sm text-muted-foreground">
        Loading...
      </div>
    );
  }

  if (healthQuery.error) {
    return (
      <div className="mx-auto max-w-xl py-10 text-sm text-destructive">
        {healthQuery.error instanceof Error
          ? healthQuery.error.message
          : "Failed to load app state"}
      </div>
    );
  }

  if (
    isAuthenticatedMode &&
    healthQuery.data?.bootstrapStatus ===
      "bootstrap_pending"
  ) {
    return (
      <BootstrapPendingPage
        hasActiveInvite={
          healthQuery.data.bootstrapInviteActive
        }
      />
    );
  }

  // Embed auth: wait for postMessage token
  if (useEmbedAuth) {
    if (!embedAuth.authenticated) {
      return (
        <div className="mx-auto max-w-xl py-10 text-sm text-muted-foreground">
          Waiting for authentication...
        </div>
      );
    }
    // Authenticated via embed — proceed
    return <Outlet />;
  }

  // Standard auth: redirect to login if no session
  if (isAuthenticatedMode && !sessionQuery.data) {
    const next = encodeURIComponent(
      `${location.pathname}${location.search}`,
    );
    return (
      <Navigate
        to={`/auth?next=${next}`}
        replace
      />
    );
  }

  return <Outlet />;
}
```

- [ ] **Step 3: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add ui/src/App.tsx ui/src/main.tsx
git commit -m "feat: integrate embed auth into CloudAccessGate"
```

---

## Chunk 5: Get-Session Support + Final Verification

Ensures the `/api/auth/get-session` endpoint works for embed token users and runs full verification.

### Task 10: Update get-session for embed auth

**Files:**
- Modify: `server/src/app.ts:95-111` (get-session route)

The existing `GET /api/auth/get-session` route reads from `req.actor`. Since embed tokens set `req.actor` with `type: "board"` and a `userId`, it already works. However, it returns `email: null` and `name: null` for non-`local_implicit` sources. We improve it to look up the user's actual email and name from the DB.

- [ ] **Step 1: Improve get-session to look up user details**

In `server/src/app.ts`, add the `eq` import from `drizzle-orm` at the top if not already present:

```typescript
import { eq } from "drizzle-orm";
```

Add the `authUsers` import from `@paperclipai/db`:

```typescript
import { authUsers } from "@paperclipai/db";
```

Replace the `app.get("/api/auth/get-session", ...)` block (lines 95-111) with:

```typescript
  app.get(
    "/api/auth/get-session",
    async (req, res) => {
      if (
        req.actor.type !== "board" ||
        !req.actor.userId
      ) {
        res
          .status(401)
          .json({ error: "Unauthorized" });
        return;
      }

      let email: string | null = null;
      let name: string | null = null;

      if (req.actor.source === "local_implicit") {
        name = "Local Board";
      } else {
        const userRow = await db
          .select({
            email: authUsers.email,
            name: authUsers.name,
          })
          .from(authUsers)
          .where(
            eq(authUsers.id, req.actor.userId),
          )
          .then((rows) => rows[0] ?? null);
        if (userRow) {
          email = userRow.email;
          name = userRow.name;
        }
      }

      res.json({
        session: {
          id: `paperclip:${req.actor.source}:${req.actor.userId}`,
          userId: req.actor.userId,
        },
        user: {
          id: req.actor.userId,
          email,
          name,
        },
      });
    },
  );
```

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git add server/src/app.ts
git commit -m "feat: improve get-session to look up user details for embed auth"
```

### Task 11: Final verification

- [ ] **Step 1: Run all unit tests**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm test:run`
Expected: All pass

- [ ] **Step 2: Run typecheck**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm -r typecheck`
Expected: No errors

- [ ] **Step 3: Test build**

Run: `cd /Users/adamrykowski/Projects/ai-native-company/paperclip && pnpm build`
Expected: Build succeeds

- [ ] **Step 4: Final commit if any remaining changes**

```bash
cd /Users/adamrykowski/Projects/ai-native-company/paperclip
git status
# If any uncommitted changes, stage and commit
```

---

## Environment Variables Summary

| Variable | Required | Description |
|----------|----------|-------------|
| `PAPERCLIP_EMBED_BUCKGURU_SECRET` | Yes | Shared secret for verifying BuckGuru JWTs. Must match the value in BuckGuru's `OperationsConfig.jwtSecret` (decrypted). |
| `PAPERCLIP_EMBED_JWT_SECRET` | No | Secret for signing Paperclip embed tokens. Falls back to `PAPERCLIP_AGENT_JWT_SECRET` if not set. |
| `PAPERCLIP_EMBED_PARENT_ORIGIN` | Yes (production) | Trusted origin for postMessage validation, e.g., `https://www.thebuckguru.com`. Used both for validating incoming messages and as `targetOrigin` for outgoing signals. |

## Protocol Conformance

This implementation conforms to the BuckGuru postMessage protocol defined in the BuckGuru spec:

| BuckGuru → Paperclip | Handler |
|----------------------|---------|
| `{ type: "BUCKGURU_OPERATIONS_AUTH", token }` | `initEmbedAuth()` listener → validates `event.origin` → `exchangeToken()` → `sendReady()` |
| `{ type: "BUCKGURU_OPERATIONS_TOKEN_REFRESH", token }` | `initEmbedAuth()` listener → validates `event.origin` → `exchangeToken()` → (or `sendTokenExpired()` on failure) |

| Paperclip → BuckGuru | Trigger | targetOrigin |
|----------------------|---------|-------------|
| `{ type: "PAPERCLIP_READY" }` | After successful initial auth exchange | `PAPERCLIP_EMBED_PARENT_ORIGIN` (never `"*"` in production) |
| `{ type: "PAPERCLIP_TOKEN_EXPIRED" }` | When token refresh fails | `PAPERCLIP_EMBED_PARENT_ORIGIN` (never `"*"` in production) |

## Security Model

1. **Incoming postMessage validation:** `event.origin` is checked against `PAPERCLIP_EMBED_PARENT_ORIGIN`. If the env var is not set, the origin from the first valid auth message is captured and used for all subsequent messages (defense-in-depth fallback).

2. **Outgoing postMessage targetOrigin:** Uses the configured `PAPERCLIP_EMBED_PARENT_ORIGIN`, never `"*"` in production. Falls back to `"*"` only if the origin hasn't been configured yet (should not happen after health check completes).

3. **JWT verification:** BuckGuru JWTs are verified with HMAC-SHA256 using timing-safe comparison (`timingSafeEqual`). The shared secret (`PAPERCLIP_EMBED_BUCKGURU_SECRET`) is never exposed to the client.

4. **Token isolation:** BuckGuru JWT → Paperclip embed token exchange creates a clean authorization boundary. The BuckGuru JWT secret and the Paperclip embed token secret are independent.

5. **No cookies in embed mode:** The API client uses `credentials: "omit"` and `Authorization: Bearer` headers. This avoids cross-origin cookie issues entirely.

## What This Does NOT Change

- No database schema changes (uses existing `authUsers`, `companyMemberships`, `instanceUserRoles`)
- No new npm dependencies
- No changes to existing cookie-based auth flow (embed auth is additive)
- No changes to agent JWT auth (existing Bearer token path is preserved)
- Paperclip's own login/signup pages still work normally
