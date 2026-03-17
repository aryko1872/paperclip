// server/src/__tests__/embed-auth.test.ts
import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createEmbedToken, verifyBuckguruJwt, verifyEmbedToken } from "../embed-auth.js";

function base64UrlEncode(value: string) {
  return Buffer.from(value, "utf8").toString("base64url");
}

function makeJwt(claims: Record<string, unknown>, secret: string) {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = base64UrlEncode(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const signature = createHmac("sha256", secret).update(signingInput).digest("base64url");
  return `${signingInput}.${signature}`;
}

describe("embed-auth", () => {
  const EMBED_SECRET = "test-embed-secret-key";
  const BUCKGURU_SECRET = "test-buckguru-shared-secret";

  beforeEach(() => {
    process.env.PAPERCLIP_EMBED_JWT_SECRET = EMBED_SECRET;
    process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET = BUCKGURU_SECRET;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    delete process.env.PAPERCLIP_EMBED_JWT_SECRET;
    delete process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET;
  });

  describe("verifyBuckguruJwt", () => {
    it("should verify a valid BuckGuru JWT", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt({ userId: "user-123", email: "admin@ria.com", role: "admin", exp: now + 300, iss: "buckguru" }, BUCKGURU_SECRET);
      const claims = verifyBuckguruJwt(token);
      expect(claims).toMatchObject({ userId: "user-123", email: "admin@ria.com", role: "admin", iss: "buckguru" });
    });

    it("should reject expired tokens", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt({ userId: "user-123", email: "admin@ria.com", role: "admin", exp: now - 10, iss: "buckguru" }, BUCKGURU_SECRET);
      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should reject wrong issuer", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt({ userId: "user-123", email: "admin@ria.com", role: "admin", exp: now + 300, iss: "not-buckguru" }, BUCKGURU_SECRET);
      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should reject wrong signature", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt({ userId: "user-123", email: "admin@ria.com", role: "admin", exp: now + 300, iss: "buckguru" }, "wrong-secret");
      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should reject missing required claims", () => {
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt({ userId: "user-123", exp: now + 300, iss: "buckguru" }, BUCKGURU_SECRET);
      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should return null when secret is missing", () => {
      delete process.env.PAPERCLIP_EMBED_BUCKGURU_SECRET;
      const now = Math.floor(Date.now() / 1000);
      const token = makeJwt({ userId: "user-123", email: "admin@ria.com", role: "admin", exp: now + 300, iss: "buckguru" }, BUCKGURU_SECRET);
      expect(verifyBuckguruJwt(token)).toBeNull();
    });

    it("should return null for empty string", () => {
      expect(verifyBuckguruJwt("")).toBeNull();
    });

    it("should return null for malformed token", () => {
      expect(verifyBuckguruJwt("not.a.valid.jwt")).toBeNull();
      expect(verifyBuckguruJwt("garbage-input")).toBeNull();
    });
  });

  describe("createEmbedToken / verifyEmbedToken", () => {
    it("should create and verify an embed token", () => {
      const token = createEmbedToken("user-123", "admin@ria.com", "admin");
      expect(typeof token).toBe("string");
      const claims = verifyEmbedToken(token!);
      expect(claims).toMatchObject({ sub: "user-123", email: "admin@ria.com", role: "admin", type: "embed", iss: "paperclip" });
    });

    it("should reject expired embed tokens", () => {
      const token = createEmbedToken("user-123", "admin@ria.com", "admin");
      vi.setSystemTime(new Date("2026-01-01T00:11:00.000Z")); // past 10-min TTL
      expect(verifyEmbedToken(token!)).toBeNull();
    });

    it("should return null when secret is missing", () => {
      delete process.env.PAPERCLIP_EMBED_JWT_SECRET;
      delete process.env.PAPERCLIP_AGENT_JWT_SECRET;
      expect(createEmbedToken("user-123", "admin@ria.com", "admin")).toBeNull();
    });
  });
});
