// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { isEmbedded, parseEmbedMessage } from "../lib/embed-auth";

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
      expect(parseEmbedMessage({ type: "OTHER" })).toBeNull();
    });

    it("should return null for non-objects", () => {
      expect(parseEmbedMessage("string")).toBeNull();
      expect(parseEmbedMessage(null)).toBeNull();
    });

    it("should return null when token is missing", () => {
      expect(parseEmbedMessage({ type: "BUCKGURU_OPERATIONS_AUTH" })).toBeNull();
    });

    it("should parse auth message with theme", () => {
      const msg = parseEmbedMessage({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
        theme: "light",
      });
      expect(msg).toEqual({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
        theme: "light",
      });
    });

    it("should parse auth message without theme", () => {
      const msg = parseEmbedMessage({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
      });
      expect(msg).toEqual({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
        theme: undefined,
      });
    });

    it("should ignore invalid theme values in auth messages", () => {
      const msg = parseEmbedMessage({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
        theme: "neon",
      });
      expect(msg).toEqual({
        type: "BUCKGURU_OPERATIONS_AUTH",
        token: "jwt-123",
        theme: undefined,
      });
    });

    it("should parse BUCKGURU_OPERATIONS_THEME", () => {
      const msg = parseEmbedMessage({
        type: "BUCKGURU_OPERATIONS_THEME",
        theme: "dark",
      });
      expect(msg).toEqual({
        type: "BUCKGURU_OPERATIONS_THEME",
        theme: "dark",
      });
    });

    it("should reject BUCKGURU_OPERATIONS_THEME without valid theme", () => {
      expect(parseEmbedMessage({ type: "BUCKGURU_OPERATIONS_THEME" })).toBeNull();
      expect(parseEmbedMessage({ type: "BUCKGURU_OPERATIONS_THEME", theme: "neon" })).toBeNull();
    });
  });
});
