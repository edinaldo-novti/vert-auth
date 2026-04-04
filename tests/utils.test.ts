/**
 * @vert/auth — Utils module tests.
 */

import { describe, test, expect } from "bun:test";
import { generateToken, hashToken, secureCompare } from "../src/utils";

describe("Utils", () => {
  describe("generateToken", () => {
    test("generates 64 char hex token by default (32 bytes)", () => {
      const token = generateToken();
      expect(token.length).toBe(64);
      expect(/^[0-9a-f]+$/.test(token)).toBe(true);
    });

    test("generates different tokens each time", () => {
      const t1 = generateToken();
      const t2 = generateToken();
      expect(t1).not.toBe(t2);
    });

    test("custom byte length", () => {
      const token = generateToken(16);
      expect(token.length).toBe(32); // 16 bytes = 32 hex chars
    });
  });

  describe("hashToken", () => {
    test("produces SHA-256 hex hash", async () => {
      const hash = await hashToken("test-token");
      expect(hash.length).toBe(64); // SHA-256 = 32 bytes = 64 hex
      expect(/^[0-9a-f]+$/.test(hash)).toBe(true);
    });

    test("deterministic hashing", async () => {
      const h1 = await hashToken("same-input");
      const h2 = await hashToken("same-input");
      expect(h1).toBe(h2);
    });

    test("different inputs produce different hashes", async () => {
      const h1 = await hashToken("input-a");
      const h2 = await hashToken("input-b");
      expect(h1).not.toBe(h2);
    });
  });

  describe("secureCompare", () => {
    test("returns true for equal strings", () => {
      expect(secureCompare("abc123", "abc123")).toBe(true);
    });

    test("returns false for different strings of same length", () => {
      expect(secureCompare("abc123", "xyz789")).toBe(false);
    });

    test("returns false for different lengths", () => {
      expect(secureCompare("short", "longer-string")).toBe(false);
    });

    test("returns false for empty vs non-empty", () => {
      expect(secureCompare("", "something")).toBe(false);
    });

    test("returns true for empty vs empty", () => {
      expect(secureCompare("", "")).toBe(true);
    });
  });
});
