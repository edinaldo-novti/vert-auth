/**
 * @vert/auth — Authenticatable module tests.
 */

import { describe, test, expect } from "bun:test";
import { hashPassword, verifyPassword, authenticate, authenticatableColumnsSQL } from "../src/authenticatable";
import type { AuthUser, UserAdapter } from "../src/types";
import { createMockAdapter, createTestUser } from "./helpers";

describe("Authenticatable", () => {
  describe("hashPassword / verifyPassword", () => {
    test("hashes with Argon2id and verifies correctly", async () => {
      const hash = await hashPassword("MyPassword123");
      expect(hash).toContain("$argon2id$");
      expect(await verifyPassword("MyPassword123", hash)).toBe(true);
    });

    test("rejects wrong password", async () => {
      const hash = await hashPassword("MyPassword123");
      expect(await verifyPassword("WrongPassword", hash)).toBe(false);
    });

    test("different hashes for same password (random salt)", async () => {
      const h1 = await hashPassword("Same123");
      const h2 = await hashPassword("Same123");
      expect(h1).not.toBe(h2);
    });
  });

  describe("authenticate", () => {
    test("succeeds with correct credentials", async () => {
      const hash = await hashPassword("ValidPass1");
      const user = createTestUser({ encryptedPassword: hash, confirmedAt: new Date() });
      const adapter = createMockAdapter([user]);

      const result = await authenticate(adapter, "test@example.com", "ValidPass1");
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.user.email).toBe("test@example.com");
      }
    });

    test("fails with wrong password", async () => {
      const hash = await hashPassword("ValidPass1");
      const user = createTestUser({ encryptedPassword: hash });
      const adapter = createMockAdapter([user]);

      const result = await authenticate(adapter, "test@example.com", "WrongPass");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe("INVALID_CREDENTIALS");
      }
    });

    test("fails with non-existent user (timing attack safe)", async () => {
      const adapter = createMockAdapter([]);
      const result = await authenticate(adapter, "nobody@example.com", "AnyPass1");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe("INVALID_CREDENTIALS");
      }
    });

    test("fails for locked account", async () => {
      const hash = await hashPassword("ValidPass1");
      const user = createTestUser({ encryptedPassword: hash, lockedAt: new Date() });
      const adapter = createMockAdapter([user]);

      const result = await authenticate(adapter, "test@example.com", "ValidPass1");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe("ACCOUNT_LOCKED");
      }
    });

    test("fails for unconfirmed account", async () => {
      const hash = await hashPassword("ValidPass1");
      const user = createTestUser({
        encryptedPassword: hash,
        confirmedAt: null,
        confirmationToken: "some-token",
      });
      const adapter = createMockAdapter([user]);

      const result = await authenticate(adapter, "test@example.com", "ValidPass1");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.code).toBe("ACCOUNT_NOT_CONFIRMED");
      }
    });
  });

  describe("authenticatableColumnsSQL", () => {
    test("returns SQL with email and encrypted_password", () => {
      const sql = authenticatableColumnsSQL();
      expect(sql).toContain("email");
      expect(sql).toContain("encrypted_password");
    });
  });
});
