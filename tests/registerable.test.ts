/**
 * @vert/auth — Registerable module tests.
 */

import { describe, test, expect } from "bun:test";
import { register, updateAccount, deleteAccount } from "../src/registerable";
import { hashPassword } from "../src/authenticatable";
import { createMockAdapter, createTestUser } from "./helpers";

describe("Registerable", () => {
  describe("register", () => {
    test("creates user with hashed password", async () => {
      const adapter = createMockAdapter();
      const result = await register(adapter, {
        email: "new@example.com",
        password: "StrongPass1",
        passwordConfirmation: "StrongPass1",
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.user.email).toBe("new@example.com");
        expect(result.user.encryptedPassword).toContain("$argon2id$");
      }
    });

    test("rejects duplicate email", async () => {
      const existing = createTestUser({ email: "taken@example.com" });
      const adapter = createMockAdapter([existing]);

      const result = await register(adapter, {
        email: "taken@example.com",
        password: "StrongPass1",
        passwordConfirmation: "StrongPass1",
      });

      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("EMAIL_ALREADY_EXISTS");
    });

    test("rejects weak password", async () => {
      const adapter = createMockAdapter();
      const result = await register(adapter, {
        email: "new@example.com",
        password: "weak",
        passwordConfirmation: "weak",
      });

      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("VALIDATION_ERROR");
    });

    test("rejects mismatched passwords", async () => {
      const adapter = createMockAdapter();
      const result = await register(adapter, {
        email: "new@example.com",
        password: "StrongPass1",
        passwordConfirmation: "DifferentPass1",
      });

      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("VALIDATION_ERROR");
    });

    test("calls hooks", async () => {
      const adapter = createMockAdapter();
      let beforeCalled = false;
      let afterCalled = false;

      await register(
        adapter,
        { email: "hook@example.com", password: "StrongPass1", passwordConfirmation: "StrongPass1" },
        {
          beforeRegister: () => { beforeCalled = true; },
          afterRegister: () => { afterCalled = true; },
        },
      );

      expect(beforeCalled).toBe(true);
      expect(afterCalled).toBe(true);
    });

    test("normalizes email to lowercase", async () => {
      const adapter = createMockAdapter();
      const result = await register(adapter, {
        email: "  User@EXAMPLE.COM  ",
        password: "StrongPass1",
        passwordConfirmation: "StrongPass1",
      });

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.user.email).toBe("user@example.com");
      }
    });
  });

  describe("updateAccount", () => {
    test("updates email with valid current password", async () => {
      const hash = await hashPassword("CurrentPass1");
      const user = createTestUser({ encryptedPassword: hash });
      const adapter = createMockAdapter([user]);

      const result = await updateAccount(adapter, user.id, {
        email: "newemail@example.com",
        currentPassword: "CurrentPass1",
      });

      expect(result.success).toBe(true);
      if (result.success) expect(result.user.email).toBe("newemail@example.com");
    });

    test("rejects with wrong current password", async () => {
      const hash = await hashPassword("CurrentPass1");
      const user = createTestUser({ encryptedPassword: hash });
      const adapter = createMockAdapter([user]);

      const result = await updateAccount(adapter, user.id, {
        email: "newemail@example.com",
        currentPassword: "WrongPass",
      });

      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("INVALID_CREDENTIALS");
    });

    test("rejects non-existent user", async () => {
      const adapter = createMockAdapter();
      const result = await updateAccount(adapter, "nonexistent-id", {
        currentPassword: "any",
      });

      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("USER_NOT_FOUND");
    });
  });

  describe("deleteAccount", () => {
    test("deletes with valid current password", async () => {
      const hash = await hashPassword("CurrentPass1");
      const user = createTestUser({ encryptedPassword: hash });
      const adapter = createMockAdapter([user]);

      const result = await deleteAccount(adapter, user.id, "CurrentPass1");
      expect(result.success).toBe(true);
      expect(adapter.users.length).toBe(0);
    });

    test("rejects with wrong password", async () => {
      const hash = await hashPassword("CurrentPass1");
      const user = createTestUser({ encryptedPassword: hash });
      const adapter = createMockAdapter([user]);

      const result = await deleteAccount(adapter, user.id, "WrongPass");
      expect(result.success).toBe(false);
      expect(adapter.users.length).toBe(1);
    });
  });
});
