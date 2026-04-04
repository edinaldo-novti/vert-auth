/**
 * @vert/auth — Validatable module tests.
 */

import { describe, test, expect } from "bun:test";
import {
  emailSchema,
  passwordSchema,
  registrationSchema,
  loginSchema,
  changePasswordSchema,
  resetPasswordSchema,
} from "../src/validatable";

describe("Validatable", () => {
  describe("emailSchema", () => {
    test("accepts valid email", () => {
      const result = emailSchema().safeParse("user@example.com");
      expect(result.success).toBe(true);
    });

    test("rejects invalid email", () => {
      const result = emailSchema().safeParse("not-an-email");
      expect(result.success).toBe(false);
    });

    test("rejects empty string", () => {
      const result = emailSchema().safeParse("");
      expect(result.success).toBe(false);
    });

    test("rejects email exceeding max length", () => {
      const longEmail = "a".repeat(300) + "@ex.com";
      const result = emailSchema().safeParse(longEmail);
      expect(result.success).toBe(false);
    });

    test("custom max length", () => {
      const result = emailSchema({ email: { maxLength: 10 } }).safeParse("verylongemail@example.com");
      expect(result.success).toBe(false);
    });
  });

  describe("passwordSchema", () => {
    test("accepts strong password", () => {
      const result = passwordSchema().safeParse("StrongPass1");
      expect(result.success).toBe(true);
    });

    test("rejects short password", () => {
      const result = passwordSchema().safeParse("Ab1");
      expect(result.success).toBe(false);
    });

    test("rejects password without uppercase", () => {
      const result = passwordSchema().safeParse("weakpassword1");
      expect(result.success).toBe(false);
    });

    test("rejects password without lowercase", () => {
      const result = passwordSchema().safeParse("STRONGPASSWORD1");
      expect(result.success).toBe(false);
    });

    test("rejects password without digit", () => {
      const result = passwordSchema().safeParse("StrongPassword");
      expect(result.success).toBe(false);
    });

    test("rejects password exceeding max length", () => {
      const long = "Aa1" + "x".repeat(200);
      const result = passwordSchema().safeParse(long);
      expect(result.success).toBe(false);
    });

    test("custom config: require special char", () => {
      const cfg = { password: { minLength: 8, maxLength: 128, requireUppercase: true, requireLowercase: true, requireDigit: true, requireSpecial: true } };
      const fail = passwordSchema(cfg).safeParse("StrongPass1");
      expect(fail.success).toBe(false);

      const pass = passwordSchema(cfg).safeParse("StrongPass1!");
      expect(pass.success).toBe(true);
    });

    test("custom config: relaxed rules", () => {
      const cfg = { password: { minLength: 4, maxLength: 64, requireUppercase: false, requireLowercase: false, requireDigit: false, requireSpecial: false } };
      const result = passwordSchema(cfg).safeParse("weak");
      expect(result.success).toBe(true);
    });

    test("custom messages", () => {
      const cfg = { messages: { passwordTooShort: "Senha muito curta" } as any };
      const result = passwordSchema(cfg).safeParse("Ab1");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((i) => i.message === "Senha muito curta")).toBe(true);
      }
    });
  });

  describe("registrationSchema", () => {
    test("accepts valid registration", () => {
      const result = registrationSchema().safeParse({
        email: "test@example.com",
        password: "StrongPass1",
        passwordConfirmation: "StrongPass1",
      });
      expect(result.success).toBe(true);
    });

    test("rejects mismatched passwords", () => {
      const result = registrationSchema().safeParse({
        email: "test@example.com",
        password: "StrongPass1",
        passwordConfirmation: "DifferentPass1",
      });
      expect(result.success).toBe(false);
    });

    test("rejects extra fields (strict)", () => {
      const result = registrationSchema().safeParse({
        email: "test@example.com",
        password: "StrongPass1",
        passwordConfirmation: "StrongPass1",
        extra: "field",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("loginSchema", () => {
    test("accepts valid login", () => {
      const result = loginSchema().safeParse({
        email: "test@example.com",
        password: "anypassword",
      });
      expect(result.success).toBe(true);
    });

    test("rejects empty password", () => {
      const result = loginSchema().safeParse({
        email: "test@example.com",
        password: "",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("changePasswordSchema", () => {
    test("accepts valid change", () => {
      const result = changePasswordSchema().safeParse({
        currentPassword: "OldPass1",
        newPassword: "NewStrongPass1",
        newPasswordConfirmation: "NewStrongPass1",
      });
      expect(result.success).toBe(true);
    });

    test("rejects mismatched new passwords", () => {
      const result = changePasswordSchema().safeParse({
        currentPassword: "OldPass1",
        newPassword: "NewStrongPass1",
        newPasswordConfirmation: "Different1",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("resetPasswordSchema", () => {
    test("accepts valid reset", () => {
      const result = resetPasswordSchema().safeParse({
        token: "some-token",
        newPassword: "NewStrongPass1",
        newPasswordConfirmation: "NewStrongPass1",
      });
      expect(result.success).toBe(true);
    });

    test("rejects empty token", () => {
      const result = resetPasswordSchema().safeParse({
        token: "",
        newPassword: "NewStrongPass1",
        newPasswordConfirmation: "NewStrongPass1",
      });
      expect(result.success).toBe(false);
    });
  });
});
