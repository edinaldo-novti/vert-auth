/**
 * @vert/auth — Recoverable module tests.
 */

import { describe, test, expect } from "bun:test";
import { sendResetPasswordToken, resetPassword, recoverableColumnsSQL } from "../src/recoverable";
import { hashPassword } from "../src/authenticatable";
import { hashToken } from "../src/utils";
import { createMockAdapter, createTestUser, createMockMailer } from "./helpers";

describe("Recoverable", () => {
  test("sends reset token email", async () => {
    const user = createTestUser();
    const adapter = createMockAdapter([user]);
    const mailer = createMockMailer();

    const result = await sendResetPasswordToken(adapter, user.email, mailer);
    expect(result.success).toBe(true);
    expect(mailer.sent.length).toBe(1);
    expect(mailer.sent[0].type).toBe("reset_password");
  });

  test("does not reveal non-existent user", async () => {
    const adapter = createMockAdapter([]);
    const mailer = createMockMailer();

    const result = await sendResetPasswordToken(adapter, "nobody@example.com", mailer);
    expect(result.success).toBe(true);
    expect(mailer.sent.length).toBe(0);
  });

  test("rate limits rapid requests", async () => {
    const user = createTestUser({ resetPasswordSentAt: new Date() });
    const adapter = createMockAdapter([user]);
    const mailer = createMockMailer();

    const result = await sendResetPasswordToken(adapter, user.email, mailer);
    expect(result.success).toBe(false);
    expect(result.code).toBe("RATE_LIMITED");
  });

  test("allows request after cooldown", async () => {
    const user = createTestUser({
      resetPasswordSentAt: new Date(Date.now() - 120_000), // 2 min ago
    });
    const adapter = createMockAdapter([user]);
    const mailer = createMockMailer();

    const result = await sendResetPasswordToken(adapter, user.email, mailer);
    expect(result.success).toBe(true);
    expect(mailer.sent.length).toBe(1);
  });

  test("resets password with valid token", async () => {
    const plainToken = "c".repeat(64);
    const hashed = await hashToken(plainToken);
    const user = createTestUser({
      resetPasswordToken: hashed,
      resetPasswordSentAt: new Date(),
    });
    const adapter = createMockAdapter([user]);

    const result = await resetPassword(adapter, plainToken, "NewStrongPass1");
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.user.encryptedPassword).toContain("$argon2id$");
      expect(result.user.resetPasswordToken).toBeNull();
    }
  });

  test("rejects invalid reset token", async () => {
    const adapter = createMockAdapter([createTestUser()]);
    const result = await resetPassword(adapter, "invalid-token", "NewStrongPass1");
    expect(result.success).toBe(false);
    if (!result.success) expect(result.code).toBe("TOKEN_INVALID");
  });

  test("rejects expired reset token", async () => {
    const plainToken = "d".repeat(64);
    const hashed = await hashToken(plainToken);
    const user = createTestUser({
      resetPasswordToken: hashed,
      resetPasswordSentAt: new Date(Date.now() - 7 * 60 * 60 * 1000), // 7 hours ago
    });
    const adapter = createMockAdapter([user]);

    const result = await resetPassword(adapter, plainToken, "NewStrongPass1");
    expect(result.success).toBe(false);
    if (!result.success) expect(result.code).toBe("TOKEN_EXPIRED");
  });

  test("rejects weak new password", async () => {
    const plainToken = "e".repeat(64);
    const hashed = await hashToken(plainToken);
    const user = createTestUser({
      resetPasswordToken: hashed,
      resetPasswordSentAt: new Date(),
    });
    const adapter = createMockAdapter([user]);

    const result = await resetPassword(adapter, plainToken, "weak");
    expect(result.success).toBe(false);
    if (!result.success) expect(result.code).toBe("VALIDATION_ERROR");
  });

  test("recoverableColumnsSQL", () => {
    const sql = recoverableColumnsSQL();
    expect(sql).toContain("reset_password_token");
    expect(sql).toContain("reset_password_sent_at");
  });
});
