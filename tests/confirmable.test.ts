/**
 * @vert/auth — Confirmable module tests.
 */

import { describe, test, expect } from "bun:test";
import { generateConfirmationToken, confirm, resendConfirmation, confirmableColumnsSQL } from "../src/confirmable";
import { hashToken } from "../src/utils";
import { createMockAdapter, createTestUser, createMockMailer } from "./helpers";

describe("Confirmable", () => {
  test("generates token, stores hash, sends email", async () => {
    const user = createTestUser({ confirmedAt: null });
    const adapter = createMockAdapter([user]);
    const mailer = createMockMailer();

    const { token } = await generateConfirmationToken(adapter, user.id, mailer);

    expect(token).toBeTruthy();
    expect(token.length).toBe(64); // 32 bytes = 64 hex chars
    expect(mailer.sent.length).toBe(1);
    expect(mailer.sent[0].type).toBe("confirmation");
    expect(mailer.sent[0].email).toBe(user.email);

    // The stored token should be the SHA-256 hash
    const stored = adapter.users[0].confirmationToken;
    const expectedHash = await hashToken(token);
    expect(stored).toBe(expectedHash);
  });

  test("confirms with valid token", async () => {
    const plainToken = "a".repeat(64);
    const hashed = await hashToken(plainToken);
    const user = createTestUser({
      confirmedAt: null,
      confirmationToken: hashed,
      confirmationSentAt: new Date(),
    });
    const adapter = createMockAdapter([user]);

    const result = await confirm(adapter, plainToken);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.user.confirmedAt).toBeTruthy();
      expect(result.user.confirmationToken).toBeNull();
    }
  });

  test("rejects invalid token", async () => {
    const adapter = createMockAdapter([createTestUser()]);
    const result = await confirm(adapter, "invalid-token");
    expect(result.success).toBe(false);
    if (!result.success) expect(result.code).toBe("TOKEN_INVALID");
  });

  test("rejects expired token", async () => {
    const plainToken = "b".repeat(64);
    const hashed = await hashToken(plainToken);
    const user = createTestUser({
      confirmedAt: null,
      confirmationToken: hashed,
      confirmationSentAt: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000), // 4 days ago
    });
    const adapter = createMockAdapter([user]);

    const result = await confirm(adapter, plainToken);
    expect(result.success).toBe(false);
    if (!result.success) expect(result.code).toBe("TOKEN_EXPIRED");
  });

  test("resend does not reveal user existence", async () => {
    const adapter = createMockAdapter([]); // No users
    const mailer = createMockMailer();

    const result = await resendConfirmation(adapter, "nobody@example.com", mailer);
    expect(result.success).toBe(true); // Always returns success
    expect(mailer.sent.length).toBe(0);
  });

  test("resend skips already confirmed user", async () => {
    const user = createTestUser({ confirmedAt: new Date() });
    const adapter = createMockAdapter([user]);
    const mailer = createMockMailer();

    const result = await resendConfirmation(adapter, user.email, mailer);
    expect(result.success).toBe(true);
    expect(mailer.sent.length).toBe(0);
  });

  test("confirmableColumnsSQL returns all columns", () => {
    const sql = confirmableColumnsSQL();
    expect(sql).toContain("confirmation_token");
    expect(sql).toContain("confirmed_at");
    expect(sql).toContain("confirmation_sent_at");
    expect(sql).toContain("unconfirmed_email");
  });
});
