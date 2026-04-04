/**
 * @vert/auth — Rememberable module tests.
 */

import { describe, test, expect } from "bun:test";
import {
  generateRememberToken,
  validateRememberToken,
  clearRememberToken,
  buildRememberCookie,
  buildClearRememberCookie,
  rememberableColumnsSQL,
} from "../src/rememberable";
import { hashToken } from "../src/utils";
import { createMockAdapter, createTestUser } from "./helpers";

describe("Rememberable", () => {
  test("generates remember token and stores hash", async () => {
    const user = createTestUser();
    const adapter = createMockAdapter([user]);

    const { token } = await generateRememberToken(adapter, user.id);
    expect(token.length).toBe(64);

    const stored = adapter.users[0].rememberToken;
    const expected = await hashToken(token);
    expect(stored).toBe(expected);
    expect(adapter.users[0].rememberCreatedAt).toBeTruthy();
  });

  test("validates token and rotates", async () => {
    const plainToken = "f".repeat(64);
    const hashed = await hashToken(plainToken);
    const user = createTestUser({ rememberToken: hashed, rememberCreatedAt: new Date() });
    const adapter = createMockAdapter([user]);

    const result = await validateRememberToken(adapter, plainToken);
    expect(result.success).toBe(true);

    // Token should have been rotated
    const newStored = adapter.users[0].rememberToken;
    expect(newStored).not.toBe(hashed);
  });

  test("rejects invalid remember token", async () => {
    const adapter = createMockAdapter([createTestUser()]);
    const result = await validateRememberToken(adapter, "invalid");
    expect(result.success).toBe(false);
    if (!result.success) expect(result.code).toBe("TOKEN_INVALID");
  });

  test("rejects expired remember token", async () => {
    const plainToken = "g".repeat(64);
    const hashed = await hashToken(plainToken);
    const user = createTestUser({
      rememberToken: hashed,
      rememberCreatedAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000), // 15 days ago
    });
    const adapter = createMockAdapter([user]);

    const result = await validateRememberToken(adapter, plainToken);
    expect(result.success).toBe(false);
    if (!result.success) expect(result.code).toBe("TOKEN_EXPIRED");
  });

  test("clears remember token", async () => {
    const user = createTestUser({ rememberToken: "some-hash", rememberCreatedAt: new Date() });
    const adapter = createMockAdapter([user]);

    await clearRememberToken(adapter, user.id);
    expect(adapter.users[0].rememberToken).toBeNull();
    expect(adapter.users[0].rememberCreatedAt).toBeNull();
  });

  test("buildRememberCookie sets secure attributes", () => {
    const cookie = buildRememberCookie("test-token");
    expect(cookie).toContain("remember_token=test-token");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Expires=");
  });

  test("buildClearRememberCookie expires cookie", () => {
    const cookie = buildClearRememberCookie();
    expect(cookie).toContain("remember_token=");
    expect(cookie).toContain("1970");
  });

  test("rememberableColumnsSQL", () => {
    const sql = rememberableColumnsSQL();
    expect(sql).toContain("remember_token");
    expect(sql).toContain("remember_created_at");
  });
});
