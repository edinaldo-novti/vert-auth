/**
 * @vert/auth — Lockable module tests.
 */

import { describe, test, expect } from "bun:test";
import {
  recordFailedAttempt,
  resetFailedAttempts,
  isLocked,
  unlockByToken,
  unlockByTime,
  lockableColumnsSQL,
} from "../src/lockable";
import { hashToken } from "../src/utils";
import { createMockAdapter, createTestUser, createMockMailer } from "./helpers";

describe("Lockable", () => {
  describe("recordFailedAttempt", () => {
    test("increments failed attempts", async () => {
      const user = createTestUser({ failedAttempts: 0 });
      const adapter = createMockAdapter([user]);

      const result = await recordFailedAttempt(adapter, user.id);
      expect(result.locked).toBe(false);
      expect(adapter.users[0].failedAttempts).toBe(1);
    });

    test("locks after max attempts (default 5)", async () => {
      const user = createTestUser({ failedAttempts: 4 });
      const adapter = createMockAdapter([user]);

      const result = await recordFailedAttempt(adapter, user.id);
      expect(result.locked).toBe(true);
      expect(adapter.users[0].lockedAt).toBeTruthy();
      expect(adapter.users[0].failedAttempts).toBe(5);
    });

    test("sends unlock email on lock", async () => {
      const user = createTestUser({ failedAttempts: 4 });
      const adapter = createMockAdapter([user]);
      const mailer = createMockMailer();

      await recordFailedAttempt(adapter, user.id, mailer);
      expect(mailer.sent.length).toBe(1);
      expect(mailer.sent[0].type).toBe("unlock");
    });

    test("custom max attempts", async () => {
      const user = createTestUser({ failedAttempts: 2 });
      const adapter = createMockAdapter([user]);

      const result = await recordFailedAttempt(adapter, user.id, undefined, { maximumAttempts: 3 });
      expect(result.locked).toBe(true);
    });

    test("returns locked=false for unknown user", async () => {
      const adapter = createMockAdapter([]);
      const result = await recordFailedAttempt(adapter, "nonexistent");
      expect(result.locked).toBe(false);
    });
  });

  describe("resetFailedAttempts", () => {
    test("resets all lock fields", async () => {
      const user = createTestUser({
        failedAttempts: 5,
        lockedAt: new Date(),
        unlockToken: "some-hash",
      });
      const adapter = createMockAdapter([user]);

      await resetFailedAttempts(adapter, user.id);
      expect(adapter.users[0].failedAttempts).toBe(0);
      expect(adapter.users[0].lockedAt).toBeNull();
      expect(adapter.users[0].unlockToken).toBeNull();
    });
  });

  describe("isLocked", () => {
    test("returns false when not locked", () => {
      const user = createTestUser({ lockedAt: undefined });
      expect(isLocked(user)).toBe(false);
    });

    test("returns true when recently locked", () => {
      const user = createTestUser({ lockedAt: new Date() });
      expect(isLocked(user)).toBe(true);
    });

    test("returns false after lock expiry (time-based unlock)", () => {
      const user = createTestUser({
        lockedAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
      });
      // Default lockFor is 1 hour
      expect(isLocked(user)).toBe(false);
    });

    test("returns true when lockFor is null (indefinite)", () => {
      const user = createTestUser({
        lockedAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000), // 1 year ago
      });
      expect(isLocked(user, { lockFor: null, unlockStrategies: ["email"] })).toBe(true);
    });
  });

  describe("unlockByToken", () => {
    test("unlocks with valid token", async () => {
      const plainToken = "h".repeat(64);
      const hashed = await hashToken(plainToken);
      const user = createTestUser({
        failedAttempts: 5,
        lockedAt: new Date(),
        unlockToken: hashed,
      });
      const adapter = createMockAdapter([user]);

      const result = await unlockByToken(adapter, plainToken);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.user.failedAttempts).toBe(0);
        expect(result.user.lockedAt).toBeNull();
        expect(result.user.unlockToken).toBeNull();
      }
    });

    test("rejects invalid token", async () => {
      const adapter = createMockAdapter([createTestUser()]);
      const result = await unlockByToken(adapter, "invalid-token");
      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("TOKEN_INVALID");
    });
  });

  describe("unlockByTime", () => {
    test("unlocks after lockFor expires", async () => {
      const user = createTestUser({
        failedAttempts: 5,
        lockedAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2h ago
      });
      const adapter = createMockAdapter([user]);

      const result = await unlockByTime(adapter, user.id);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.user.failedAttempts).toBe(0);
      }
    });

    test("rejects if still within lock period", async () => {
      const user = createTestUser({
        failedAttempts: 5,
        lockedAt: new Date(), // just now
      });
      const adapter = createMockAdapter([user]);

      const result = await unlockByTime(adapter, user.id);
      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("ACCOUNT_LOCKED");
    });

    test("rejects indefinite lock", async () => {
      const user = createTestUser({
        lockedAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000),
      });
      const adapter = createMockAdapter([user]);

      const result = await unlockByTime(adapter, user.id, { lockFor: null });
      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("ACCOUNT_LOCKED");
    });
  });

  test("lockableColumnsSQL", () => {
    const sql = lockableColumnsSQL();
    expect(sql).toContain("failed_attempts");
    expect(sql).toContain("locked_at");
    expect(sql).toContain("unlock_token");
  });
});
