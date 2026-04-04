/**
 * @vert/auth — Timeoutable module tests.
 */

import { describe, test, expect } from "bun:test";
import { isTimedOut, touchActivity, timeoutableColumnsSQL } from "../src/timeoutable";
import { createMockAdapter, createTestUser } from "./helpers";

describe("Timeoutable", () => {
  test("not timed out with recent activity", () => {
    const user = createTestUser({ lastActivityAt: new Date() });
    expect(isTimedOut(user)).toBe(false);
  });

  test("timed out after default 30min", () => {
    const user = createTestUser({
      lastActivityAt: new Date(Date.now() - 31 * 60 * 1000),
    });
    expect(isTimedOut(user)).toBe(true);
  });

  test("not timed out without lastActivityAt", () => {
    const user = createTestUser({ lastActivityAt: undefined });
    expect(isTimedOut(user)).toBe(false);
  });

  test("custom timeout config", () => {
    const user = createTestUser({
      lastActivityAt: new Date(Date.now() - 10 * 60 * 1000), // 10 min ago
    });
    // 5 min timeout — should be timed out
    expect(isTimedOut(user, { timeoutIn: 5 * 60 * 1000 })).toBe(true);
    // 15 min timeout — should NOT be timed out
    expect(isTimedOut(user, { timeoutIn: 15 * 60 * 1000 })).toBe(false);
  });

  test("touchActivity updates lastActivityAt", async () => {
    const user = createTestUser({
      lastActivityAt: new Date(Date.now() - 60000),
    });
    const adapter = createMockAdapter([user]);

    const before = user.lastActivityAt!.getTime();
    const updated = await touchActivity(adapter, user.id);
    expect(updated.lastActivityAt!.getTime()).toBeGreaterThan(before);
  });

  test("timeoutableColumnsSQL", () => {
    const sql = timeoutableColumnsSQL();
    expect(sql).toContain("last_activity_at");
  });
});
