/**
 * @vert/auth — Trackable module tests.
 */

import { describe, test, expect } from "bun:test";
import { trackSignIn, extractIp, trackableColumnsSQL } from "../src/trackable";
import { createMockAdapter, createTestUser } from "./helpers";

describe("Trackable", () => {
  test("increments signInCount and records IP", async () => {
    const user = createTestUser({ signInCount: 0 });
    const adapter = createMockAdapter([user]);

    const updated = await trackSignIn(adapter, user.id, "192.168.1.1");
    expect(updated.signInCount).toBe(1);
    expect(updated.currentSignInIp).toBe("192.168.1.1");
    expect(updated.currentSignInAt).toBeTruthy();
  });

  test("preserves last sign-in data", async () => {
    const prevDate = new Date(Date.now() - 60000);
    const user = createTestUser({
      signInCount: 5,
      currentSignInAt: prevDate,
      currentSignInIp: "10.0.0.1",
    });
    const adapter = createMockAdapter([user]);

    const updated = await trackSignIn(adapter, user.id, "192.168.1.2");
    expect(updated.signInCount).toBe(6);
    expect(updated.lastSignInAt).toEqual(prevDate);
    expect(updated.lastSignInIp).toBe("10.0.0.1");
    expect(updated.currentSignInIp).toBe("192.168.1.2");
  });

  describe("extractIp", () => {
    test("extracts from x-forwarded-for", () => {
      const req = new Request("http://localhost", {
        headers: { "x-forwarded-for": "203.0.113.50, 70.41.3.18" },
      });
      expect(extractIp(req)).toBe("203.0.113.50");
    });

    test("extracts from x-real-ip", () => {
      const req = new Request("http://localhost", {
        headers: { "x-real-ip": "192.168.1.100" },
      });
      expect(extractIp(req)).toBe("192.168.1.100");
    });

    test("returns fallback when no headers", () => {
      const req = new Request("http://localhost");
      expect(extractIp(req)).toBe("0.0.0.0");
    });
  });

  test("trackableColumnsSQL", () => {
    const sql = trackableColumnsSQL();
    expect(sql).toContain("sign_in_count");
    expect(sql).toContain("current_sign_in_at");
    expect(sql).toContain("last_sign_in_at");
    expect(sql).toContain("current_sign_in_ip");
    expect(sql).toContain("last_sign_in_ip");
  });
});
