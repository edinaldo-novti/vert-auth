/**
 * @vert/auth — Middleware module tests.
 */

import { describe, test, expect, afterEach } from "bun:test";
import {
  sessionIdFromCookie,
  rememberTokenFromCookie,
  requireAuth,
  unauthorizedResponse,
  authenticateMiddleware,
} from "../src/middleware";
import { hashToken } from "../src/utils";
import { resetAuthConfig, defineAuthConfig } from "../src/config";
import { createMockAdapter, createTestUser } from "./helpers";

afterEach(() => {
  resetAuthConfig();
});

describe("Middleware", () => {
  describe("sessionIdFromCookie", () => {
    test("extracts session_id from cookie header", () => {
      const req = new Request("http://localhost", {
        headers: { cookie: "session_id=abc123; other=val" },
      });
      expect(sessionIdFromCookie(req)).toBe("abc123");
    });

    test("returns null when no cookie", () => {
      const req = new Request("http://localhost");
      expect(sessionIdFromCookie(req)).toBeNull();
    });

    test("returns null when session_id not in cookie", () => {
      const req = new Request("http://localhost", {
        headers: { cookie: "other=val" },
      });
      expect(sessionIdFromCookie(req)).toBeNull();
    });

    test("custom cookie name", () => {
      const req = new Request("http://localhost", {
        headers: { cookie: "my_session=xyz" },
      });
      expect(sessionIdFromCookie(req, "my_session")).toBe("xyz");
    });
  });

  describe("rememberTokenFromCookie", () => {
    test("extracts remember_token from cookie header", () => {
      const req = new Request("http://localhost", {
        headers: { cookie: "remember_token=token123; other=x" },
      });
      expect(rememberTokenFromCookie(req)).toBe("token123");
    });

    test("returns null when missing", () => {
      const req = new Request("http://localhost");
      expect(rememberTokenFromCookie(req)).toBeNull();
    });
  });

  describe("requireAuth", () => {
    test("returns true for valid user", () => {
      const user = createTestUser();
      expect(requireAuth(user)).toBe(true);
    });

    test("returns false for null", () => {
      expect(requireAuth(null)).toBe(false);
    });
  });

  describe("unauthorizedResponse", () => {
    test("returns 401 with JSON body", async () => {
      const res = unauthorizedResponse();
      expect(res.status).toBe(401);
      const body = await res.json();
      expect(body.error).toBe("Unauthorized");
    });

    test("custom message", async () => {
      const res = unauthorizedResponse("Custom error");
      const body = await res.json();
      expect(body.error).toBe("Custom error");
    });
  });

  describe("authenticateMiddleware", () => {
    test("returns user from valid session", async () => {
      defineAuthConfig();
      const user = createTestUser({ lastActivityAt: new Date() });
      const adapter = createMockAdapter([user]);

      const sessionStore = {
        async get(id: string) {
          return id === "valid-session" ? { userId: user.id } : null;
        },
      };

      const req = new Request("http://localhost", {
        headers: { cookie: "session_id=valid-session" },
      });

      const result = await authenticateMiddleware(req, {
        adapter,
        sessionStore,
        getSessionId: (r) => sessionIdFromCookie(r),
      });

      expect(result.user).not.toBeNull();
      expect(result.user!.email).toBe(user.email);
    });

    test("returns null for invalid session", async () => {
      defineAuthConfig();
      const adapter = createMockAdapter([]);

      const sessionStore = {
        async get() { return null; },
      };

      const req = new Request("http://localhost", {
        headers: { cookie: "session_id=invalid" },
      });

      const result = await authenticateMiddleware(req, {
        adapter,
        sessionStore,
        getSessionId: (r) => sessionIdFromCookie(r),
      });

      expect(result.user).toBeNull();
    });

    test("returns null for locked user", async () => {
      defineAuthConfig();
      const user = createTestUser({ lockedAt: new Date(), lastActivityAt: new Date() });
      const adapter = createMockAdapter([user]);

      const sessionStore = {
        async get() { return { userId: user.id }; },
      };

      const req = new Request("http://localhost", {
        headers: { cookie: "session_id=sess" },
      });

      const result = await authenticateMiddleware(req, {
        adapter,
        sessionStore,
        getSessionId: (r) => sessionIdFromCookie(r),
      });

      expect(result.user).toBeNull();
    });

    test("returns null for timed-out user", async () => {
      defineAuthConfig({ timeoutIn: 1000 }); // 1 second
      const user = createTestUser({
        lastActivityAt: new Date(Date.now() - 5000), // 5 seconds ago
      });
      const adapter = createMockAdapter([user]);

      const sessionStore = {
        async get() { return { userId: user.id }; },
      };

      const req = new Request("http://localhost", {
        headers: { cookie: "session_id=sess" },
      });

      const result = await authenticateMiddleware(req, {
        adapter,
        sessionStore,
        getSessionId: (r) => sessionIdFromCookie(r),
      });

      expect(result.user).toBeNull();
    });

    test("falls back to remember token when no session", async () => {
      defineAuthConfig();
      const plainToken = "i".repeat(64);
      const hashed = await hashToken(plainToken);
      const user = createTestUser({ rememberToken: hashed, rememberCreatedAt: new Date() });
      const adapter = createMockAdapter([user]);

      const sessionStore = {
        async get() { return null; },
      };

      const req = new Request("http://localhost", {
        headers: { cookie: `remember_token=${plainToken}` },
      });

      const result = await authenticateMiddleware(req, {
        adapter,
        sessionStore,
        getSessionId: (r) => sessionIdFromCookie(r),
        getRememberToken: (r) => rememberTokenFromCookie(r),
      });

      expect(result.user).not.toBeNull();
      expect(result.newRememberCookie).toBeTruthy();
    });
  });
});
