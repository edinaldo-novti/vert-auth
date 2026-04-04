/**
 * @vert/auth — Config module tests.
 */

import { describe, test, expect, afterEach } from "bun:test";
import { defineAuthConfig, getAuthConfig, resetAuthConfig } from "../src/config";

afterEach(() => {
  resetAuthConfig();
});

describe("Config", () => {
  test("returns defaults when no config defined", () => {
    const config = getAuthConfig();
    expect(config.passwordMinLength).toBe(8);
    expect(config.passwordMaxLength).toBe(128);
    expect(config.passwordRequireUppercase).toBe(true);
    expect(config.passwordRequireLowercase).toBe(true);
    expect(config.passwordRequireDigit).toBe(true);
    expect(config.passwordRequireSpecial).toBe(false);
    expect(config.maximumAttempts).toBe(5);
    expect(config.timeoutIn).toBe(30 * 60 * 1000);
    expect(config.rememberFor).toBe(14 * 24 * 60 * 60 * 1000);
    expect(config.rememberCookieSecure).toBe(true);
    expect(config.rememberCookieSameSite).toBe("Lax");
    expect(config.enableTrackable).toBe(true);
  });

  test("defineAuthConfig overrides defaults", () => {
    const config = defineAuthConfig({
      passwordMinLength: 12,
      maximumAttempts: 3,
      timeoutIn: 15 * 60 * 1000,
      rememberCookieSameSite: "Strict",
    });

    expect(config.passwordMinLength).toBe(12);
    expect(config.maximumAttempts).toBe(3);
    expect(config.timeoutIn).toBe(15 * 60 * 1000);
    expect(config.rememberCookieSameSite).toBe("Strict");
    // Others keep defaults
    expect(config.passwordMaxLength).toBe(128);
  });

  test("getAuthConfig returns same instance after define", () => {
    defineAuthConfig({ passwordMinLength: 10 });
    const c1 = getAuthConfig();
    const c2 = getAuthConfig();
    expect(c1).toBe(c2);
    expect(c1.passwordMinLength).toBe(10);
  });

  test("resetAuthConfig clears config", () => {
    defineAuthConfig({ passwordMinLength: 20 });
    resetAuthConfig();
    // Should return fresh defaults
    const config = getAuthConfig();
    expect(config.passwordMinLength).toBe(8);
  });

  test("rejects invalid passwordMinLength", () => {
    expect(() => defineAuthConfig({ passwordMinLength: 2 })).toThrow();
  });

  test("rejects invalid passwordMaxLength", () => {
    expect(() => defineAuthConfig({ passwordMaxLength: 999 })).toThrow();
  });

  test("rejects invalid maximumAttempts", () => {
    expect(() => defineAuthConfig({ maximumAttempts: 0 })).toThrow();
  });

  test("accepts nullable lockFor", () => {
    const config = defineAuthConfig({ lockFor: null });
    expect(config.lockFor).toBeNull();
  });

  test("oauthProviders defaults to empty", () => {
    const config = getAuthConfig();
    expect(config.oauthProviders).toEqual([]);
  });

  test("oauthProviders with entries", () => {
    const config = defineAuthConfig({
      oauthProviders: [
        {
          name: "google",
          clientId: "test-id",
          clientSecret: "test-secret-do-not-use-in-production",
          redirectUri: "http://localhost/cb",
          scopes: ["openid", "email"],
        },
      ],
    });
    expect(config.oauthProviders.length).toBe(1);
    expect(config.oauthProviders[0].name).toBe("google");
  });
});
