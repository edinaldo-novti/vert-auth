/**
 * @vert/auth — JWT module tests.
 */

import { describe, test, expect, beforeAll } from "bun:test";
import {
  generateJwtKeyPair,
  exportKeyPairToJwk,
  importKeyPairFromJwk,
  signAccessToken,
  signRefreshToken,
  signTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  refreshTokens,
  revokeAccessToken,
  revokeRefreshToken,
  extractBearerToken,
  decodeTokenUnsafe,
  type JwtKeyPair,
  type TokenBlacklist,
} from "../src/jwt";

// ─── In-memory blacklist for tests ─────────────────────────────────────────
function createTestBlacklist(): TokenBlacklist & { store: Set<string>; families: Set<string> } {
  const store = new Set<string>();
  const families = new Set<string>();
  return {
    store,
    families,
    async add(jti: string, _ttl: number) { store.add(jti); },
    async has(jti: string) { return store.has(jti); },
    async revokeFamily(family: string) { families.add(family); },
  };
}

let keyPairES256: JwtKeyPair;
let keyPairRS256: JwtKeyPair;
let keyPairEdDSA: JwtKeyPair;

beforeAll(async () => {
  [keyPairES256, keyPairRS256, keyPairEdDSA] = await Promise.all([
    generateJwtKeyPair("ES256"),
    generateJwtKeyPair("RS256"),
    generateJwtKeyPair("EdDSA"),
  ]);
});

describe("JWT", () => {
  // ─── Key Management ────────────────────────────────────────────────────
  describe("Key Management", () => {
    test("generates ES256 key pair", () => {
      expect(keyPairES256.algorithm).toBe("ES256");
      expect(keyPairES256.privateKey).toBeTruthy();
      expect(keyPairES256.publicKey).toBeTruthy();
    });

    test("generates RS256 key pair", () => {
      expect(keyPairRS256.algorithm).toBe("RS256");
      expect(keyPairRS256.privateKey).toBeTruthy();
    });

    test("generates EdDSA key pair", () => {
      expect(keyPairEdDSA.algorithm).toBe("EdDSA");
      expect(keyPairEdDSA.privateKey).toBeTruthy();
    });

    test("exports and imports key pair to/from JWK", async () => {
      const exported = await exportKeyPairToJwk(keyPairES256);
      expect(exported.privateKey.alg).toBe("ES256");
      expect(exported.publicKey.alg).toBe("ES256");

      const reimported = await importKeyPairFromJwk(
        exported.privateKey,
        exported.publicKey,
        "ES256",
      );
      expect(reimported.algorithm).toBe("ES256");

      // Verify reimported keys work
      const { token } = await signAccessToken(reimported, { sub: "user-1" });
      const result = await verifyAccessToken(reimported, token);
      expect(result.valid).toBe(true);
    });
  });

  // ─── Access Token ──────────────────────────────────────────────────────
  describe("Access Token", () => {
    test("signs and verifies ES256 access token", async () => {
      const { token, jti, expiresAt } = await signAccessToken(keyPairES256, {
        sub: "user-123",
        email: "test@example.com",
      });

      expect(token).toBeTruthy();
      expect(jti.length).toBe(32);
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now());

      const result = await verifyAccessToken(keyPairES256, token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.sub).toBe("user-123");
        expect(result.payload.email).toBe("test@example.com");
        expect(result.payload.type).toBe("access");
        expect(result.payload.jti).toBe(jti);
      }
    });

    test("signs and verifies RS256 access token", async () => {
      const { token } = await signAccessToken(keyPairRS256, {
        sub: "user-456",
      }, { algorithm: "RS256" });

      const result = await verifyAccessToken(keyPairRS256, token);
      expect(result.valid).toBe(true);
      if (result.valid) expect(result.payload.sub).toBe("user-456");
    });

    test("signs and verifies EdDSA access token", async () => {
      const { token } = await signAccessToken(keyPairEdDSA, {
        sub: "user-789",
      }, { algorithm: "EdDSA" });

      const result = await verifyAccessToken(keyPairEdDSA, token);
      expect(result.valid).toBe(true);
      if (result.valid) expect(result.payload.sub).toBe("user-789");
    });

    test("supports custom claims", async () => {
      const { token } = await signAccessToken(keyPairES256, {
        sub: "user-1",
        claims: { role: "admin", tenantId: "t-001" },
      });

      const result = await verifyAccessToken(keyPairES256, token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect((result.payload as any).role).toBe("admin");
        expect((result.payload as any).tenantId).toBe("t-001");
      }
    });

    test("rejects token signed with wrong key", async () => {
      const { token } = await signAccessToken(keyPairES256, { sub: "user-1" });
      const otherKeyPair = await generateJwtKeyPair("ES256");
      const result = await verifyAccessToken(otherKeyPair, token);
      expect(result.valid).toBe(false);
      if (!result.valid) expect(result.code).toBe("TOKEN_INVALID");
    });

    test("rejects expired access token", async () => {
      const { token } = await signAccessToken(keyPairES256, { sub: "user-1" }, {
        accessTokenExpiry: "1s",
      });

      // Wait for expiry
      await new Promise((r) => setTimeout(r, 1500));

      const result = await verifyAccessToken(keyPairES256, token, { clockTolerance: 0 });
      expect(result.valid).toBe(false);
      if (!result.valid) expect(result.code).toBe("TOKEN_EXPIRED");
    });

    test("rejects refresh token passed as access token", async () => {
      const { token } = await signRefreshToken(keyPairES256, { sub: "user-1" });
      const result = await verifyAccessToken(keyPairES256, token);
      expect(result.valid).toBe(false);
      if (!result.valid) expect(result.code).toBe("TOKEN_INVALID");
    });

    test("validates issuer", async () => {
      const { token } = await signAccessToken(keyPairES256, { sub: "user-1" }, {
        issuer: "my-app",
      });
      const result = await verifyAccessToken(keyPairES256, token, { issuer: "other-app" });
      expect(result.valid).toBe(false);
    });

    test("validates audience", async () => {
      const { token } = await signAccessToken(keyPairES256, { sub: "user-1" }, {
        audience: "my-audience",
      });
      const result = await verifyAccessToken(keyPairES256, token, { audience: "other-audience" });
      expect(result.valid).toBe(false);
    });

    test("rejects blacklisted access token", async () => {
      const blacklist = createTestBlacklist();
      const { token, jti } = await signAccessToken(keyPairES256, { sub: "user-1" });

      // First verify succeeds
      const r1 = await verifyAccessToken(keyPairES256, token, { blacklist });
      expect(r1.valid).toBe(true);

      // Add to blacklist
      await blacklist.add(jti, 3600);

      // Second verify fails
      const r2 = await verifyAccessToken(keyPairES256, token, { blacklist });
      expect(r2.valid).toBe(false);
      if (!r2.valid) expect(r2.code).toBe("TOKEN_REVOKED");
    });
  });

  // ─── Refresh Token ─────────────────────────────────────────────────────
  describe("Refresh Token", () => {
    test("signs and verifies refresh token", async () => {
      const { token, jti, family, expiresAt } = await signRefreshToken(keyPairES256, {
        sub: "user-1",
      });

      expect(token).toBeTruthy();
      expect(jti.length).toBe(32);
      expect(family.length).toBe(32);
      expect(expiresAt.getTime()).toBeGreaterThan(Date.now());

      const result = await verifyRefreshToken(keyPairES256, token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.sub).toBe("user-1");
        expect(result.payload.type).toBe("refresh");
        expect(result.payload.family).toBe(family);
      }
    });

    test("preserves family across rotations", async () => {
      const { token, family } = await signRefreshToken(keyPairES256, {
        sub: "user-1",
        family: "my-family-id",
      });

      const result = await verifyRefreshToken(keyPairES256, token);
      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.payload.family).toBe("my-family-id");
      }
    });

    test("rejects access token passed as refresh token", async () => {
      const { token } = await signAccessToken(keyPairES256, { sub: "user-1" });
      const result = await verifyRefreshToken(keyPairES256, token);
      expect(result.valid).toBe(false);
      if (!result.valid) expect(result.code).toBe("TOKEN_INVALID");
    });

    test("blacklisted refresh token triggers family revocation", async () => {
      const blacklist = createTestBlacklist();
      const { token, jti } = await signRefreshToken(keyPairES256, {
        sub: "user-1",
        family: "family-001",
      });

      // Blacklist the token
      await blacklist.add(jti, 86400);

      // Verify detects revocation and triggers family revoke
      const result = await verifyRefreshToken(keyPairES256, token, { blacklist });
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.code).toBe("TOKEN_REVOKED");
      }
      expect(blacklist.families.has("family-001")).toBe(true);
    });
  });

  // ─── Token Pair ────────────────────────────────────────────────────────
  describe("signTokenPair", () => {
    test("returns both access and refresh tokens", async () => {
      const tokens = await signTokenPair(keyPairES256, {
        sub: "user-1",
        email: "pair@example.com",
      });

      expect(tokens.accessToken).toBeTruthy();
      expect(tokens.refreshToken).toBeTruthy();
      expect(tokens.accessTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(tokens.refreshTokenExpiresAt.getTime()).toBeGreaterThan(tokens.accessTokenExpiresAt.getTime());

      // Both are valid
      const accessResult = await verifyAccessToken(keyPairES256, tokens.accessToken);
      const refreshResult = await verifyRefreshToken(keyPairES256, tokens.refreshToken);
      expect(accessResult.valid).toBe(true);
      expect(refreshResult.valid).toBe(true);
    });
  });

  // ─── Refresh / Rotate ─────────────────────────────────────────────────
  describe("refreshTokens", () => {
    test("rotates tokens with valid refresh token", async () => {
      const tokens = await signTokenPair(keyPairES256, {
        sub: "user-1",
        email: "rotate@example.com",
      });

      const result = await refreshTokens(
        keyPairES256,
        tokens.refreshToken,
        async (sub) => ({ email: "rotate@example.com" }),
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.result.tokens.accessToken).toBeTruthy();
        expect(result.result.tokens.refreshToken).toBeTruthy();
        // New tokens should be different
        expect(result.result.tokens.accessToken).not.toBe(tokens.accessToken);
        expect(result.result.tokens.refreshToken).not.toBe(tokens.refreshToken);
      }
    });

    test("blacklists old refresh token on rotation", async () => {
      const blacklist = createTestBlacklist();
      const tokens = await signTokenPair(keyPairES256, {
        sub: "user-1",
        email: "bl@example.com",
      });

      const result = await refreshTokens(
        keyPairES256,
        tokens.refreshToken,
        async () => ({ email: "bl@example.com" }),
        undefined,
        { blacklist },
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(blacklist.store.has(result.result.oldRefreshJti)).toBe(true);
      }
    });

    test("fails when user not found", async () => {
      const tokens = await signTokenPair(keyPairES256, { sub: "ghost" });

      const result = await refreshTokens(
        keyPairES256,
        tokens.refreshToken,
        async () => null, // user not found
      );

      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("TOKEN_INVALID");
    });

    test("fails with invalid refresh token", async () => {
      const result = await refreshTokens(
        keyPairES256,
        "not-a-valid-token",
        async () => ({ email: "x@x.com" }),
      );

      expect(result.success).toBe(false);
      if (!result.success) expect(result.code).toBe("TOKEN_INVALID");
    });

    test("preserves family on rotation", async () => {
      const tokens = await signTokenPair(keyPairES256, {
        sub: "user-1",
        family: "test-family",
      });

      const result = await refreshTokens(
        keyPairES256,
        tokens.refreshToken,
        async () => ({ email: "f@x.com" }),
      );

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.result.family).toBe("test-family");
        // verify new refresh token has same family
        const newRefresh = await verifyRefreshToken(keyPairES256, result.result.tokens.refreshToken);
        expect(newRefresh.valid).toBe(true);
        if (newRefresh.valid) {
          expect(newRefresh.payload.family).toBe("test-family");
        }
      }
    });
  });

  // ─── Revocation ────────────────────────────────────────────────────────
  describe("Revocation", () => {
    test("revokeAccessToken adds jti to blacklist", async () => {
      const blacklist = createTestBlacklist();
      const { token, jti } = await signAccessToken(keyPairES256, { sub: "user-1" });

      const revoked = await revokeAccessToken(keyPairES256, token, blacklist);
      expect(revoked).toBe(true);
      expect(blacklist.store.has(jti)).toBe(true);
    });

    test("revokeRefreshToken adds jti and revokes family", async () => {
      const blacklist = createTestBlacklist();
      const { token, jti, family } = await signRefreshToken(keyPairES256, {
        sub: "user-1",
        family: "revoke-family",
      });

      const revoked = await revokeRefreshToken(keyPairES256, token, blacklist);
      expect(revoked).toBe(true);
      expect(blacklist.store.has(jti)).toBe(true);
      expect(blacklist.families.has("revoke-family")).toBe(true);
    });

    test("revokeAccessToken returns false for invalid token", async () => {
      const blacklist = createTestBlacklist();
      const revoked = await revokeAccessToken(keyPairES256, "invalid", blacklist);
      expect(revoked).toBe(false);
    });
  });

  // ─── Helpers ───────────────────────────────────────────────────────────
  describe("Helpers", () => {
    test("extractBearerToken from Authorization header", () => {
      const req = new Request("http://localhost", {
        headers: { Authorization: "Bearer my-token-123" },
      });
      expect(extractBearerToken(req)).toBe("my-token-123");
    });

    test("extractBearerToken returns null without header", () => {
      const req = new Request("http://localhost");
      expect(extractBearerToken(req)).toBeNull();
    });

    test("extractBearerToken returns null for non-Bearer auth", () => {
      const req = new Request("http://localhost", {
        headers: { Authorization: "Basic dXNlcjpwYXNz" },
      });
      expect(extractBearerToken(req)).toBeNull();
    });

    test("decodeTokenUnsafe decodes payload without verification", async () => {
      const { token } = await signAccessToken(keyPairES256, {
        sub: "user-decode",
        email: "decode@test.com",
      });

      const payload = decodeTokenUnsafe(token);
      expect(payload).not.toBeNull();
      expect(payload!.sub).toBe("user-decode");
      expect((payload as any).email).toBe("decode@test.com");
    });

    test("decodeTokenUnsafe returns null for invalid token", () => {
      expect(decodeTokenUnsafe("not.a.jwt")).toBeNull();
      expect(decodeTokenUnsafe("")).toBeNull();
      expect(decodeTokenUnsafe("single-segment")).toBeNull();
    });
  });

  // ─── Custom Expiry Configs ─────────────────────────────────────────────
  describe("Custom Expiry", () => {
    test("custom access token expiry", async () => {
      const { expiresAt } = await signAccessToken(keyPairES256, { sub: "u1" }, {
        accessTokenExpiry: "1h",
      });
      const diffMs = expiresAt.getTime() - Date.now();
      // Should be ~1 hour (3600s) with some tolerance
      expect(diffMs).toBeGreaterThan(3500 * 1000);
      expect(diffMs).toBeLessThan(3700 * 1000);
    });

    test("custom refresh token expiry", async () => {
      const { expiresAt } = await signRefreshToken(keyPairES256, { sub: "u1" }, {
        refreshTokenExpiry: "30d",
      });
      const diffMs = expiresAt.getTime() - Date.now();
      // Should be ~30 days
      expect(diffMs).toBeGreaterThan(29 * 86400 * 1000);
      expect(diffMs).toBeLessThan(31 * 86400 * 1000);
    });

    test("rejects invalid expiry format", () => {
      expect(
        signAccessToken(keyPairES256, { sub: "u1" }, { accessTokenExpiry: "invalid" })
      ).rejects.toThrow("Invalid expiry format");
    });
  });
});
