/**
 * @vert/auth — JWT module.
 *
 * Full JWT support using `jose` library.
 * Supports RS256, ES256, EdDSA (asymmetric only — NEVER HS256 with weak secret).
 *
 * Features:
 * - Key pair generation (RSA, EC P-256, Ed25519)
 * - Access + Refresh token signing/verification
 * - Token rotation (refresh → new access + new refresh)
 * - Blacklist interface for token revocation
 * - JWK export/import for key management
 * - Claims validation (exp, iss, aud, sub, jti)
 */

import {
  SignJWT,
  jwtVerify,
  generateKeyPair,
  importJWK,
  exportJWK,
  type JWTPayload,
  type CryptoKey as JoseCryptoKey,
} from "jose";
import { generateToken } from "../utils";

// ─── Types ─────────────────────────────────────────────────────────────────

export type JwtAlgorithm = "RS256" | "ES256" | "EdDSA";

export interface JwtConfig {
  /** Signing algorithm. Default: "ES256". */
  algorithm: JwtAlgorithm;
  /** Issuer claim (iss). */
  issuer: string;
  /** Audience claim (aud). */
  audience: string;
  /** Access token expiration (e.g., "15m", "1h"). Default: "15m". */
  accessTokenExpiry: string;
  /** Refresh token expiration (e.g., "7d", "30d"). Default: "7d". */
  refreshTokenExpiry: string;
  /** Rotate refresh token on every use. Default: true. */
  rotateRefreshTokens: boolean;
}

export interface JwtKeyPair {
  privateKey: JoseCryptoKey;
  publicKey: JoseCryptoKey;
  algorithm: JwtAlgorithm;
}

export interface JwtTokens {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: Date;
  refreshTokenExpiresAt: Date;
}

export interface JwtAccessPayload extends JWTPayload {
  sub: string;
  email?: string;
  type: "access";
  jti: string;
}

export interface JwtRefreshPayload extends JWTPayload {
  sub: string;
  type: "refresh";
  jti: string;
  /** Family ID for rotation tracking (detect reuse). */
  family: string;
}

/** Blacklist adapter — consumers implement to persist revoked tokens. */
export interface TokenBlacklist {
  /** Add a token (by jti) to the blacklist. ttl = seconds until auto-purge. */
  add(jti: string, ttl: number): Promise<void>;
  /** Check if a token (by jti) is blacklisted. */
  has(jti: string): Promise<boolean>;
  /** Revoke all tokens in a family (for refresh token rotation detection). */
  revokeFamily?(family: string): Promise<void>;
}

// ─── Default Config ────────────────────────────────────────────────────────

const DEFAULT_CONFIG: JwtConfig = {
  algorithm: "ES256",
  issuer: "vert-auth",
  audience: "vert-app",
  accessTokenExpiry: "15m",
  refreshTokenExpiry: "7d",
  rotateRefreshTokens: true,
};

// ─── Key Management ────────────────────────────────────────────────────────

/**
 * Generate a new key pair for JWT signing.
 * Supports RS256 (RSA 2048), ES256 (EC P-256), EdDSA (Ed25519).
 */
export async function generateJwtKeyPair(
  algorithm: JwtAlgorithm = "ES256",
): Promise<JwtKeyPair> {
  const { privateKey, publicKey } = await generateKeyPair(algorithm, {
    extractable: true,
  });
  return { privateKey, publicKey, algorithm };
}

/** Export key pair to JWK format (for persistence). */
export async function exportKeyPairToJwk(
  keyPair: JwtKeyPair,
): Promise<{ privateKey: Record<string, unknown>; publicKey: Record<string, unknown> }> {
  const [priv, pub] = await Promise.all([
    exportJWK(keyPair.privateKey),
    exportJWK(keyPair.publicKey),
  ]);
  return {
    privateKey: { ...priv, alg: keyPair.algorithm },
    publicKey: { ...pub, alg: keyPair.algorithm },
  };
}

/** Import key pair from JWK format. */
export async function importKeyPairFromJwk(
  privateJwk: Record<string, unknown>,
  publicJwk: Record<string, unknown>,
  algorithm: JwtAlgorithm,
): Promise<JwtKeyPair> {
  const [privateKey, publicKey] = await Promise.all([
    importJWK(privateJwk, algorithm),
    importJWK(publicJwk, algorithm),
  ]);
  return {
    privateKey: privateKey as JoseCryptoKey,
    publicKey: publicKey as JoseCryptoKey,
    algorithm,
  };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function parseExpiry(expiry: string): number {
  const match = expiry.match(/^(\d+)(s|m|h|d)$/);
  if (!match || !match[1] || !match[2]) throw new Error(`Invalid expiry format: "${expiry}". Use e.g. "15m", "1h", "7d".`);
  const value = parseInt(match[1], 10);
  const unit = match[2] as "s" | "m" | "h" | "d";
  const multipliers: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return value * (multipliers[unit] ?? 1);
}

// ─── Sign ──────────────────────────────────────────────────────────────────

/**
 * Sign an access token.
 */
export async function signAccessToken(
  keyPair: JwtKeyPair,
  payload: { sub: string; email?: string; claims?: Record<string, unknown> },
  config?: Partial<JwtConfig>,
): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const c = { ...DEFAULT_CONFIG, ...config };
  const jti = generateToken(16); // 32 hex chars
  const expirySeconds = parseExpiry(c.accessTokenExpiry);
  const expiresAt = new Date(Date.now() + expirySeconds * 1000);

  const jwt = new SignJWT({
    type: "access" as const,
    email: payload.email,
    jti,
    ...payload.claims,
  } satisfies Record<string, unknown>)
    .setProtectedHeader({ alg: c.algorithm })
    .setSubject(payload.sub)
    .setIssuer(c.issuer)
    .setAudience(c.audience)
    .setIssuedAt()
    .setExpirationTime(`${expirySeconds}s`);

  const token = await jwt.sign(keyPair.privateKey);
  return { token, jti, expiresAt };
}

/**
 * Sign a refresh token.
 */
export async function signRefreshToken(
  keyPair: JwtKeyPair,
  payload: { sub: string; family?: string },
  config?: Partial<JwtConfig>,
): Promise<{ token: string; jti: string; family: string; expiresAt: Date }> {
  const c = { ...DEFAULT_CONFIG, ...config };
  const jti = generateToken(16);
  const family = payload.family ?? generateToken(16);
  const expirySeconds = parseExpiry(c.refreshTokenExpiry);
  const expiresAt = new Date(Date.now() + expirySeconds * 1000);

  const jwt = new SignJWT({
    type: "refresh" as const,
    family,
    jti,
  } satisfies Record<string, unknown>)
    .setProtectedHeader({ alg: c.algorithm })
    .setSubject(payload.sub)
    .setIssuer(c.issuer)
    .setAudience(c.audience)
    .setIssuedAt()
    .setExpirationTime(`${expirySeconds}s`);

  const token = await jwt.sign(keyPair.privateKey);
  return { token, jti, family, expiresAt };
}

/**
 * Sign both access + refresh tokens as a pair.
 */
export async function signTokenPair(
  keyPair: JwtKeyPair,
  payload: { sub: string; email?: string; claims?: Record<string, unknown>; family?: string },
  config?: Partial<JwtConfig>,
): Promise<JwtTokens> {
  const [access, refresh] = await Promise.all([
    signAccessToken(keyPair, payload, config),
    signRefreshToken(keyPair, { sub: payload.sub, family: payload.family }, config),
  ]);

  return {
    accessToken: access.token,
    refreshToken: refresh.token,
    accessTokenExpiresAt: access.expiresAt,
    refreshTokenExpiresAt: refresh.expiresAt,
  };
}

// ─── Verify ────────────────────────────────────────────────────────────────

export interface VerifyOptions {
  /** Expected issuer. */
  issuer?: string;
  /** Expected audience. */
  audience?: string;
  /** Token blacklist to check revocation. */
  blacklist?: TokenBlacklist;
  /** Required clock tolerance in seconds. Default: 5. */
  clockTolerance?: number;
}

/**
 * Verify and decode an access token.
 */
export async function verifyAccessToken(
  keyPair: JwtKeyPair,
  token: string,
  options?: VerifyOptions,
): Promise<
  | { valid: true; payload: JwtAccessPayload }
  | { valid: false; error: string; code: "TOKEN_EXPIRED" | "TOKEN_INVALID" | "TOKEN_REVOKED" }
> {
  try {
    const result = await jwtVerify(token, keyPair.publicKey, {
      issuer: options?.issuer ?? DEFAULT_CONFIG.issuer,
      audience: options?.audience ?? DEFAULT_CONFIG.audience,
      clockTolerance: options?.clockTolerance ?? 5,
    });

    const payload = result.payload as JwtAccessPayload;

    if (payload.type !== "access") {
      return { valid: false, error: "Not an access token", code: "TOKEN_INVALID" };
    }

    if (!payload.sub || !payload.jti) {
      return { valid: false, error: "Missing required claims", code: "TOKEN_INVALID" };
    }

    // Check blacklist
    if (options?.blacklist) {
      const revoked = await options.blacklist.has(payload.jti);
      if (revoked) {
        return { valid: false, error: "Token has been revoked", code: "TOKEN_REVOKED" };
      }
    }

    return { valid: true, payload };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("exp") || message.includes("expired")) {
      return { valid: false, error: "Access token expired", code: "TOKEN_EXPIRED" };
    }
    return { valid: false, error: `Invalid access token: ${message}`, code: "TOKEN_INVALID" };
  }
}

/**
 * Verify and decode a refresh token.
 */
export async function verifyRefreshToken(
  keyPair: JwtKeyPair,
  token: string,
  options?: VerifyOptions,
): Promise<
  | { valid: true; payload: JwtRefreshPayload }
  | { valid: false; error: string; code: "TOKEN_EXPIRED" | "TOKEN_INVALID" | "TOKEN_REVOKED" }
> {
  try {
    const result = await jwtVerify(token, keyPair.publicKey, {
      issuer: options?.issuer ?? DEFAULT_CONFIG.issuer,
      audience: options?.audience ?? DEFAULT_CONFIG.audience,
      clockTolerance: options?.clockTolerance ?? 5,
    });

    const payload = result.payload as JwtRefreshPayload;

    if (payload.type !== "refresh") {
      return { valid: false, error: "Not a refresh token", code: "TOKEN_INVALID" };
    }

    if (!payload.sub || !payload.jti || !payload.family) {
      return { valid: false, error: "Missing required claims", code: "TOKEN_INVALID" };
    }

    // Check blacklist
    if (options?.blacklist) {
      const revoked = await options.blacklist.has(payload.jti);
      if (revoked) {
        // Potential token reuse — revoke entire family
        if (options.blacklist.revokeFamily) {
          await options.blacklist.revokeFamily(payload.family);
        }
        return { valid: false, error: "Refresh token reused (revoked)", code: "TOKEN_REVOKED" };
      }
    }

    return { valid: true, payload };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("exp") || message.includes("expired")) {
      return { valid: false, error: "Refresh token expired", code: "TOKEN_EXPIRED" };
    }
    return { valid: false, error: `Invalid refresh token: ${message}`, code: "TOKEN_INVALID" };
  }
}

// ─── Refresh / Rotate ──────────────────────────────────────────────────────

export interface RefreshResult {
  tokens: JwtTokens;
  /** The jti of the old refresh token (should be blacklisted). */
  oldRefreshJti: string;
  /** The family of the refresh token chain. */
  family: string;
}

/**
 * Rotate tokens: verify refresh token, issue new access + refresh pair.
 * Old refresh token jti is returned for blacklisting.
 */
export async function refreshTokens(
  keyPair: JwtKeyPair,
  refreshToken: string,
  getUserPayload: (sub: string) => Promise<{ email?: string; claims?: Record<string, unknown> } | null>,
  config?: Partial<JwtConfig>,
  options?: VerifyOptions,
): Promise<
  | { success: true; result: RefreshResult }
  | { success: false; error: string; code: "TOKEN_EXPIRED" | "TOKEN_INVALID" | "TOKEN_REVOKED" }
> {
  const c = { ...DEFAULT_CONFIG, ...config };

  const verification = await verifyRefreshToken(keyPair, refreshToken, options);
  if (!verification.valid) {
    return { success: false, error: verification.error, code: verification.code };
  }

  const { sub, jti: oldJti, family } = verification.payload;

  // Fetch fresh user data for new access token
  const userData = await getUserPayload(sub);
  if (!userData) {
    return { success: false, error: "User not found", code: "TOKEN_INVALID" };
  }

  // Blacklist old refresh token
  if (options?.blacklist) {
    const refreshTtl = parseExpiry(c.refreshTokenExpiry);
    await options.blacklist.add(oldJti, refreshTtl);
  }

  // Sign new token pair (same family for rotation tracking)
  const newFamily = c.rotateRefreshTokens ? family : undefined;
  const tokens = await signTokenPair(
    keyPair,
    { sub, email: userData.email, claims: userData.claims, family: newFamily },
    config,
  );

  return {
    success: true,
    result: {
      tokens,
      oldRefreshJti: oldJti,
      family,
    },
  };
}

// ─── Revocation ────────────────────────────────────────────────────────────

/**
 * Revoke an access token by adding its jti to the blacklist.
 */
export async function revokeAccessToken(
  keyPair: JwtKeyPair,
  token: string,
  blacklist: TokenBlacklist,
  config?: Partial<JwtConfig>,
): Promise<boolean> {
  const c = { ...DEFAULT_CONFIG, ...config };
  try {
    const result = await jwtVerify(token, keyPair.publicKey, {
      issuer: c.issuer,
      audience: c.audience,
      clockTolerance: 60, // generous tolerance for revocation
    });
    const jti = result.payload.jti;
    if (!jti) return false;
    const ttl = parseExpiry(c.accessTokenExpiry);
    await blacklist.add(jti, ttl);
    return true;
  } catch {
    // Token might already be expired — still try to extract jti
    // For security, we can't blacklist a token we can't verify
    return false;
  }
}

/**
 * Revoke a refresh token by adding its jti to the blacklist.
 */
export async function revokeRefreshToken(
  keyPair: JwtKeyPair,
  token: string,
  blacklist: TokenBlacklist,
  config?: Partial<JwtConfig>,
): Promise<boolean> {
  const c = { ...DEFAULT_CONFIG, ...config };
  try {
    const result = await jwtVerify(token, keyPair.publicKey, {
      issuer: c.issuer,
      audience: c.audience,
      clockTolerance: 60,
    });
    const payload = result.payload as JwtRefreshPayload;
    if (!payload.jti) return false;
    const ttl = parseExpiry(c.refreshTokenExpiry);
    await blacklist.add(payload.jti, ttl);
    // Also revoke entire family if adapter supports it
    if (payload.family && blacklist.revokeFamily) {
      await blacklist.revokeFamily(payload.family);
    }
    return true;
  } catch {
    return false;
  }
}

// ─── Token Extraction Helper ───────────────────────────────────────────────

/**
 * Extract bearer token from Authorization header.
 */
export function extractBearerToken(req: Request): string | null {
  const auth = req.headers.get("authorization");
  if (!auth) return null;
  const match = auth.match(/^Bearer\s+(\S+)$/i);
  return match?.[1] ?? null;
}

// ─── Decode Without Verify (inspection only) ──────────────────────────────

/**
 * Decode a JWT payload WITHOUT verifying the signature.
 * Use ONLY for logging/debugging — never trust the payload for authorization.
 */
export function decodeTokenUnsafe(token: string): JWTPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[1]) return null;
    const payload = JSON.parse(atob(parts[1]));
    return payload;
  } catch {
    return null;
  }
}
