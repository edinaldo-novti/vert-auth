/**
 * @vert/auth — Authentication middleware for Bun.serve.
 *
 * Provides authenticate, requireAuth, timeoutable, and JWT middleware.
 */

import type { AuthUser, UserAdapter } from "../types";
import { isTimedOut, touchActivity } from "../timeoutable";
import { isLocked } from "../lockable";
import { getAuthConfig } from "../config";
import { validateRememberToken } from "../rememberable";
import {
  extractBearerToken,
  verifyAccessToken,
  type JwtKeyPair,
  type JwtAccessPayload,
  type VerifyOptions,
  type TokenBlacklist,
} from "../jwt";

export interface AuthRequest extends Request {
  __authUser?: AuthUser;
}

type SessionStore = {
  get(sessionId: string): Promise<{ userId: string } | null>;
  touch?(sessionId: string): Promise<void>;
};

export interface AuthMiddlewareOptions<T extends AuthUser = AuthUser> {
  adapter: UserAdapter<T>;
  sessionStore: SessionStore;
  getSessionId: (req: Request) => string | null;
  getRememberToken?: (req: Request) => string | null;
}

/**
 * Extracts session ID from cookie header.
 */
export function sessionIdFromCookie(
  req: Request,
  cookieName = "session_id",
): string | null {
  const cookie = req.headers.get("cookie");
  if (!cookie) return null;
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]+)`));
  return match?.[1] ?? null;
}

/**
 * Extracts remember token from cookie header.
 */
export function rememberTokenFromCookie(
  req: Request,
  cookieName = "remember_token",
): string | null {
  const cookie = req.headers.get("cookie");
  if (!cookie) return null;
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${cookieName}=([^;]+)`));
  return match?.[1] ?? null;
}

/**
 * Authenticate middleware — resolves the current user from session.
 * Does NOT block unauthenticated requests (use requireAuth for that).
 */
export async function authenticateMiddleware<T extends AuthUser>(
  req: Request,
  options: AuthMiddlewareOptions<T>,
): Promise<{ user: T | null; newRememberCookie?: string }> {
  const config = getAuthConfig();

  // 1. Try session
  const sessionId = options.getSessionId(req);
  if (sessionId) {
    const session = await options.sessionStore.get(sessionId);
    if (session) {
      const user = await options.adapter.findById(session.userId);
      if (user) {
        // Check lock
        if (isLocked(user, { maximumAttempts: config.maximumAttempts, lockFor: config.lockFor, unlockStrategies: config.unlockStrategies })) {
          return { user: null };
        }

        // Check timeout
        if (isTimedOut(user, { timeoutIn: config.timeoutIn })) {
          return { user: null };
        }

        // Touch activity
        const updated = await touchActivity(options.adapter, user.id);
        if (options.sessionStore.touch) {
          await options.sessionStore.touch(sessionId);
        }
        return { user: updated };
      }
    }
  }

  // 2. Try remember token
  const getRemember = options.getRememberToken ?? ((r: Request) => rememberTokenFromCookie(r));
  const rememberToken = getRemember(req);
  if (rememberToken) {
    const result = await validateRememberToken(options.adapter, rememberToken, {
      rememberFor: config.rememberFor,
      cookieName: config.rememberCookieName,
      secure: config.rememberCookieSecure,
      sameSite: config.rememberCookieSameSite,
    });
    if (result.success) {
      const user = result.user as T & { __newRememberToken?: string };
      const newToken = user.__newRememberToken;
      delete user.__newRememberToken;
      return { user, newRememberCookie: newToken };
    }
  }

  return { user: null };
}

/**
 * Guard: responds with 401 if not authenticated.
 */
export function requireAuth<T extends AuthUser>(
  user: T | null,
): user is T {
  return user !== null;
}

/**
 * Build a 401 response.
 */
export function unauthorizedResponse(message = "Unauthorized"): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });
}

// ─── JWT Middleware ─────────────────────────────────────────────────────────

export interface JwtAuthMiddlewareOptions<T extends AuthUser = AuthUser> {
  keyPair: JwtKeyPair;
  adapter: UserAdapter<T>;
  blacklist?: TokenBlacklist;
  verifyOptions?: VerifyOptions;
}

export interface JwtAuthResult<T extends AuthUser = AuthUser> {
  user: T | null;
  payload: JwtAccessPayload | null;
  error?: string;
}

/**
 * JWT authentication middleware — verifies Bearer token and resolves user.
 * Does NOT block — caller decides what to do with null user.
 */
export async function jwtAuthMiddleware<T extends AuthUser>(
  req: Request,
  options: JwtAuthMiddlewareOptions<T>,
): Promise<JwtAuthResult<T>> {
  const token = extractBearerToken(req);
  if (!token) {
    return { user: null, payload: null };
  }

  const result = await verifyAccessToken(options.keyPair, token, {
    ...options.verifyOptions,
    blacklist: options.blacklist,
  });

  if (!result.valid) {
    return { user: null, payload: null, error: result.error };
  }

  const user = await options.adapter.findById(result.payload.sub);
  if (!user) {
    return { user: null, payload: result.payload, error: "User not found" };
  }

  // Check lock
  const config = getAuthConfig();
  if (isLocked(user, { maximumAttempts: config.maximumAttempts, lockFor: config.lockFor, unlockStrategies: config.unlockStrategies })) {
    return { user: null, payload: result.payload, error: "Account is locked" };
  }

  return { user, payload: result.payload };
}

/**
 * Convenience: require JWT auth or 401.
 */
export async function requireJwtAuth<T extends AuthUser>(
  req: Request,
  options: JwtAuthMiddlewareOptions<T>,
): Promise<{ user: T; payload: JwtAccessPayload } | Response> {
  const result = await jwtAuthMiddleware(req, options);
  if (!result.user || !result.payload) {
    return unauthorizedResponse(result.error ?? "Unauthorized");
  }
  return { user: result.user, payload: result.payload };
}
