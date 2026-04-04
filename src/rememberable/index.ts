/**
 * @vert/auth — Rememberable module.
 *
 * "Remember me" cookie tokens with rotation on each use.
 * HttpOnly, Secure, SameSite=Lax.
 */

import type { AuthUser, AuthResult, UserAdapter } from "../types";
import { generateToken, hashToken } from "../utils";

export interface RememberableConfig {
  /** Cookie name. Default: "remember_token". */
  cookieName: string;
  /** Remember duration in ms. Default: 14 days. */
  rememberFor: number;
  /** Cookie path. Default: "/". */
  cookiePath: string;
  /** SameSite attribute. Default: "Lax". */
  sameSite: "Strict" | "Lax" | "None";
  /** Secure flag (HTTPS only). Default: true. */
  secure: boolean;
}

const DEFAULT_CONFIG: RememberableConfig = {
  cookieName: "remember_token",
  rememberFor: 14 * 24 * 60 * 60 * 1000,
  cookiePath: "/",
  sameSite: "Lax",
  secure: true,
};

export async function generateRememberToken<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
): Promise<{ token: string }> {
  const plainToken = generateToken();
  const hashed = await hashToken(plainToken);

  await adapter.update(userId, {
    rememberToken: hashed,
    rememberCreatedAt: new Date(),
  } as Partial<T>);

  return { token: plainToken };
}

export async function validateRememberToken<T extends AuthUser>(
  adapter: UserAdapter<T>,
  token: string,
  config?: Partial<RememberableConfig>,
): Promise<AuthResult<T>> {
  const c = { ...DEFAULT_CONFIG, ...config };
  const hashed = await hashToken(token);

  const user = await adapter.findByToken("rememberToken", hashed);
  if (!user) {
    return { success: false, error: "Invalid remember token", code: "TOKEN_INVALID" };
  }

  // Check expiry
  if (user.rememberCreatedAt) {
    const elapsed = Date.now() - new Date(user.rememberCreatedAt).getTime();
    if (elapsed > c.rememberFor) {
      // Clear expired token
      await adapter.update(user.id, {
        rememberToken: null,
        rememberCreatedAt: null,
      } as Partial<T>);
      return { success: false, error: "Remember token has expired", code: "TOKEN_EXPIRED" };
    }
  }

  // Rotate token on every use
  const newPlain = generateToken();
  const newHashed = await hashToken(newPlain);
  const updated = await adapter.update(user.id, {
    rememberToken: newHashed,
    rememberCreatedAt: new Date(),
  } as Partial<T>);

  return { success: true, user: Object.assign(updated, { __newRememberToken: newPlain }) };
}

export function clearRememberToken<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
): Promise<T> {
  return adapter.update(userId, {
    rememberToken: null,
    rememberCreatedAt: null,
  } as Partial<T>);
}

export function buildRememberCookie(
  token: string,
  config?: Partial<RememberableConfig>,
): string {
  const c = { ...DEFAULT_CONFIG, ...config };
  const expires = new Date(Date.now() + c.rememberFor).toUTCString();
  const parts = [
    `${c.cookieName}=${token}`,
    `Path=${c.cookiePath}`,
    `Expires=${expires}`,
    `HttpOnly`,
    `SameSite=${c.sameSite}`,
  ];
  if (c.secure) parts.push("Secure");
  return parts.join("; ");
}

export function buildClearRememberCookie(
  config?: Partial<RememberableConfig>,
): string {
  const c = { ...DEFAULT_CONFIG, ...config };
  return [
    `${c.cookieName}=`,
    `Path=${c.cookiePath}`,
    `Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
    `HttpOnly`,
    `SameSite=${c.sameSite}`,
  ].join("; ");
}

export function rememberableColumnsSQL(): string {
  return [
    `"remember_token" VARCHAR(255)`,
    `"remember_created_at" TIMESTAMPTZ`,
  ].join(",\n  ");
}

export const REMEMBERABLE_COLUMNS = [
  "remember_token",
  "remember_created_at",
] as const;
