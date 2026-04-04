/**
 * @vert/auth — Authenticatable (Database Authenticatable) module.
 *
 * Password hashing via Bun.password (Argon2id).
 * Credential verification with timing-safe comparison.
 */

import type { AuthUser, AuthResult, UserAdapter } from "../types";

// ─── Argon2id Config (OWASP recommendations) ──────────────────────────────
export interface Argon2Config {
  memoryCost: number; // in KiB
  timeCost: number;
}

const DEFAULT_ARGON2: Argon2Config = {
  memoryCost: 65536, // 64 MB
  timeCost: 3,
};

// ─── Hash & Verify ─────────────────────────────────────────────────────────

export async function hashPassword(
  password: string,
  config?: Partial<Argon2Config>,
): Promise<string> {
  const c = { ...DEFAULT_ARGON2, ...config };
  return Bun.password.hash(password, {
    algorithm: "argon2id",
    memoryCost: c.memoryCost,
    timeCost: c.timeCost,
  });
}

export async function verifyPassword(
  password: string,
  hash: string,
): Promise<boolean> {
  return Bun.password.verify(password, hash);
}

// ─── Authenticate ──────────────────────────────────────────────────────────

export async function authenticate<T extends AuthUser>(
  adapter: UserAdapter<T>,
  email: string,
  password: string,
): Promise<AuthResult<T>> {
  const user = await adapter.findByEmail(email.trim().toLowerCase());

  if (!user) {
    // Perform a dummy hash to prevent timing attacks (consistent response time)
    await Bun.password.hash("dummy-password-timing-safe", { algorithm: "argon2id" });
    return { success: false, error: "Invalid credentials", code: "INVALID_CREDENTIALS" };
  }

  if (user.lockedAt) {
    return { success: false, error: "Account is locked", code: "ACCOUNT_LOCKED" };
  }

  if (user.confirmedAt === null && user.confirmationToken !== undefined) {
    return { success: false, error: "Account not confirmed", code: "ACCOUNT_NOT_CONFIRMED" };
  }

  const valid = await verifyPassword(password, user.encryptedPassword);
  if (!valid) {
    return { success: false, error: "Invalid credentials", code: "INVALID_CREDENTIALS" };
  }

  return { success: true, user };
}

// ─── SQL Schema ────────────────────────────────────────────────────────────

export function authenticatableColumnsSQL(): string {
  return [
    `"email" VARCHAR(255) NOT NULL UNIQUE`,
    `"encrypted_password" VARCHAR(255) NOT NULL`,
  ].join(",\n  ");
}

export const AUTHENTICATABLE_COLUMNS = ["email", "encrypted_password"] as const;
