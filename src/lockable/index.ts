/**
 * @vert/auth — Lockable module.
 *
 * Account locking after N failed attempts.
 * Unlock via email token or by time.
 * Timing-attack safe.
 */

import type { AuthUser, AuthResult, UserAdapter, MailerAdapter } from "../types";
import { generateToken, hashToken } from "../utils";

export interface LockableConfig {
  /** Max failed attempts before lock. Default: 5. */
  maximumAttempts: number;
  /** Lock duration in ms. Default: 1 hour. null = forever (until email unlock). */
  lockFor: number | null;
  /** Unlock strategies. Default: ["email", "time"]. */
  unlockStrategies: ("email" | "time")[];
}

const DEFAULT_CONFIG: LockableConfig = {
  maximumAttempts: 5,
  lockFor: 60 * 60 * 1000,
  unlockStrategies: ["email", "time"],
};

export async function recordFailedAttempt<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
  mailer?: MailerAdapter,
  config?: Partial<LockableConfig>,
): Promise<{ locked: boolean }> {
  const c = { ...DEFAULT_CONFIG, ...config };
  const user = await adapter.findById(userId);
  if (!user) return { locked: false };

  const attempts = (user.failedAttempts ?? 0) + 1;

  if (attempts >= c.maximumAttempts) {
    // Lock account
    const updates: Partial<T> = {
      failedAttempts: attempts,
      lockedAt: new Date(),
    } as Partial<T>;

    if (c.unlockStrategies.includes("email")) {
      const plainToken = generateToken();
      const hashed = await hashToken(plainToken);
      (updates as Record<string, unknown>).unlockToken = hashed;

      if (mailer) {
        await mailer.sendUnlock(user.email, plainToken);
      }
    }

    await adapter.update(userId, updates);
    return { locked: true };
  }

  await adapter.update(userId, {
    failedAttempts: attempts,
  } as Partial<T>);

  return { locked: false };
}

export function resetFailedAttempts<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
): Promise<T> {
  return adapter.update(userId, {
    failedAttempts: 0,
    lockedAt: null,
    unlockToken: null,
  } as Partial<T>);
}

export function isLocked<T extends AuthUser>(
  user: T,
  config?: Partial<LockableConfig>,
): boolean {
  const c = { ...DEFAULT_CONFIG, ...config };
  if (!user.lockedAt) return false;

  // If time-based unlock is enabled, check if lock expired
  if (c.unlockStrategies.includes("time") && c.lockFor !== null) {
    const elapsed = Date.now() - new Date(user.lockedAt).getTime();
    return elapsed < c.lockFor;
  }

  return true; // Locked indefinitely
}

export async function unlockByToken<T extends AuthUser>(
  adapter: UserAdapter<T>,
  token: string,
): Promise<AuthResult<T>> {
  const hashed = await hashToken(token);
  const user = await adapter.findByToken("unlockToken", hashed);

  if (!user) {
    return { success: false, error: "Invalid unlock token", code: "TOKEN_INVALID" };
  }

  const updated = await adapter.update(user.id, {
    failedAttempts: 0,
    lockedAt: null,
    unlockToken: null,
  } as Partial<T>);

  return { success: true, user: updated };
}

export async function unlockByTime<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
  config?: Partial<LockableConfig>,
): Promise<AuthResult<T>> {
  const c = { ...DEFAULT_CONFIG, ...config };
  const user = await adapter.findById(userId);
  if (!user) {
    return { success: false, error: "User not found", code: "USER_NOT_FOUND" };
  }

  if (!user.lockedAt) {
    return { success: true, user };
  }

  if (c.lockFor === null) {
    return { success: false, error: "Account is locked", code: "ACCOUNT_LOCKED" };
  }

  const elapsed = Date.now() - new Date(user.lockedAt).getTime();
  if (elapsed < c.lockFor) {
    return { success: false, error: "Account is still locked", code: "ACCOUNT_LOCKED" };
  }

  const updated = await adapter.update(user.id, {
    failedAttempts: 0,
    lockedAt: null,
    unlockToken: null,
  } as Partial<T>);

  return { success: true, user: updated };
}

export function lockableColumnsSQL(): string {
  return [
    `"failed_attempts" INTEGER NOT NULL DEFAULT 0`,
    `"locked_at" TIMESTAMPTZ`,
    `"unlock_token" VARCHAR(255)`,
  ].join(",\n  ");
}

export const LOCKABLE_COLUMNS = [
  "failed_attempts",
  "locked_at",
  "unlock_token",
] as const;
