/**
 * @vert/auth — Timeoutable module.
 *
 * Session timeout based on lastActivityAt.
 * Configurable timeout with automatic extension.
 */

import type { AuthUser, UserAdapter } from "../types";

export interface TimeoutableConfig {
  /** Session timeout in ms. Default: 30 minutes. */
  timeoutIn: number;
}

const DEFAULT_CONFIG: TimeoutableConfig = {
  timeoutIn: 30 * 60 * 1000,
};

export function isTimedOut<T extends AuthUser>(
  user: T,
  config?: Partial<TimeoutableConfig>,
): boolean {
  const c = { ...DEFAULT_CONFIG, ...config };
  if (!user.lastActivityAt) return false;
  const elapsed = Date.now() - new Date(user.lastActivityAt).getTime();
  return elapsed > c.timeoutIn;
}

export async function touchActivity<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
): Promise<T> {
  return adapter.update(userId, {
    lastActivityAt: new Date(),
  } as Partial<T>);
}

export function timeoutableColumnsSQL(): string {
  return `"last_activity_at" TIMESTAMPTZ`;
}

export const TIMEOUTABLE_COLUMNS = ["last_activity_at"] as const;
