/**
 * @vert/auth — Trackable module.
 *
 * Tracks sign-in count, timestamps, and IP addresses.
 */

import type { AuthUser, UserAdapter } from "../types";

export interface TrackableData {
  signInCount: number;
  currentSignInAt: Date;
  lastSignInAt: Date | null;
  currentSignInIp: string;
  lastSignInIp: string | null;
}

export async function trackSignIn<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
  ip: string,
): Promise<T> {
  const user = await adapter.findById(userId);
  if (!user) throw new Error("User not found for tracking");

  return adapter.update(userId, {
    signInCount: (user.signInCount ?? 0) + 1,
    lastSignInAt: user.currentSignInAt ?? null,
    currentSignInAt: new Date(),
    lastSignInIp: user.currentSignInIp ?? null,
    currentSignInIp: ip,
  } as Partial<T>);
}

export function extractIp(request: Request): string {
  // Check common proxy headers
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) {
    // Take the first IP (client IP)
    const first = forwarded.split(",")[0];
    if (first) return first.trim();
  }
  const realIp = request.headers.get("x-real-ip");
  if (realIp) return realIp.trim();
  // Fallback — Bun doesn't expose remoteAddress on Request
  return "0.0.0.0";
}

export function trackableColumnsSQL(): string {
  return [
    `"sign_in_count" INTEGER NOT NULL DEFAULT 0`,
    `"current_sign_in_at" TIMESTAMPTZ`,
    `"last_sign_in_at" TIMESTAMPTZ`,
    `"current_sign_in_ip" VARCHAR(45)`,
    `"last_sign_in_ip" VARCHAR(45)`,
  ].join(",\n  ");
}

export const TRACKABLE_COLUMNS = [
  "sign_in_count",
  "current_sign_in_at",
  "last_sign_in_at",
  "current_sign_in_ip",
  "last_sign_in_ip",
] as const;
