/**
 * @vert/auth — Shared crypto utilities.
 * Uses Web Crypto API and timing-safe comparison.
 */

import { timingSafeEqual } from "crypto";

/** Generate a cryptographically secure random token (hex). */
export function generateToken(bytes = 32): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Buffer.from(buf).toString("hex");
}

/** SHA-256 hash of a token for storage (never store plaintext). */
export async function hashToken(token: string): Promise<string> {
  const encoded = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Buffer.from(digest).toString("hex");
}

/** Timing-safe comparison of two strings. */
export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "utf-8"), Buffer.from(b, "utf-8"));
  } catch {
    return false;
  }
}
