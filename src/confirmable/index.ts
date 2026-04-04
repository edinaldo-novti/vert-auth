/**
 * @vert/auth — Confirmable module.
 *
 * Email confirmation via cryptographically secure tokens.
 * Tokens are hashed before storage (plaintext sent to user).
 */

import type { AuthUser, AuthResult, UserAdapter, MailerAdapter } from "../types";
import { generateToken, hashToken } from "../utils";

export interface ConfirmableConfig {
  /** Confirmation token expiry in milliseconds. Default: 3 days. */
  confirmWithin: number;
  /** Allow re-sending confirmation? */
  allowResend: boolean;
}

const DEFAULT_CONFIG: ConfirmableConfig = {
  confirmWithin: 3 * 24 * 60 * 60 * 1000, // 3 days
  allowResend: true,
};

export async function generateConfirmationToken<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
  mailer?: MailerAdapter,
): Promise<{ token: string }> {
  const plainToken = generateToken();
  const hashed = await hashToken(plainToken);

  await adapter.update(userId, {
    confirmationToken: hashed,
    confirmationSentAt: new Date(),
  } as Partial<T>);

  if (mailer) {
    const user = await adapter.findById(userId);
    if (user) {
      await mailer.sendConfirmation(user.email, plainToken);
    }
  }

  return { token: plainToken };
}

export async function confirm<T extends AuthUser>(
  adapter: UserAdapter<T>,
  token: string,
  config?: Partial<ConfirmableConfig>,
): Promise<AuthResult<T>> {
  const c = { ...DEFAULT_CONFIG, ...config };
  const hashed = await hashToken(token);

  const user = await adapter.findByToken("confirmationToken", hashed);
  if (!user) {
    return { success: false, error: "Invalid confirmation token", code: "TOKEN_INVALID" };
  }

  // Check expiry
  if (user.confirmationSentAt) {
    const elapsed = Date.now() - new Date(user.confirmationSentAt).getTime();
    if (elapsed > c.confirmWithin) {
      return { success: false, error: "Confirmation token has expired", code: "TOKEN_EXPIRED" };
    }
  }

  const updated = await adapter.update(user.id, {
    confirmedAt: new Date(),
    confirmationToken: null,
    confirmationSentAt: null,
  } as Partial<T>);

  return { success: true, user: updated };
}

export async function resendConfirmation<T extends AuthUser>(
  adapter: UserAdapter<T>,
  email: string,
  mailer: MailerAdapter,
  config?: Partial<ConfirmableConfig>,
): Promise<{ success: boolean; error?: string }> {
  const c = { ...DEFAULT_CONFIG, ...config };
  if (!c.allowResend) {
    return { success: false, error: "Resend not allowed" };
  }

  const user = await adapter.findByEmail(email.trim().toLowerCase());
  if (!user) {
    // Don't reveal whether user exists
    return { success: true };
  }

  if (user.confirmedAt) {
    return { success: true }; // Already confirmed
  }

  await generateConfirmationToken(adapter, user.id, mailer);
  return { success: true };
}

export function confirmableColumnsSQL(): string {
  return [
    `"confirmation_token" VARCHAR(255)`,
    `"confirmed_at" TIMESTAMPTZ`,
    `"confirmation_sent_at" TIMESTAMPTZ`,
    `"unconfirmed_email" VARCHAR(255)`,
  ].join(",\n  ");
}

export const CONFIRMABLE_COLUMNS = [
  "confirmation_token",
  "confirmed_at",
  "confirmation_sent_at",
  "unconfirmed_email",
] as const;
