/**
 * @vert/auth — Recoverable module.
 *
 * Password reset via token. Hash stored in DB, plaintext sent by email.
 * Rate limiting on token generation.
 */

import type { AuthUser, AuthResult, UserAdapter, MailerAdapter } from "../types";
import { generateToken, hashToken } from "../utils";
import { hashPassword } from "../authenticatable";
import { passwordSchema, type ValidatableConfig } from "../validatable";

export interface RecoverableConfig {
  /** Reset token expiry in ms. Default: 6 hours. */
  resetPasswordWithin: number;
  /** Minimum interval between reset emails in ms. Default: 60 seconds. */
  resetPasswordCooldown: number;
}

const DEFAULT_CONFIG: RecoverableConfig = {
  resetPasswordWithin: 6 * 60 * 60 * 1000,
  resetPasswordCooldown: 60 * 1000,
};

export async function sendResetPasswordToken<T extends AuthUser>(
  adapter: UserAdapter<T>,
  email: string,
  mailer: MailerAdapter,
  config?: Partial<RecoverableConfig>,
): Promise<{ success: boolean; error?: string; code?: string }> {
  const c = { ...DEFAULT_CONFIG, ...config };
  const user = await adapter.findByEmail(email.trim().toLowerCase());

  if (!user) {
    // Don't reveal whether user exists — always return success
    return { success: true };
  }

  // Rate limiting: check cooldown
  if (user.resetPasswordSentAt) {
    const elapsed = Date.now() - new Date(user.resetPasswordSentAt).getTime();
    if (elapsed < c.resetPasswordCooldown) {
      return { success: false, error: "Please wait before requesting another reset", code: "RATE_LIMITED" };
    }
  }

  const plainToken = generateToken();
  const hashed = await hashToken(plainToken);

  await adapter.update(user.id, {
    resetPasswordToken: hashed,
    resetPasswordSentAt: new Date(),
  } as Partial<T>);

  await mailer.sendResetPassword(user.email, plainToken);
  return { success: true };
}

export async function resetPassword<T extends AuthUser>(
  adapter: UserAdapter<T>,
  token: string,
  newPassword: string,
  config?: Partial<RecoverableConfig>,
  validationConfig?: Partial<ValidatableConfig>,
): Promise<AuthResult<T>> {
  const c = { ...DEFAULT_CONFIG, ...config };

  // Validate new password strength
  const passwordResult = passwordSchema(validationConfig).safeParse(newPassword);
  if (!passwordResult.success) {
    const msg = passwordResult.error.issues.map((i) => i.message).join("; ");
    return { success: false, error: msg, code: "VALIDATION_ERROR" };
  }

  const hashed = await hashToken(token);
  const user = await adapter.findByToken("resetPasswordToken", hashed);

  if (!user) {
    return { success: false, error: "Invalid reset token", code: "TOKEN_INVALID" };
  }

  // Check expiry
  if (user.resetPasswordSentAt) {
    const elapsed = Date.now() - new Date(user.resetPasswordSentAt).getTime();
    if (elapsed > c.resetPasswordWithin) {
      return { success: false, error: "Reset token has expired", code: "TOKEN_EXPIRED" };
    }
  }

  const encryptedPassword = await hashPassword(newPassword);

  const updated = await adapter.update(user.id, {
    encryptedPassword,
    resetPasswordToken: null,
    resetPasswordSentAt: null,
  } as Partial<T>);

  return { success: true, user: updated };
}

export function recoverableColumnsSQL(): string {
  return [
    `"reset_password_token" VARCHAR(255)`,
    `"reset_password_sent_at" TIMESTAMPTZ`,
  ].join(",\n  ");
}

export const RECOVERABLE_COLUMNS = [
  "reset_password_token",
  "reset_password_sent_at",
] as const;
