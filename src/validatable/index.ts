/**
 * @vert/auth — Validatable module.
 *
 * Zod-based schemas for email and password validation.
 * Configurable rules, I18n-ready error messages.
 */

import { z } from "zod";

// ─── Default Config ────────────────────────────────────────────────────────

export interface ValidatableConfig {
  password: {
    minLength: number;
    maxLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireDigit: boolean;
    requireSpecial: boolean;
  };
  email: {
    maxLength: number;
  };
  messages: ValidatableMessages;
}

export interface ValidatableMessages {
  emailRequired: string;
  emailInvalid: string;
  emailTooLong: string;
  passwordRequired: string;
  passwordTooShort: string;
  passwordTooLong: string;
  passwordRequiresUppercase: string;
  passwordRequiresLowercase: string;
  passwordRequiresDigit: string;
  passwordRequiresSpecial: string;
}

const DEFAULT_MESSAGES: ValidatableMessages = {
  emailRequired: "Email is required",
  emailInvalid: "Email is invalid",
  emailTooLong: "Email is too long",
  passwordRequired: "Password is required",
  passwordTooShort: "Password is too short",
  passwordTooLong: "Password is too long",
  passwordRequiresUppercase: "Password must contain at least one uppercase letter",
  passwordRequiresLowercase: "Password must contain at least one lowercase letter",
  passwordRequiresDigit: "Password must contain at least one digit",
  passwordRequiresSpecial: "Password must contain at least one special character",
};

const DEFAULT_CONFIG: ValidatableConfig = {
  password: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireDigit: true,
    requireSpecial: false,
  },
  email: {
    maxLength: 255,
  },
  messages: DEFAULT_MESSAGES,
};

// ─── Schema Builders ───────────────────────────────────────────────────────

export function emailSchema(config?: Partial<ValidatableConfig>) {
  const c = { ...DEFAULT_CONFIG, ...config };
  const m = { ...DEFAULT_MESSAGES, ...config?.messages };

  return z
    .string({ required_error: m.emailRequired })
    .transform((v) => v.trim().toLowerCase())
    .pipe(
      z.string()
        .email(m.emailInvalid)
        .max(c.email.maxLength, m.emailTooLong)
    );
}

export function passwordSchema(config?: Partial<ValidatableConfig>): z.ZodString {
  const pc = { ...DEFAULT_CONFIG.password, ...config?.password };
  const m = { ...DEFAULT_MESSAGES, ...config?.messages };

  let schema = z
    .string({ required_error: m.passwordRequired })
    .min(pc.minLength, m.passwordTooShort)
    .max(pc.maxLength, m.passwordTooLong);

  if (pc.requireUppercase) {
    schema = schema.regex(/[A-Z]/, m.passwordRequiresUppercase);
  }
  if (pc.requireLowercase) {
    schema = schema.regex(/[a-z]/, m.passwordRequiresLowercase);
  }
  if (pc.requireDigit) {
    schema = schema.regex(/\d/, m.passwordRequiresDigit);
  }
  if (pc.requireSpecial) {
    schema = schema.regex(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/, m.passwordRequiresSpecial);
  }

  return schema;
}

/** Registration schema: email + password + passwordConfirmation. */
export function registrationSchema(config?: Partial<ValidatableConfig>) {
  return z
    .object({
      email: emailSchema(config),
      password: passwordSchema(config),
      passwordConfirmation: z.string(),
    })
    .strict()
    .refine((d) => d.password === d.passwordConfirmation, {
      message: "Passwords do not match",
      path: ["passwordConfirmation"],
    });
}

/** Login schema: email + password (no strength rules). */
export function loginSchema() {
  return z
    .object({
      email: z.string().email().transform((v) => v.trim().toLowerCase()),
      password: z.string().min(1, "Password is required"),
    })
    .strict();
}

/** Change-password schema: currentPassword + newPassword + confirmation. */
export function changePasswordSchema(config?: Partial<ValidatableConfig>) {
  return z
    .object({
      currentPassword: z.string().min(1, "Current password is required"),
      newPassword: passwordSchema(config),
      newPasswordConfirmation: z.string(),
    })
    .strict()
    .refine((d) => d.newPassword === d.newPasswordConfirmation, {
      message: "Passwords do not match",
      path: ["newPasswordConfirmation"],
    });
}

/** Reset-password schema: token + newPassword + confirmation. */
export function resetPasswordSchema(config?: Partial<ValidatableConfig>) {
  return z
    .object({
      token: z.string().min(1, "Token is required"),
      newPassword: passwordSchema(config),
      newPasswordConfirmation: z.string(),
    })
    .strict()
    .refine((d) => d.newPassword === d.newPasswordConfirmation, {
      message: "Passwords do not match",
      path: ["newPasswordConfirmation"],
    });
}

export type RegistrationInput = z.infer<ReturnType<typeof registrationSchema>>;
export type LoginInput = z.infer<ReturnType<typeof loginSchema>>;
export type ChangePasswordInput = z.infer<ReturnType<typeof changePasswordSchema>>;
export type ResetPasswordInput = z.infer<ReturnType<typeof resetPasswordSchema>>;
