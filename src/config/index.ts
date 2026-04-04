/**
 * @vert/auth — Auth configuration.
 *
 * Zod-validated configuration with sensible secure defaults.
 */

import { z } from "zod";

export const authConfigSchema = z.object({
  // Authenticatable
  passwordHashMemoryCost: z.number().default(65536),
  passwordHashTimeCost: z.number().default(3),

  // Validatable
  passwordMinLength: z.number().min(6).default(8),
  passwordMaxLength: z.number().max(256).default(128),
  passwordRequireUppercase: z.boolean().default(true),
  passwordRequireLowercase: z.boolean().default(true),
  passwordRequireDigit: z.boolean().default(true),
  passwordRequireSpecial: z.boolean().default(false),
  emailMaxLength: z.number().default(255),

  // Confirmable
  confirmWithin: z.number().default(3 * 24 * 60 * 60 * 1000), // 3 days
  allowResendConfirmation: z.boolean().default(true),

  // Recoverable
  resetPasswordWithin: z.number().default(6 * 60 * 60 * 1000), // 6 hours
  resetPasswordCooldown: z.number().default(60 * 1000), // 1 min

  // Rememberable
  rememberFor: z.number().default(14 * 24 * 60 * 60 * 1000), // 14 days
  rememberCookieName: z.string().default("remember_token"),
  rememberCookieSecure: z.boolean().default(true),
  rememberCookieSameSite: z.enum(["Strict", "Lax", "None"]).default("Lax"),

  // Trackable
  enableTrackable: z.boolean().default(true),

  // Timeoutable
  timeoutIn: z.number().default(30 * 60 * 1000), // 30 min

  // Lockable
  maximumAttempts: z.number().min(1).default(5),
  lockFor: z.number().nullable().default(60 * 60 * 1000), // 1 hour
  unlockStrategies: z.array(z.enum(["email", "time"])).default(["email", "time"]),

  // OmniAuth
  oauthProviders: z
    .array(
      z.object({
        name: z.string(),
        clientId: z.string(),
        clientSecret: z.string(),
        redirectUri: z.string(),
        scopes: z.array(z.string()).optional(),
      }),
    )
    .default([]),
});

export type AuthConfig = z.infer<typeof authConfigSchema>;

let _config: AuthConfig | null = null;

export function defineAuthConfig(input?: Partial<AuthConfig>): AuthConfig {
  _config = authConfigSchema.parse(input ?? {});
  return _config;
}

export function getAuthConfig(): AuthConfig {
  if (!_config) {
    _config = authConfigSchema.parse({});
  }
  return _config;
}

export function resetAuthConfig(): void {
  _config = null;
}
