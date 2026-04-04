/**
 * @vert/auth — Shared types for all auth modules.
 */

// ─── User Record ───────────────────────────────────────────────────────────
/** Minimal user record with all optional auth fields. */
export interface AuthUser {
  id: string;
  email: string;
  encryptedPassword: string;

  // Confirmable
  confirmationToken?: string | null;
  confirmationSentAt?: Date | null;
  confirmedAt?: Date | null;
  unconfirmedEmail?: string | null;

  // Recoverable
  resetPasswordToken?: string | null;
  resetPasswordSentAt?: Date | null;

  // Rememberable
  rememberCreatedAt?: Date | null;
  rememberToken?: string | null;

  // Trackable
  signInCount?: number;
  currentSignInAt?: Date | null;
  lastSignInAt?: Date | null;
  currentSignInIp?: string | null;
  lastSignInIp?: string | null;

  // Timeoutable
  lastActivityAt?: Date | null;

  // Lockable
  failedAttempts?: number;
  lockedAt?: Date | null;
  unlockToken?: string | null;

  // Timestamps
  createdAt?: Date;
  updatedAt?: Date;
}

// ─── Adapter Interfaces ────────────────────────────────────────────────────
/** Database adapter — consumers must implement this to plug into any ORM. */
export interface UserAdapter<T extends AuthUser = AuthUser> {
  findById(id: string): Promise<T | null>;
  findByEmail(email: string): Promise<T | null>;
  findByToken(field: string, token: string): Promise<T | null>;
  create(data: Partial<T>): Promise<T>;
  update(id: string, data: Partial<T>): Promise<T>;
  delete(id: string): Promise<void>;
}

/** Mailer adapter — pluggable e-mail sending. */
export interface MailerAdapter {
  sendConfirmation(email: string, token: string): Promise<void>;
  sendResetPassword(email: string, token: string): Promise<void>;
  sendUnlock(email: string, token: string): Promise<void>;
  sendWelcome?(email: string): Promise<void>;
}

// ─── Hook Types ────────────────────────────────────────────────────────────
export type HookFn<T = AuthUser> = (user: T) => void | Promise<void>;

export interface AuthHooks<T = AuthUser> {
  beforeRegister?: HookFn<Partial<T>>;
  afterRegister?: HookFn<T>;
  beforeAuthenticate?: HookFn<{ email: string }>;
  afterAuthenticate?: HookFn<T>;
  beforeConfirm?: HookFn<T>;
  afterConfirm?: HookFn<T>;
  beforeResetPassword?: HookFn<T>;
  afterResetPassword?: HookFn<T>;
  beforeLock?: HookFn<T>;
  afterLock?: HookFn<T>;
  beforeUnlock?: HookFn<T>;
  afterUnlock?: HookFn<T>;
}

// ─── Result Types ──────────────────────────────────────────────────────────
export type AuthResult<T = AuthUser> =
  | { success: true; user: T }
  | { success: false; error: string; code: AuthErrorCode };

export type AuthErrorCode =
  | "INVALID_CREDENTIALS"
  | "ACCOUNT_LOCKED"
  | "ACCOUNT_NOT_CONFIRMED"
  | "TOKEN_EXPIRED"
  | "TOKEN_INVALID"
  | "VALIDATION_ERROR"
  | "USER_NOT_FOUND"
  | "EMAIL_ALREADY_EXISTS"
  | "SESSION_EXPIRED"
  | "RATE_LIMITED";

// ─── OmniAuth Types ───────────────────────────────────────────────────────
export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
}

export interface OAuthProfile {
  provider: string;
  uid: string;
  email: string;
  name?: string;
  avatarUrl?: string;
  raw: Record<string, unknown>;
}

export interface OAuthProvider {
  name: string;
  authorizeUrl(state: string): string;
  callback(code: string, state: string): Promise<OAuthProfile>;
}

// ─── Migration Template Types ──────────────────────────────────────────────
export interface MigrationColumn {
  name: string;
  type: string;
  nullable?: boolean;
  default?: string;
}
