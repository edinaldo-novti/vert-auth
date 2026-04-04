/**
 * @vert/auth — Authentication library for Bun.
 *
 * Modules: Authenticatable, Registerable, Confirmable, Recoverable,
 * Rememberable, Trackable, Timeoutable, Lockable, Validatable, OmniAuth.
 */

export const VERSION = "0.1.0";

// ─── Types ─────────────────────────────────────────────────────────────────
export type {
  AuthUser,
  UserAdapter,
  MailerAdapter,
  AuthResult,
  AuthErrorCode,
  AuthHooks,
  HookFn,
  OAuthProvider,
  OAuthProviderConfig,
  OAuthProfile,
  MigrationColumn,
} from "./types";

// ─── Config ────────────────────────────────────────────────────────────────
export {
  defineAuthConfig,
  getAuthConfig,
  resetAuthConfig,
  authConfigSchema,
  type AuthConfig,
} from "./config";

// ─── Validatable ───────────────────────────────────────────────────────────
export {
  emailSchema,
  passwordSchema,
  registrationSchema,
  loginSchema,
  changePasswordSchema,
  resetPasswordSchema,
  type ValidatableConfig,
  type ValidatableMessages,
  type RegistrationInput,
  type LoginInput,
  type ChangePasswordInput,
  type ResetPasswordInput,
} from "./validatable";

// ─── Authenticatable ───────────────────────────────────────────────────────
export {
  hashPassword,
  verifyPassword,
  authenticate,
  authenticatableColumnsSQL,
  AUTHENTICATABLE_COLUMNS,
  type Argon2Config,
} from "./authenticatable";

// ─── Registerable ──────────────────────────────────────────────────────────
export {
  register,
  updateAccount,
  deleteAccount,
  registerableColumnsSQL,
  type RegisterInput,
} from "./registerable";

// ─── Confirmable ───────────────────────────────────────────────────────────
export {
  generateConfirmationToken,
  confirm,
  resendConfirmation,
  confirmableColumnsSQL,
  CONFIRMABLE_COLUMNS,
  type ConfirmableConfig,
} from "./confirmable";

// ─── Recoverable ──────────────────────────────────────────────────────────
export {
  sendResetPasswordToken,
  resetPassword,
  recoverableColumnsSQL,
  RECOVERABLE_COLUMNS,
  type RecoverableConfig,
} from "./recoverable";

// ─── Rememberable ─────────────────────────────────────────────────────────
export {
  generateRememberToken,
  validateRememberToken,
  clearRememberToken,
  buildRememberCookie,
  buildClearRememberCookie,
  rememberableColumnsSQL,
  REMEMBERABLE_COLUMNS,
  type RememberableConfig,
} from "./rememberable";

// ─── Trackable ────────────────────────────────────────────────────────────
export {
  trackSignIn,
  extractIp,
  trackableColumnsSQL,
  TRACKABLE_COLUMNS,
  type TrackableData,
} from "./trackable";

// ─── Timeoutable ──────────────────────────────────────────────────────────
export {
  isTimedOut,
  touchActivity,
  timeoutableColumnsSQL,
  TIMEOUTABLE_COLUMNS,
  type TimeoutableConfig,
} from "./timeoutable";

// ─── Lockable ─────────────────────────────────────────────────────────────
export {
  recordFailedAttempt,
  resetFailedAttempts,
  isLocked,
  unlockByToken,
  unlockByTime,
  lockableColumnsSQL,
  LOCKABLE_COLUMNS,
  type LockableConfig,
} from "./lockable";

// ─── OmniAuth ─────────────────────────────────────────────────────────────
export {
  registerProvider,
  getProvider,
  listProviders,
  clearProviders,
  generateOAuthState,
  generateCodeVerifier,
  generateCodeChallenge,
  googleProvider,
  githubProvider,
  appleProvider,
} from "./omniauth";

// ─── Middleware ────────────────────────────────────────────────────────────
export {
  authenticateMiddleware,
  requireAuth,
  unauthorizedResponse,
  sessionIdFromCookie,
  rememberTokenFromCookie,
  jwtAuthMiddleware,
  requireJwtAuth,
  type AuthMiddlewareOptions,
  type JwtAuthMiddlewareOptions,
  type JwtAuthResult,
} from "./middleware";

// ─── JWT ──────────────────────────────────────────────────────────────────
export {
  generateJwtKeyPair,
  exportKeyPairToJwk,
  importKeyPairFromJwk,
  signAccessToken,
  signRefreshToken,
  signTokenPair,
  verifyAccessToken,
  verifyRefreshToken,
  refreshTokens,
  revokeAccessToken,
  revokeRefreshToken,
  extractBearerToken,
  decodeTokenUnsafe,
  type JwtAlgorithm,
  type JwtConfig,
  type JwtKeyPair,
  type JwtTokens,
  type JwtAccessPayload,
  type JwtRefreshPayload,
  type TokenBlacklist,
  type VerifyOptions,
  type RefreshResult,
} from "./jwt";

// ─── Utils ────────────────────────────────────────────────────────────────
export { generateToken, hashToken, secureCompare } from "./utils";

// ─── Migrations ───────────────────────────────────────────────────────────
export {
  generateAuthMigration,
  generateAuthRollback,
  type MigrationOptions,
} from "./migrations";
