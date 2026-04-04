/**
 * @vert/auth — Registerable module.
 *
 * Account creation, update, and deletion with validation and hooks.
 */

import type { AuthUser, AuthResult, UserAdapter, AuthHooks } from "../types";
import { hashPassword } from "../authenticatable";
import { registrationSchema, type ValidatableConfig } from "../validatable";

export interface RegisterInput {
  email: string;
  password: string;
  passwordConfirmation: string;
  [key: string]: unknown;
}

export async function register<T extends AuthUser>(
  adapter: UserAdapter<T>,
  input: RegisterInput,
  hooks?: AuthHooks<T>,
  validationConfig?: Partial<ValidatableConfig>,
): Promise<AuthResult<T>> {
  // Validate input
  const parsed = registrationSchema(validationConfig).safeParse(input);
  if (!parsed.success) {
    const msg = parsed.error.issues.map((i) => i.message).join("; ");
    return { success: false, error: msg, code: "VALIDATION_ERROR" };
  }

  const { email, password } = parsed.data;

  // Check duplicate
  const existing = await adapter.findByEmail(email);
  if (existing) {
    return { success: false, error: "Email already exists", code: "EMAIL_ALREADY_EXISTS" };
  }

  // Hook: beforeRegister
  if (hooks?.beforeRegister) {
    await hooks.beforeRegister({ email } as Partial<T>);
  }

  const encryptedPassword = await hashPassword(password);

  const user = await adapter.create({
    email,
    encryptedPassword,
  } as Partial<T>);

  // Hook: afterRegister
  if (hooks?.afterRegister) {
    await hooks.afterRegister(user);
  }

  return { success: true, user };
}

export async function updateAccount<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
  updates: { email?: string; password?: string; currentPassword: string },
): Promise<AuthResult<T>> {
  const user = await adapter.findById(userId);
  if (!user) {
    return { success: false, error: "User not found", code: "USER_NOT_FOUND" };
  }

  // Verify current password
  const { verifyPassword } = await import("../authenticatable");
  const valid = await verifyPassword(updates.currentPassword, user.encryptedPassword);
  if (!valid) {
    return { success: false, error: "Invalid current password", code: "INVALID_CREDENTIALS" };
  }

  const data: Partial<T> = {} as Partial<T>;

  if (updates.email) {
    const normalized = updates.email.trim().toLowerCase();
    const existing = await adapter.findByEmail(normalized);
    if (existing && existing.id !== userId) {
      return { success: false, error: "Email already exists", code: "EMAIL_ALREADY_EXISTS" };
    }
    (data as Record<string, unknown>).email = normalized;
  }

  if (updates.password) {
    (data as Record<string, unknown>).encryptedPassword = await hashPassword(updates.password);
  }

  const updated = await adapter.update(userId, data);
  return { success: true, user: updated };
}

export async function deleteAccount<T extends AuthUser>(
  adapter: UserAdapter<T>,
  userId: string,
  currentPassword: string,
): Promise<AuthResult<T>> {
  const user = await adapter.findById(userId);
  if (!user) {
    return { success: false, error: "User not found", code: "USER_NOT_FOUND" };
  }

  const { verifyPassword } = await import("../authenticatable");
  const valid = await verifyPassword(currentPassword, user.encryptedPassword);
  if (!valid) {
    return { success: false, error: "Invalid current password", code: "INVALID_CREDENTIALS" };
  }

  await adapter.delete(userId);
  return { success: true, user };
}

export function registerableColumnsSQL(): string {
  // Registerable uses the same columns as authenticatable
  return "-- Registerable: no extra columns (uses authenticatable columns)";
}
