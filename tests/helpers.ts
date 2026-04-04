/**
 * @vert/auth — Test helpers: in-memory adapter + factory.
 */

import type { AuthUser, UserAdapter, MailerAdapter } from "../src/types";

let _idCounter = 0;

export function createTestUser(overrides: Partial<AuthUser> = {}): AuthUser {
  _idCounter++;
  return {
    id: 'id' in overrides ? overrides.id! : `user-${_idCounter}`,
    email: overrides.email ?? "test@example.com",
    encryptedPassword: overrides.encryptedPassword ?? "not-set",
    confirmationToken: 'confirmationToken' in overrides ? overrides.confirmationToken : undefined,
    confirmationSentAt: 'confirmationSentAt' in overrides ? overrides.confirmationSentAt : undefined,
    confirmedAt: 'confirmedAt' in overrides ? overrides.confirmedAt : undefined,
    unconfirmedEmail: 'unconfirmedEmail' in overrides ? overrides.unconfirmedEmail : undefined,
    resetPasswordToken: 'resetPasswordToken' in overrides ? overrides.resetPasswordToken : undefined,
    resetPasswordSentAt: 'resetPasswordSentAt' in overrides ? overrides.resetPasswordSentAt : undefined,
    rememberCreatedAt: 'rememberCreatedAt' in overrides ? overrides.rememberCreatedAt : undefined,
    rememberToken: 'rememberToken' in overrides ? overrides.rememberToken : undefined,
    signInCount: overrides.signInCount ?? 0,
    currentSignInAt: 'currentSignInAt' in overrides ? overrides.currentSignInAt : undefined,
    lastSignInAt: 'lastSignInAt' in overrides ? overrides.lastSignInAt : undefined,
    currentSignInIp: 'currentSignInIp' in overrides ? overrides.currentSignInIp : undefined,
    lastSignInIp: 'lastSignInIp' in overrides ? overrides.lastSignInIp : undefined,
    lastActivityAt: 'lastActivityAt' in overrides ? overrides.lastActivityAt : undefined,
    failedAttempts: overrides.failedAttempts ?? 0,
    lockedAt: 'lockedAt' in overrides ? overrides.lockedAt : undefined,
    unlockToken: 'unlockToken' in overrides ? overrides.unlockToken : undefined,
    createdAt: overrides.createdAt ?? new Date(),
    updatedAt: overrides.updatedAt ?? new Date(),
  };
}

export function createMockAdapter(initial: AuthUser[] = []): UserAdapter<AuthUser> & { users: AuthUser[] } {
  const users = [...initial];

  return {
    users,
    async findById(id: string) {
      return users.find((u) => u.id === id) ?? null;
    },
    async findByEmail(email: string) {
      return users.find((u) => u.email === email.toLowerCase()) ?? null;
    },
    async findByToken(field: string, token: string) {
      return users.find((u) => (u as any)[field] === token) ?? null;
    },
    async create(data: Partial<AuthUser>) {
      _idCounter++;
      const user = createTestUser({ ...data, id: data.id ?? `user-${_idCounter}` });
      users.push(user);
      return user;
    },
    async update(id: string, data: Partial<AuthUser>) {
      const idx = users.findIndex((u) => u.id === id);
      if (idx === -1) throw new Error(`User ${id} not found`);
      users[idx] = { ...users[idx], ...data, updatedAt: new Date() } as AuthUser;
      return users[idx];
    },
    async delete(id: string) {
      const idx = users.findIndex((u) => u.id === id);
      if (idx !== -1) users.splice(idx, 1);
    },
  };
}

export function createMockMailer(): MailerAdapter & {
  sent: Array<{ type: string; email: string; token: string }>;
} {
  const sent: Array<{ type: string; email: string; token: string }> = [];
  return {
    sent,
    async sendConfirmation(email, token) {
      sent.push({ type: "confirmation", email, token });
    },
    async sendResetPassword(email, token) {
      sent.push({ type: "reset_password", email, token });
    },
    async sendUnlock(email, token) {
      sent.push({ type: "unlock", email, token });
    },
    async sendWelcome(email) {
      sent.push({ type: "welcome", email, token: "" });
    },
  };
}
