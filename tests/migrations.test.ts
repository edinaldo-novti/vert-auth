/**
 * @vert/auth — Migrations module tests.
 */

import { describe, test, expect } from "bun:test";
import { generateAuthMigration, generateAuthRollback } from "../src/migrations";

describe("Migrations", () => {
  test("generates full migration with all modules", () => {
    const sql = generateAuthMigration();
    expect(sql).toContain("CREATE TABLE");
    expect(sql).toContain('"users"');
    // Authenticatable
    expect(sql).toContain('"email"');
    expect(sql).toContain('"encrypted_password"');
    // Confirmable
    expect(sql).toContain('"confirmation_token"');
    expect(sql).toContain('"confirmed_at"');
    // Recoverable
    expect(sql).toContain('"reset_password_token"');
    // Rememberable
    expect(sql).toContain('"remember_token"');
    // Trackable
    expect(sql).toContain('"sign_in_count"');
    expect(sql).toContain('"current_sign_in_ip"');
    // Timeoutable
    expect(sql).toContain('"last_activity_at"');
    // Lockable
    expect(sql).toContain('"failed_attempts"');
    expect(sql).toContain('"unlock_token"');
    // Timestamps
    expect(sql).toContain('"created_at"');
    expect(sql).toContain('"updated_at"');
    // Indexes
    expect(sql).toContain("idx_users_email");
    expect(sql).toContain("idx_users_confirmation_token");
    expect(sql).toContain("idx_users_reset_password_token");
    expect(sql).toContain("idx_users_remember_token");
    expect(sql).toContain("idx_users_unlock_token");
  });

  test("custom table name", () => {
    const sql = generateAuthMigration({ tableName: "accounts" });
    expect(sql).toContain('"accounts"');
    expect(sql).toContain("idx_accounts_email");
  });

  test("disables optional modules", () => {
    const sql = generateAuthMigration({
      enableConfirmable: false,
      enableRecoverable: false,
      enableRememberable: false,
      enableTrackable: false,
      enableTimeoutable: false,
      enableLockable: false,
    });
    expect(sql).toContain('"email"');
    expect(sql).not.toContain('"confirmation_token"');
    expect(sql).not.toContain('"reset_password_token"');
    expect(sql).not.toContain('"remember_token"');
    expect(sql).not.toContain('"sign_in_count"');
    expect(sql).not.toContain('"last_activity_at"');
    expect(sql).not.toContain('"failed_attempts"');
  });

  test("generates UUID primary key by default", () => {
    const sql = generateAuthMigration();
    expect(sql).toContain("UUID PRIMARY KEY");
    expect(sql).toContain("gen_random_uuid()");
  });

  test("omits UUID when disabled", () => {
    const sql = generateAuthMigration({ includeUuidPrimaryKey: false });
    expect(sql).not.toContain("UUID PRIMARY KEY");
  });

  test("omits timestamps when disabled", () => {
    const sql = generateAuthMigration({ includeTimestamps: false });
    expect(sql).not.toContain('"created_at"');
    expect(sql).not.toContain('"updated_at"');
  });

  test("generateAuthRollback produces DROP TABLE", () => {
    const sql = generateAuthRollback();
    expect(sql).toContain("DROP TABLE");
    expect(sql).toContain('"users"');
    expect(sql).toContain("CASCADE");
  });

  test("generateAuthRollback with custom table", () => {
    const sql = generateAuthRollback({ tableName: "members" });
    expect(sql).toContain('"members"');
  });
});
