/**
 * @vert/auth — Migration template generator.
 *
 * Generates SQL for all auth columns (Drizzle-compatible).
 */

import { authenticatableColumnsSQL } from "../authenticatable";
import { confirmableColumnsSQL } from "../confirmable";
import { recoverableColumnsSQL } from "../recoverable";
import { rememberableColumnsSQL } from "../rememberable";
import { trackableColumnsSQL } from "../trackable";
import { timeoutableColumnsSQL } from "../timeoutable";
import { lockableColumnsSQL } from "../lockable";

export interface MigrationOptions {
  tableName?: string;
  enableConfirmable?: boolean;
  enableRecoverable?: boolean;
  enableRememberable?: boolean;
  enableTrackable?: boolean;
  enableTimeoutable?: boolean;
  enableLockable?: boolean;
  includeUuidPrimaryKey?: boolean;
  includeTimestamps?: boolean;
}

const DEFAULTS: Required<MigrationOptions> = {
  tableName: "users",
  enableConfirmable: true,
  enableRecoverable: true,
  enableRememberable: true,
  enableTrackable: true,
  enableTimeoutable: true,
  enableLockable: true,
  includeUuidPrimaryKey: true,
  includeTimestamps: true,
};

export function generateAuthMigration(options?: MigrationOptions): string {
  const o = { ...DEFAULTS, ...options };
  const columns: string[] = [];

  if (o.includeUuidPrimaryKey) {
    columns.push(`"id" UUID PRIMARY KEY DEFAULT gen_random_uuid()`);
  }

  // Authenticatable (always)
  columns.push(authenticatableColumnsSQL());

  if (o.enableConfirmable) columns.push(confirmableColumnsSQL());
  if (o.enableRecoverable) columns.push(recoverableColumnsSQL());
  if (o.enableRememberable) columns.push(rememberableColumnsSQL());
  if (o.enableTrackable) columns.push(trackableColumnsSQL());
  if (o.enableTimeoutable) columns.push(timeoutableColumnsSQL());
  if (o.enableLockable) columns.push(lockableColumnsSQL());

  if (o.includeTimestamps) {
    columns.push(`"created_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
    columns.push(`"updated_at" TIMESTAMPTZ NOT NULL DEFAULT NOW()`);
  }

  return [
    `-- @vert/auth migration: ${o.tableName}`,
    `CREATE TABLE IF NOT EXISTS "${o.tableName}" (`,
    `  ${columns.join(",\n  ")}`,
    `);`,
    ``,
    `-- Indexes`,
    `CREATE UNIQUE INDEX IF NOT EXISTS "idx_${o.tableName}_email" ON "${o.tableName}" ("email");`,
    o.enableConfirmable
      ? `CREATE UNIQUE INDEX IF NOT EXISTS "idx_${o.tableName}_confirmation_token" ON "${o.tableName}" ("confirmation_token") WHERE "confirmation_token" IS NOT NULL;`
      : null,
    o.enableRecoverable
      ? `CREATE UNIQUE INDEX IF NOT EXISTS "idx_${o.tableName}_reset_password_token" ON "${o.tableName}" ("reset_password_token") WHERE "reset_password_token" IS NOT NULL;`
      : null,
    o.enableRememberable
      ? `CREATE UNIQUE INDEX IF NOT EXISTS "idx_${o.tableName}_remember_token" ON "${o.tableName}" ("remember_token") WHERE "remember_token" IS NOT NULL;`
      : null,
    o.enableLockable
      ? `CREATE UNIQUE INDEX IF NOT EXISTS "idx_${o.tableName}_unlock_token" ON "${o.tableName}" ("unlock_token") WHERE "unlock_token" IS NOT NULL;`
      : null,
  ]
    .filter(Boolean)
    .join("\n");
}

export function generateAuthRollback(options?: MigrationOptions): string {
  const o = { ...DEFAULTS, ...options };
  return `-- @vert/auth rollback: ${o.tableName}\nDROP TABLE IF EXISTS "${o.tableName}" CASCADE;`;
}
