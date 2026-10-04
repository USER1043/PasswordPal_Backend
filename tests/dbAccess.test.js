import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";

// Static checks on the SQL: the cloud tests have no database, so this guards the
// scripts the owner runs by hand. Policies below are the "open" ones found live.
const OPEN_POLICIES = [
  ["login_attempts", "Allow all for login_attempts"],
  ["recovery_keys", "Allow all for recovery_keys"],
  ["mfa_settings", "Allow all for mfa_settings"],
  ["refresh_tokens", "Allow all for refresh_tokens"],
  ["sync_queue", "Allow all for sync_queue"],
  ["conflicts", "Allow all for conflicts"],
];
const VAULT_FUNCTIONS = ["atomic_upsert_vault_record", "update_vault_record"];

const initDb = readFileSync("scripts/init_db.sql", "utf8");
const migration = readFileSync("scripts/migrations/2026-10-07_lock_down_database_access.sql", "utf8");

// Statements only, without comments
const statements = (sql) =>
  sql.split("\n").filter((l) => !l.trim().startsWith("--")).join("\n").split(";").map((s) => s.replace(/\s+/g, " ").trim());

describe("init_db.sql gives the public-facing roles nothing", () => {
  const stmts = statements(initDb);

  it("creates no 'allow all' policy", () => {
    expect(stmts.filter((s) => /^CREATE POLICY/i.test(s) && /USING \(true\)/i.test(s))).toEqual([]);
  });

  it("grants nothing to anon or authenticated", () => {
    expect(stmts.filter((s) => /^GRANT/i.test(s) && /\b(anon|authenticated)\b/i.test(s))).toEqual([]);
  });

  it("revokes table privileges from anon and authenticated and keeps service_role", () => {
    expect(stmts).toContain("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated");
    expect(stmts).toContain("GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role");
  });

  it("makes the vault functions callable by service_role only", () => {
    for (const fn of VAULT_FUNCTIONS) {
      expect(stmts.some((s) => s.startsWith(`REVOKE ALL ON FUNCTION public.${fn}(`) && /FROM PUBLIC, anon, authenticated$/.test(s))).toBe(true);
      expect(stmts.some((s) => s.startsWith(`GRANT EXECUTE ON FUNCTION public.${fn}(`) && /TO service_role$/.test(s))).toBe(true);
    }
  });
});

describe("lock-down migration", () => {
  const stmts = statements(migration);

  it.each(OPEN_POLICIES)("drops the open policy on %s", (table, policy) => {
    expect(stmts).toContain(`DROP POLICY IF EXISTS "${policy}" ON public.${table}`);
  });

  it("revokes table privileges from anon and authenticated, keeping service_role", () => {
    expect(stmts).toContain("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated");
    expect(stmts).toContain("GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role");
  });

  it("revokes both vault functions from public-facing roles", () => {
    // The DO block holds semicolons, so read it from the raw text rather than the split statements
    const block = migration.slice(migration.indexOf("DO $$"), migration.indexOf("END $$;"));
    for (const fn of VAULT_FUNCTIONS) expect(block).toContain(`'${fn}'`);
    expect(block).toContain("REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated");
    expect(block).toContain("GRANT EXECUTE ON FUNCTION %s TO service_role");
  });

  it("grants nothing to anon or authenticated, and creates no policy", () => {
    expect(stmts.filter((s) => /^GRANT/i.test(s) && /\b(anon|authenticated)\b/i.test(s))).toEqual([]);
    expect(stmts.filter((s) => /^CREATE POLICY/i.test(s))).toEqual([]);
  });
});
