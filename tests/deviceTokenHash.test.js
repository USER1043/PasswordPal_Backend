import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHash } from "crypto";

// Records the writes and filters each query makes
const state = { update: null, eq: [] };
vi.mock("../config/db.js", () => {
  const chain = {
    update: vi.fn((row) => { state.update = row; return chain; }),
    eq: vi.fn((col, val) => { state.eq.push([col, val]); return chain; }),
    select: vi.fn(() => chain),
    maybeSingle: vi.fn().mockResolvedValue({ data: {}, error: null }),
    then: (resolve) => resolve({ error: null }),
  };
  return { supabase: { from: vi.fn(() => chain) } };
});

import { setDeviceRefreshToken, updateDeviceToken, revokeDeviceByToken } from "../models/deviceModel.js";

const sha256 = (t) => createHash("sha256").update(t).digest("hex");
const OLD = "old.refresh.jwt";
const NEW = "new.refresh.jwt";

describe("refresh tokens are hashed at rest", () => {
  beforeEach(() => {
    state.update = null;
    state.eq = [];
  });

  it("setDeviceRefreshToken stores the hash, never the raw token", async () => {
    await setDeviceRefreshToken("row-1", NEW);
    expect(state.update.refresh_token).toBe(sha256(NEW));
    expect(state.update.refresh_token).not.toBe(NEW);
  });

  it("updateDeviceToken matches on the old hash and stores the new hash", async () => {
    await updateDeviceToken(OLD, NEW);
    expect(state.eq).toContainEqual(["refresh_token", sha256(OLD)]);
    expect(state.eq).not.toContainEqual(["refresh_token", OLD]);
    expect(state.update.refresh_token).toBe(sha256(NEW));
  });

  it("revokeDeviceByToken (logout) matches on the hash", async () => {
    await revokeDeviceByToken(OLD);
    expect(state.eq).toContainEqual(["refresh_token", sha256(OLD)]);
    expect(state.eq).not.toContainEqual(["refresh_token", OLD]);
  });
});
