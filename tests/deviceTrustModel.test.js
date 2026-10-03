import { describe, it, expect, vi, beforeEach } from "vitest";

const state = { updates: [] };
vi.mock("../config/db.js", () => {
  const chain = {
    update: vi.fn((row) => { state.updates.push(row); return chain; }),
    eq: vi.fn(() => chain),
    neq: vi.fn(() => chain),
    select: vi.fn(() => chain),
    then: (resolve) => resolve({ data: [{ id: "d1" }], error: null }),
  };
  return { supabase: { from: vi.fn(() => chain) } };
});

import {
  revokeDeviceById, revokeOtherDevices, setDeviceBlocked,
  setDeviceTrusted, clearTrustedDevices, isDeviceTrusted,
} from "../models/deviceModel.js";

describe("device trust in the model", () => {
  beforeEach(() => { state.updates = []; });

  it("revoking a device cancels its trust", async () => {
    await revokeDeviceById("d1", "u1");
    expect(state.updates[0]).toMatchObject({ is_revoked: true, trusted_until: null });
  });

  it("revoking all other devices cancels their trust", async () => {
    await revokeOtherDevices("u1", "d1");
    expect(state.updates[0]).toMatchObject({ is_revoked: true, trusted_until: null });
  });

  it("blocking a device cancels its trust; unblocking does not touch it", async () => {
    await setDeviceBlocked("d1", "u1", true);
    expect(state.updates[0]).toMatchObject({ is_blocked: true, trusted_until: null });
    await setDeviceBlocked("d1", "u1", false);
    expect(state.updates[1]).not.toHaveProperty("trusted_until");
  });

  it("clearTrustedDevices nulls trusted_until", async () => {
    await clearTrustedDevices("u1");
    expect(state.updates[0]).toEqual({ trusted_until: null });
  });

  it("setDeviceTrusted trusts for about 30 days", async () => {
    const until = await setDeviceTrusted("d1", "u1");
    const days = (new Date(until).getTime() - Date.now()) / 86400000;
    expect(days).toBeGreaterThan(29.9);
    expect(days).toBeLessThanOrEqual(30);
    expect(state.updates[0]).toEqual({ trusted_until: until });
  });

  it("isDeviceTrusted is false for null, missing and expired", () => {
    expect(isDeviceTrusted(null)).toBe(false);
    expect(isDeviceTrusted({ trusted_until: null })).toBe(false);
    expect(isDeviceTrusted({ trusted_until: new Date(Date.now() - 1000).toISOString() })).toBe(false);
    expect(isDeviceTrusted({ trusted_until: new Date(Date.now() + 1000).toISOString() })).toBe(true);
  });
});
