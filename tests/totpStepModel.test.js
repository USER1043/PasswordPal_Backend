import { describe, it, expect, vi, beforeEach } from "vitest";

const state = { filters: [], update: null, result: { data: [{ user_id: "u1" }], error: null } };
vi.mock("../config/db.js", () => {
  const chain = {
    update: vi.fn((row) => { state.update = row; return chain; }),
    eq: vi.fn((c, v) => { state.filters.push(["eq", c, v]); return chain; }),
    or: vi.fn((f) => { state.filters.push(["or", f]); return chain; }),
    select: vi.fn(() => chain),
    then: (resolve) => resolve(state.result),
  };
  return { supabase: { from: vi.fn(() => chain) } };
});

import { consumeTotpStep } from "../models/mfaSettingsModel.js";

describe("consumeTotpStep", () => {
  beforeEach(() => {
    state.filters = [];
    state.update = null;
    state.result = { data: [{ user_id: "u1" }], error: null };
  });

  it("only updates if no code from this step or a later one was used (a single conditional UPDATE)", async () => {
    expect(await consumeTotpStep("u1", 100)).toBe(true);
    expect(state.update).toEqual({ last_used_step: 100 });
    expect(state.filters).toContainEqual(["eq", "user_id", "u1"]);
    expect(state.filters).toContainEqual(["or", "last_used_step.is.null,last_used_step.lt.100"]);
  });

  it("returns false when nothing was updated (the step was already used)", async () => {
    state.result = { data: [], error: null };
    expect(await consumeTotpStep("u1", 100)).toBe(false);
  });

  it("throws on a database error rather than letting a code through", async () => {
    state.result = { data: null, error: { message: "boom" } };
    await expect(consumeTotpStep("u1", 100)).rejects.toThrow(/boom/);
  });
});
