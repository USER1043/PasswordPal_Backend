import { describe, it, expect, vi } from "vitest";

const calls = [];
vi.mock("../config/db.js", () => {
  const chain = {};
  for (const m of ["select", "eq", "gt", "or"]) {
    chain[m] = vi.fn((...args) => { calls.push([m, ...args]); return chain; });
  }
  chain.then = (resolve) => resolve({ count: 3, error: null });
  return { supabase: { from: vi.fn(() => chain) } };
});

import { countRecentFailedAttempts } from "../models/loginAttemptModel.js";

describe("countRecentFailedAttempts", () => {
  it("does not count device_blocked refusals, but keeps rows with no failure_reason", async () => {
    const count = await countRecentFailedAttempts("1.2.3.4");
    expect(count).toBe(3);
    const filter = calls.find(([m]) => m === "or")?.[1];
    expect(filter).toBe("failure_reason.is.null,failure_reason.neq.device_blocked");
  });
});
