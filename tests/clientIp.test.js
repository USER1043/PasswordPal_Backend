import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";

vi.mock("../models/userModel.js", () => ({
  getUserByEmail: vi.fn().mockResolvedValue(null), // unknown user -> failed attempt is recorded
  createUser: vi.fn(),
}));

vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));

vi.mock("../models/mfaSettingsModel.js", () => ({ getMfaSettings: vi.fn() }));
vi.mock("../models/deviceModel.js", () => ({}));
vi.mock("../config/db.js", () => ({ supabase: {} }));

import router from "../route/auth.js";
import { configureTrustProxy } from "../utils/clientIp.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";

const DEVICE_ID = "3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c";

const makeApp = (env) => {
  const app = express();
  configureTrustProxy(app, env);
  app.use(express.json());
  app.use(cookieParser());
  app.use("/auth", router);
  return app;
};

// Attempt a login and return the IP the server attributed it to
const loginFrom = async (app, forwardedFor) => {
  const req = request(app).post("/auth/login").set("X-Device-Id", DEVICE_ID);
  if (forwardedFor) req.set("X-Forwarded-For", forwardedFor);
  await req.send({ email: "nobody@example.com", auth_hash: "guess" });
  return recordLoginAttempt.mock.calls.at(-1)[0].ipAddress;
};

const isLoopback = (ip) => ["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(ip);

describe("client IP resolution", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("no proxy (local development, TRUST_PROXY_HOPS unset)", () => {
    it("ignores a client-supplied X-Forwarded-For header", async () => {
      const ip = await loginFrom(makeApp({}), "6.6.6.6");

      expect(isLoopback(ip)).toBe(true);
    });

    it("rate-limits on the connection address, not the header", async () => {
      await loginFrom(makeApp({}), "6.6.6.6");

      expect(isLoopback(countRecentFailedAttempts.mock.calls[0][0])).toBe(true);
    });
  });

  describe("behind one proxy (TRUST_PROXY_HOPS=1)", () => {
    const app = makeApp({ TRUST_PROXY_HOPS: "1" });

    it("uses the address the proxy reported", async () => {
      expect(await loginFrom(app, "203.0.113.7")).toBe("203.0.113.7");
    });

    it("ignores an address the client put in front of the proxy's entry", async () => {
      // Client sent "X-Forwarded-For: 6.6.6.6"; the proxy appended the real address.
      expect(await loginFrom(app, "6.6.6.6, 203.0.113.7")).toBe("203.0.113.7");
    });
  });

  describe("configuration", () => {
    it.each([["0"], ["-1"], ["abc"], [""], [undefined]])("treats TRUST_PROXY_HOPS=%s as no proxy", async (value) => {
      const ip = await loginFrom(makeApp({ TRUST_PROXY_HOPS: value }), "6.6.6.6");

      expect(isLoopback(ip)).toBe(true);
    });
  });
});
