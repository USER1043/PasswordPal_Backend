import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";

vi.mock("argon2", () => ({
  default: { verify: vi.fn(), hash: vi.fn().mockResolvedValue("hashed"), argon2id: 2 },
}));
vi.mock("../models/userModel.js", () => ({
  getUserByEmail: vi.fn(),
  createUser: vi.fn(),
}));
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));
vi.mock("../models/mfaSettingsModel.js", () => ({ getMfaSettings: vi.fn() }));
vi.mock("../models/deviceModel.js", () => ({}));

// A small in-memory stand-in for the tables recovery touches
const db = { recovery_keys: null, recovery_challenges: new Map(), writes: [] };
vi.mock("../config/db.js", () => {
  const make = (table) => {
    const q = { filters: [], op: "select", row: null };
    const chain = {
      select: vi.fn(() => chain),
      insert: vi.fn((row) => {
        db.writes.push({ table, op: "insert", row });
        if (table === "recovery_challenges") db.recovery_challenges.set(row.challenge_hash, row);
        return Promise.resolve({ error: null });
      }),
      update: vi.fn((row) => { q.op = "update"; q.row = row; return chain; }),
      delete: vi.fn(() => { q.op = "delete"; return chain; }),
      eq: vi.fn((c, v) => { q.filters.push(["eq", c, v]); return chain; }),
      gt: vi.fn((c, v) => { q.filters.push(["gt", c, v]); return chain; }),
      lt: vi.fn((c, v) => { q.filters.push(["lt", c, v]); return chain; }),
      single: vi.fn(() =>
        Promise.resolve(table === "recovery_keys" && db.recovery_keys
          ? { data: db.recovery_keys, error: null }
          : { data: null, error: { message: "none" } })),
      then: (resolve) => {
        if (q.op === "update") db.writes.push({ table, op: "update", row: q.row });
        if (table === "recovery_challenges" && q.op === "delete") {
          const eq = (c) => q.filters.find((f) => f[0] === "eq" && f[1] === c)?.[2];
          const gt = q.filters.find((f) => f[0] === "gt");
          const row = db.recovery_challenges.get(eq("challenge_hash"));
          if (row && row.user_id === eq("user_id") && (!gt || row.expires_at > gt[2])) {
            db.recovery_challenges.delete(row.challenge_hash);
            return resolve({ data: [{ challenge_hash: row.challenge_hash }], error: null });
          }
          return resolve({ data: [], error: null });
        }
        return resolve({ data: [], error: null });
      },
    };
    return chain;
  };
  return { supabase: { from: vi.fn(make) } };
});

import router from "../route/auth.js";
import * as users from "../models/userModel.js";
import { buildRecoveryMessage } from "../utils/recoverySignature.js";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth", router);

// ---- Test-side stand-in for the app: an Ed25519 key pair and a signer -------
const makeKeys = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { publicHex: raw.toString("hex"), privateKey };
};
const sign = (privateKey, fields) =>
  crypto.sign(null, buildRecoveryMessage(fields), privateKey).toString("hex");

const NEW = {
  newSalt: Buffer.from("fresh-salt-bytes!").toString("base64"),
  newWrappedMek: Buffer.from("wrapped-mek-bytes-0123456789").toString("base64"),
  newAuthHash: "cd".repeat(32),
};
const body = (challenge, signature, over = {}) => ({
  email: "a@example.com", challenge, signature,
  new_salt: NEW.newSalt, new_wrapped_mek: NEW.newWrappedMek, new_auth_hash: NEW.newAuthHash, ...over,
});

describe("recovery by signature", () => {
  let keys;
  const getChallenge = async () =>
    (await request(app).post("/auth/recover/challenge").send({ email: "a@example.com" })).body.challenge;

  beforeEach(() => {
    vi.clearAllMocks();
    keys = makeKeys();
    db.recovery_keys = { public_key: keys.publicHex };
    db.recovery_challenges.clear();
    db.writes = [];
    users.getUserByEmail.mockResolvedValue({ id: "u1", email: "a@example.com" });
  });

  describe("registration", () => {
    it("stores only the public key", async () => {
      users.createUser.mockResolvedValue({ id: "u1", email: "a@example.com" });
      const res = await request(app).post("/auth/register").send({
        email: "a@example.com", salt: "s", wrapped_mek: "m", auth_hash: "h", recovery_public_key: keys.publicHex,
      });
      expect(res.status).toBe(201);
      expect(db.writes.find((w) => w.table === "recovery_keys").row).toEqual({ user_id: "u1", public_key: keys.publicHex });
    });

    it("rejects the old replayable verifier field", async () => {
      const res = await request(app).post("/auth/register").send({
        email: "a@example.com", salt: "s", wrapped_mek: "m", auth_hash: "h", recovery_key_hash: "ab".repeat(32),
      });
      expect(res.status).toBe(400);
      expect(users.createUser).not.toHaveBeenCalled();
    });
  });

  describe("challenge", () => {
    it("issues a 32-byte hex challenge, storing only its hash", async () => {
      const challenge = await getChallenge();
      expect(challenge).toMatch(/^[0-9a-f]{64}$/);
      const stored = [...db.recovery_challenges.values()][0];
      expect(stored.user_id).toBe("u1");
      expect(stored.challenge_hash).toBe(crypto.createHash("sha256").update(challenge).digest("hex"));
      expect(stored.challenge_hash).not.toBe(challenge);
    });

    it("answers the same way for an unknown email, and stores nothing", async () => {
      users.getUserByEmail.mockResolvedValue(null);
      const res = await request(app).post("/auth/recover/challenge").send({ email: "nobody@example.com" });
      expect(res.status).toBe(200);
      expect(res.body.challenge).toMatch(/^[0-9a-f]{64}$/);
      expect(res.body.expires_in).toBeGreaterThan(0);
      expect(db.recovery_challenges.size).toBe(0);
    });

    it("stores nothing for an account that has no recovery public key", async () => {
      db.recovery_keys = { public_key: null, key_hash: "legacy" };
      const res = await request(app).post("/auth/recover/challenge").send({ email: "a@example.com" });
      expect(res.status).toBe(200);
      expect(db.recovery_challenges.size).toBe(0);
    });
  });

  describe("recover", () => {
    it("accepts a valid signature over the challenge and the new values", async () => {
      const challenge = await getChallenge();
      const res = await request(app).post("/auth/recover")
        .send(body(challenge, sign(keys.privateKey, { challenge, ...NEW })));

      expect(res.status).toBe(200);
      expect(db.writes.find((w) => w.table === "users" && w.op === "update").row.wrapped_mek).toBe(NEW.newWrappedMek);
      expect(db.writes.find((w) => w.table === "user_devices" && w.op === "update").row.is_revoked).toBe(true);
    });

    it("fails a replayed request: the challenge is used up", async () => {
      const challenge = await getChallenge();
      const replay = body(challenge, sign(keys.privateKey, { challenge, ...NEW }));

      expect((await request(app).post("/auth/recover").send(replay)).status).toBe(200);
      db.writes = [];
      const second = await request(app).post("/auth/recover").send(replay);

      expect(second.status).toBe(401);
      expect(second.body.code).toBe("CHALLENGE_INVALID");
      expect(db.writes.filter((w) => w.table === "users")).toHaveLength(0);
    });

    it("fails a signature made over different new values", async () => {
      const challenge = await getChallenge();
      const signature = sign(keys.privateKey, { challenge, ...NEW });
      const res = await request(app).post("/auth/recover").send(
        body(challenge, signature, { new_auth_hash: "ee".repeat(32) }),
      );

      expect(res.status).toBe(401);
      expect(db.writes.filter((w) => w.table === "users")).toHaveLength(0);
      // A bad signature must not burn the challenge
      expect(db.recovery_challenges.size).toBe(1);
    });

    it("fails a signature from a different key", async () => {
      const challenge = await getChallenge();
      const other = makeKeys();
      const res = await request(app).post("/auth/recover")
        .send(body(challenge, sign(other.privateKey, { challenge, ...NEW })));
      expect(res.status).toBe(401);
    });

    it("fails an expired challenge", async () => {
      const challenge = await getChallenge();
      for (const row of db.recovery_challenges.values()) row.expires_at = new Date(Date.now() - 1000).toISOString();
      const res = await request(app).post("/auth/recover")
        .send(body(challenge, sign(keys.privateKey, { challenge, ...NEW })));

      expect(res.status).toBe(401);
      expect(res.body.code).toBe("CHALLENGE_INVALID");
      expect(db.writes.filter((w) => w.table === "users")).toHaveLength(0);
    });

    it("fails a challenge the server never issued", async () => {
      const challenge = "ab".repeat(32);
      const res = await request(app).post("/auth/recover")
        .send(body(challenge, sign(keys.privateKey, { challenge, ...NEW })));
      expect(res.status).toBe(401);
    });

    it("fails a challenge issued to a different account", async () => {
      const challenge = await getChallenge();
      for (const row of db.recovery_challenges.values()) row.user_id = "someone-else";
      const res = await request(app).post("/auth/recover")
        .send(body(challenge, sign(keys.privateKey, { challenge, ...NEW })));
      expect(res.status).toBe(401);
    });

    it("refuses an account enrolled under the old scheme (no public key)", async () => {
      db.recovery_keys = { public_key: null, key_hash: "legacy" };
      const challenge = "ab".repeat(32);
      const res = await request(app).post("/auth/recover")
        .send(body(challenge, sign(keys.privateKey, { challenge, ...NEW })));
      expect(res.status).toBe(404);
      expect(db.writes.filter((w) => w.table === "users")).toHaveLength(0);
    });

    it("rejects the old fingerprint-style request", async () => {
      const res = await request(app).post("/auth/recover").send({
        email: "a@example.com", recovery_key_hash: "ab".repeat(32),
        new_salt: NEW.newSalt, new_wrapped_mek: NEW.newWrappedMek, new_auth_hash: NEW.newAuthHash,
      });
      expect(res.status).toBe(400);
    });

    it("rejects malformed signatures without crashing", async () => {
      const challenge = await getChallenge();
      const res = await request(app).post("/auth/recover").send(body(challenge, "00".repeat(64)));
      expect(res.status).toBe(401);
    });
  });
});
