import { describe, it, expect } from "vitest";
import crypto from "crypto";
import { buildRecoveryMessage, verifyRecoverySignature } from "../utils/recoverySignature.js";

describe("recovery message", () => {
  const f = { challenge: "c", newSalt: "s", newWrappedMek: "m", newAuthHash: "h" };

  it("is deterministic and length-prefixed", () => {
    expect(buildRecoveryMessage(f).toString()).toBe(
      "passwordpal-recovery-v1\n1:c\n1:s\n1:m\n1:h\n",
    );
  });

  it("cannot be forged by shifting bytes between fields", () => {
    const a = buildRecoveryMessage({ ...f, newSalt: "s\n1:m", newWrappedMek: "x" });
    const b = buildRecoveryMessage({ ...f, newSalt: "s", newWrappedMek: "m\n1:x" });
    expect(a.equals(b)).toBe(false);
  });

  it("counts UTF-8 bytes, not characters", () => {
    expect(buildRecoveryMessage({ ...f, challenge: "é" }).toString()).toContain("2:é\n");
  });
});

describe("verifyRecoverySignature", () => {
  it("returns false, not an exception, for malformed input", () => {
    const m = Buffer.from("x");
    expect(verifyRecoverySignature("zz", "zz", m)).toBe(false);
    expect(verifyRecoverySignature("ab".repeat(32), "ab".repeat(10), m)).toBe(false);
    expect(verifyRecoverySignature("", "", m)).toBe(false);
  });

  it("verifies a real Ed25519 signature and nothing else", () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
    const m = Buffer.from("message");
    const sig = crypto.sign(null, m, privateKey).toString("hex");
    expect(verifyRecoverySignature(raw, sig, m)).toBe(true);
    expect(verifyRecoverySignature(raw, sig, Buffer.from("other"))).toBe(false);
  });
});
