// Ed25519 verification for account recovery (see docs/RECOVERY_SIGNATURE_DESIGN.md).
// The app derives an Ed25519 key pair from the recovery key; the server keeps only
// the public key and checks a signature over a one-time challenge + the new credentials.

import crypto from "crypto";

const MESSAGE_DOMAIN = "passwordpal-recovery-v1\n";

// DER prefix for an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows it.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Bytes the app signs. Every field is length-prefixed (in UTF-8 bytes), so two
 * different sets of fields can never produce the same message.
 */
export function buildRecoveryMessage({ challenge, newSalt, newWrappedMek, newAuthHash }) {
  let message = MESSAGE_DOMAIN;
  for (const field of [challenge, newSalt, newWrappedMek, newAuthHash]) {
    message += `${Buffer.byteLength(field, "utf8")}:${field}\n`;
  }
  return Buffer.from(message, "utf8");
}

/**
 * @param {string} publicKeyHex - raw 32-byte Ed25519 public key, 64 hex chars
 * @param {string} signatureHex - 64-byte signature, 128 hex chars
 * @returns {boolean} false for any malformed input instead of throwing
 */
export function verifyRecoverySignature(publicKeyHex, signatureHex, message) {
  try {
    const raw = Buffer.from(publicKeyHex, "hex");
    const signature = Buffer.from(signatureHex, "hex");
    if (raw.length !== 32 || signature.length !== 64) return false;

    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, message, publicKey, signature);
  } catch {
    return false;
  }
}
