// Data access for recovery_challenges: one-time, short-lived challenges that
// the app must sign to recover an account. Only a SHA-256 of the challenge is stored.

import crypto from "crypto";
import { supabase } from "../config/db.js";

export const CHALLENGE_TTL_SECONDS = 5 * 60;

const sha256Hex = (value) => crypto.createHash("sha256").update(value).digest("hex");

/** A fresh unpredictable challenge (hex). Not stored by itself. */
export const newChallenge = () => crypto.randomBytes(32).toString("hex");

/**
 * Store a challenge for a user, and drop that user's expired ones.
 * @throws {Error} if the database write fails.
 */
export async function storeChallenge(userId, challenge) {
  const now = new Date();
  await supabase
    .from("recovery_challenges")
    .delete()
    .eq("user_id", userId)
    .lt("expires_at", now.toISOString());

  const { error } = await supabase.from("recovery_challenges").insert({
    challenge_hash: sha256Hex(challenge),
    user_id: userId,
    expires_at: new Date(now.getTime() + CHALLENGE_TTL_SECONDS * 1000).toISOString(),
  });
  if (error) throw error;
}

/**
 * Use up a challenge. A single DELETE that must remove exactly one row, so the
 * same challenge can never be used twice, even by two concurrent requests.
 *
 * @returns {Promise<boolean>} true if the challenge existed, belonged to this
 *   user and had not expired.
 */
export async function consumeChallenge(userId, challenge) {
  const { data, error } = await supabase
    .from("recovery_challenges")
    .delete()
    .eq("challenge_hash", sha256Hex(challenge))
    .eq("user_id", userId)
    .gt("expires_at", new Date().toISOString())
    .select("challenge_hash");

  if (error) throw error;
  return Array.isArray(data) && data.length === 1;
}
