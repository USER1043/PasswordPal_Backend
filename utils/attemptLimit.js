// Shared per-IP limit on failed password-style attempts (login, recovery,
// re-authentication, change-password). All of them share one budget, so
// switching endpoint does not reset it.

import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";
import { getClientDeviceId } from "./session.js";

export const MAX_FAILED_ATTEMPTS = 5;
export const RATE_LIMIT_WINDOW_MINUTES = 15;

export const clientIpOf = (req) => req.ip || "0.0.0.0";

/** True once this IP has used up its failed attempts for the window. */
export async function isRateLimited(req) {
  const failures = await countRecentFailedAttempts(clientIpOf(req), null, RATE_LIMIT_WINDOW_MINUTES);
  return failures >= MAX_FAILED_ATTEMPTS;
}

/** Sends the 429 response used by every limited endpoint. */
export function sendRateLimited(res, what = "login") {
  return res.status(429).json({ error: `Too many failed ${what} attempts. Please try again later.` });
}

/** Records a failed attempt; a logging failure never changes the response. */
export function recordFailedAttempt(req, userId, failureReason) {
  return recordLoginAttempt({
    userId,
    ipAddress: clientIpOf(req),
    wasSuccessful: false,
    userAgent: req.headers["user-agent"] || null,
    deviceId: getClientDeviceId(req),
    failureReason,
  }).catch(() => { });
}
