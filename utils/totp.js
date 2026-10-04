// Time-based one-time password (TOTP) checks for the second login step.

import speakeasy from "speakeasy";

export const TOTP_STEP_SECONDS = 30;

// How many 30-second steps either side of the current one still count, to allow for clock
// drift between the phone and the server. 1 = the previous, current and next code only
// (the codes of roughly the last minute). It used to be 4, which accepted nine codes.
export const TOTP_WINDOW = 1;

/**
 * Checks a 6-digit code against a base32 secret.
 *
 * @returns {{ step: number } | null} The 30-second step the code belongs to (needed to
 *   refuse a second use of the same code), or null if the code is not valid now.
 */
export function verifyTotp({ secret, token, now = Date.now() }) {
  const result = speakeasy.totp.verifyDelta({
    secret,
    encoding: "base32",
    token: String(token),
    window: TOTP_WINDOW,
    step: TOTP_STEP_SECONDS,
    time: Math.floor(now / 1000),
  });
  if (!result) return null;
  return { step: Math.floor(now / 1000 / TOTP_STEP_SECONDS) + result.delta };
}
