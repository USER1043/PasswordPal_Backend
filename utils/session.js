import jwt from "jsonwebtoken";
import { registerUserDevice, setDeviceRefreshToken } from "../models/deviceModel.js";

// 8-4-4-4-12 hex. Deliberately not v4-strict: older installs derived their ID from a hash.
const DEVICE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const cookieOptions = (maxAge) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
  maxAge,
});

/**
 * Read the per-install device UUID the client sends in `X-Device-Id`.
 * Returns the lowercased UUID, or null when missing/malformed.
 */
export function getClientDeviceId(req) {
  const raw = req.headers["x-device-id"];
  if (typeof raw !== "string" || !DEVICE_ID_PATTERN.test(raw.trim())) return null;
  return raw.trim().toLowerCase();
}

/**
 * Sign access + refresh tokens bound to a device row (`did` claim) and set them as cookies.
 */
export function setSessionCookies(res, { id, email, did }) {
  const accessToken = jwt.sign({ id, email, did }, process.env.JWT_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ id, email, did }, process.env.JWT_SECRET, { expiresIn: "7d" });

  res.cookie("sb-access-token", accessToken, cookieOptions(15 * 60 * 1000));
  res.cookie("sb-refresh-token", refreshToken, cookieOptions(7 * 24 * 60 * 60 * 1000));

  return { accessToken, refreshToken };
}

/**
 * Complete a login: register the device, refuse blocked devices, then issue
 * device-bound session cookies.
 *
 * @returns {Promise<{ok: true, device: object} | {ok: false, status: number, body: object}>}
 */
export async function issueSession(req, res, user) {
  const clientDeviceId = getClientDeviceId(req);
  if (!clientDeviceId) {
    return {
      ok: false,
      status: 400,
      body: { error: "Missing or invalid device ID.", code: "DEVICE_ID_REQUIRED" },
    };
  }

  const deviceName = req.headers["user-agent"] || "Unknown Device";
  const device = await registerUserDevice(user.id, deviceName, clientDeviceId);

  if (!device || device.is_blocked) {
    return {
      ok: false,
      status: 403,
      body: { error: "This device has been blocked from this account.", code: "DEVICE_BLOCKED" },
    };
  }

  const { refreshToken } = setSessionCookies(res, { id: user.id, email: user.email, did: device.id });
  await setDeviceRefreshToken(device.id, refreshToken);

  return { ok: true, device };
}
