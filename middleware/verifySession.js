import jwt from 'jsonwebtoken';
import { getDeviceForSession } from '../models/deviceModel.js';

/**
 * Middleware to verify the session JWT stored in cookies.
 * 
 * Logic:
 * 1. Checks for 'sb-access-token' in request cookies.
 * 2. Verifies the token using the secret.
 * 3. Checks the token's device (`did`) is still active - not revoked or blocked.
 * 4. Decodes the user info and attaches it to `req.user`.
 * 5. Passes control to next middleware if valid, otherwise returns 401.
 */
export const verifySession = async (req, res, next) => {
  const token = req.cookies['sb-access-token'];
  if (!token) {
    return res.status(401).json({ error: 'No session found. Please login.' });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }

  // Every full session is bound to a device row. Tokens without one
  // (legacy sessions, MFA-pending tokens) are not accepted.
  if (!decoded.did) {
    return res.status(401).json({ error: 'Session revoked. Please login again.', code: 'SESSION_REVOKED' });
  }

  try {
    const device = await getDeviceForSession(decoded.did, decoded.id);
    if (!device || device.is_revoked || device.is_blocked) {
      return res.status(401).json({ error: 'Session revoked. Please login again.', code: 'SESSION_REVOKED' });
    }
  } catch (err) {
    console.error('Device session check failed:', err);
    return res.status(503).json({ error: 'Unable to verify session. Please try again.' });
  }

  req.user = decoded; // Attach user info to request
  next();
};
