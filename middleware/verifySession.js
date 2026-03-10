import jwt from 'jsonwebtoken';

/**
 * Middleware to verify the session JWT stored in cookies.
 * 
 * Logic:
 * 1. Checks for 'sb-access-token' in request cookies.
 * 2. Verifies the token using the secret.
 * 3. Decodes the user info and attaches it to `req.user`.
 * 4. Passes control to next middleware if valid, otherwise returns 401.
 */
export const verifySession = async (req, res, next) => {
  try {
    const token = req.cookies['sb-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'No session found. Please login.' });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach user info to request
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
};
