import jwt from 'jsonwebtoken';

export const verifySession = async (req, res, next) => {
  try {
    const token = req.cookies['sb-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'No session found. Please login.' });
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
};
