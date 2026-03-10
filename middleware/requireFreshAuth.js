/**
 * Middleware to ensure the user's session is "fresh" (e.g., login occurred recently).
 * Used for sensitive actions like exporting data or deleting accounts.
 * 
 * Rule: Token must be issued (iat) within the last 5 minutes.
 */
export const requireFreshAuth = (req, res, next) => {
    // Assuming verifySession has already run and populated req.user
    if (!req.user || !req.user.iat) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const tokenIssuedAt = req.user.iat; // In seconds
    const now = Math.floor(Date.now() / 1000); // Current time in seconds
    const staleThreshold = 5 * 60; // 5 minutes in seconds

    if (now - tokenIssuedAt > staleThreshold) {
        return res.status(401).json({
            error: 'Fresh authentication required',
            code: 'REAUTH_REQUIRED' // Frontend will look for this specific code to trigger re-login modal
        });
    }

    next();
};
