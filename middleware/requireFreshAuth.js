/**
 * Middleware to ensure the user proved their password recently.
 * Used for sensitive actions like exporting data or deleting accounts.
 *
 * Rule: the session's `auth_time` (last login or /auth/verify-password) must be
 * within the last 5 minutes. The token's issue time (iat) is deliberately not
 * used: a silent token refresh renews iat without the password being entered.
 *
 * Responds 403 rather than 401 so the client doesn't treat it as an expired
 * token and try to refresh its way past the check.
 */
export const requireFreshAuth = (req, res, next) => {
    // Assuming verifySession has already run and populated req.user
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const authTime = req.user.auth_time; // In seconds; absent on tokens issued before this claim existed
    const now = Math.floor(Date.now() / 1000); // Current time in seconds
    const staleThreshold = 5 * 60; // 5 minutes in seconds

    if (!authTime || now - authTime > staleThreshold) {
        return res.status(403).json({
            error: 'Fresh authentication required',
            code: 'REAUTH_REQUIRED' // Frontend looks for this code to show the re-enter-password prompt
        });
    }

    next();
};
