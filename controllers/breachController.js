
/**
 * Breach Controller
 * Proxies requests to HaveIBeenPwned API to protect user IP address.
 */

export const checkBreach = async (req, res) => {
    try {
        const { prefix } = req.params;

        // 1. Validate Prefix (Must be 5-char hex)
        if (!prefix || !/^[a-fA-F0-9]{5}$/.test(prefix)) {
            return res.status(400).json({ error: "Invalid prefix format. Expected 5 hex characters." });
        }

        // 2. Call HIBP API
        // https://haveibeenpwned.com/API/v3#PwnedPasswords
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
            method: 'GET',
            headers: {
                // Add a user agent as polite behavior for HIBP
                'User-Agent': 'PasswordPal-Backend'
            }
        });

        if (!response.ok) {
            throw new Error(`HIBP API responded with ${response.status}`);
        }

        // 3. Get the text body (suffixes:count)
        const data = await response.text();

        // 4. Return to client
        // We return plain text to match HIBP format, or we could parse it.
        // For simplicity and strict proxying, returning the text is best.
        res.setHeader('Content-Type', 'text/plain');
        res.send(data);

    } catch (error) {
        console.error("Breach Check Error:", error);
        res.status(500).json({ error: "Failed to check breach status." });
    }
};
