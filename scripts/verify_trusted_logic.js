
import jwt from 'jsonwebtoken';

// Mock env
process.env.JWT_SECRET = 'test_secret_123';

console.log('--- Verifying Trusted Device Logic ---');

// --- Test 1: Generate Token (Logic from totp.js) ---
console.log('\nTest 1: Generates valid trusted device token...');
const userId = 'user_123';
const deviceToken = jwt.sign({
    id: userId,
    type: 'trusted-device',
    issuedAt: Date.now()
}, process.env.JWT_SECRET, { expiresIn: '30d' });

console.log('Generated Token:', deviceToken);

if (!deviceToken) {
    console.error('FAIL: Token not generated');
    process.exit(1);
}

// --- Test 2: Verify Token (Logic from auth.js) ---
console.log('\nTest 2: Verifies valid token correctly...');

// Simulate cookies object
const req = {
    cookies: {
        'sb-trusted-device': deviceToken
    }
};

// Logic from auth.js
const trustedDeviceToken = req.cookies['sb-trusted-device'];
let isTrustedDevice = false;

if (trustedDeviceToken) {
    try {
        const decodedDevice = jwt.verify(trustedDeviceToken, process.env.JWT_SECRET);
        // Simulate user object match
        const user = { id: 'user_123' };

        if (decodedDevice.id === user.id && decodedDevice.type === 'trusted-device') {
            isTrustedDevice = true;
        }
    } catch (e) {
        console.log('Error verifying:', e);
    }
}

if (isTrustedDevice === true) {
    console.log('SUCCESS: Token verified and isTrustedDevice = true');
} else {
    console.error('FAIL: Token failed verification');
    process.exit(1);
}

// --- Test 3: Verify Invalid/Modified Token ---
console.log('\nTest 3: Rejects invalid token...');
const invalidToken = deviceToken + 'effed_up';
const reqInvalid = { cookies: { 'sb-trusted-device': invalidToken } };

let isTrustedDeviceInvalid = false;
try {
    const decodedDevice = jwt.verify(invalidToken, process.env.JWT_SECRET);
    // Should throw before here
    if (decodedDevice.id === userId && decodedDevice.type === 'trusted-device') {
        isTrustedDeviceInvalid = true;
    }
} catch (e) {
    console.log('Correctly caught error for invalid token:', e.message);
}

if (isTrustedDeviceInvalid === false) {
    console.log('SUCCESS: Invalid token rejected');
} else {
    console.error('FAIL: Invalid token was accepted!');
    process.exit(1);
}
