// verify_lockout.js
// Usage: node verify_lockout.js [email]
// Default email: test@example.com

const BASE_URL = 'http://localhost:3000';
const EMAIL = process.argv[2] || 'test@example.com';
const GOOD_PASSWORD = 'password123';
const BAD_PASSWORD = 'wrong_password';

async function login(email, password) {
    try {
        const res = await fetch(`${BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        return res;
    } catch (e) {
        console.error('Fetch error:', e);
        process.exit(1);
    }
}

async function runTest() {
    console.log(`--- Starting Account Lockout Verification for ${EMAIL} ---`);
    console.log('Ensure you have run the migration and the user exists.');

    // 1. Success Login to Reset Counters
    console.log('\n[1] Resetting counters with successful login...');
    let res = await login(EMAIL, GOOD_PASSWORD);
    if (res.ok) {
        console.log('Login successful. Counters reset.');
    } else {
        console.error('Failed initial login. Ensure user exists and password is "password123". Status:', res.status);
        console.log('Response:', await res.text());
        return;
    }

    // 2. Attempt 5 failed logins
    console.log('\n[2] Attempting 5 failed logins...');
    for (let i = 1; i <= 5; i++) {
        res = await login(EMAIL, BAD_PASSWORD);
        if (res.status === 401) {
            console.log(`Attempt ${i}: Failed as expected (401).`);
        } else {
            console.error(`Attempt ${i} Unexpected status:`, res.status);
            console.log('Response:', await res.text());
        }
    }

    // 3. Attempt 6th failed login (Should be Locked)
    console.log('\n[3] Attempting 6th failed login (Should be Locked 429)...');
    res = await login(EMAIL, BAD_PASSWORD);
    if (res.status === 429) {
        const data = await res.json();
        console.log('SUCCESS! Account is locked.');
        console.log('Error Message:', data.error);
    } else {
        console.error('FAILURE! Account is NOT locked. Status:', res.status);
        console.log('Response:', await res.text());
    }

    // 4. Attempt login with CORRECT password (Should still be Locked)
    console.log('\n[4] Attempting login with CORRECT password (Should still be Locked)...');
    res = await login(EMAIL, GOOD_PASSWORD);
    if (res.status === 429) {
        console.log('SUCCESS! Account prevents login even with correct password.');
    } else {
        console.error('FAILURE! Account allowed login. Status:', res.status);
    }

    console.log('\n--- Test Complete ---');
    console.log('To reset the lock manually for development, run:');
    console.log(`UPDATE users SET lockout_until = NULL, failed_login_attempts = 0 WHERE email = '${EMAIL}';`);
}

runTest();
