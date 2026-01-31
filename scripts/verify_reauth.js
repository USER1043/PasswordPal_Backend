// using native fetch
// Since it's module, we can use top-level await if Node is new enough.

const BASE_URL = 'http://localhost:3000';
const EMAIL = 'test@example.com';
const PASSWORD = 'password123';

let cookies = {};

function parseCookies(response) {
    const raw = response.headers.get('set-cookie');
    if (!raw) return;
    // node-fetch or native fetch might return a comma-separated string or an array depending on implementation
    // If it's a string with commas, it can be tricky because dates have commas.
    // But typically for simple testing:
    const parts = raw.split(/,(?=\s*[^;]+=[^;]+)/); // Split only on commas that look like new cookies
    parts.forEach(part => {
        const nameVal = part.split(';')[0].trim();
        const [name, val] = nameVal.split('=');
        cookies[name] = val;
    });
}

function getCookieHeader() {
    return Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
}

async function runTest() {
    console.log('--- Starting Re-Auth Verification ---');

    // 1. Login
    console.log('1. Logging in...');
    let res = await fetch(`${BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: EMAIL, password: PASSWORD })
    });

    if (!res.ok) {
        console.error('Login failed:', await res.text());
        process.exit(1);
    }
    parseCookies(res);
    console.log('Login successful. Cookies:', cookies);

    // 2. Export Immediate (Fresh)
    console.log('2. Testing immediate export (Fresh session)...');
    res = await fetch(`${BASE_URL}/api/export`, {
        method: 'POST',
        headers: { 'Cookie': getCookieHeader() }
    });
    let data = await res.json();
    if (res.ok) {
        console.log('Success (Expected):', data.message);
    } else {
        console.error('Failed (Unexpected):', data);
        process.exit(1);
    }

    // 3. Wait 6 seconds
    console.log('3. Waiting 6 seconds to let token become stale...');
    await new Promise(r => setTimeout(r, 6000));

    // 4. Export Stale (Expect 401)
    console.log('4. Testing stale export (Expect 401 REAUTH_REQUIRED)...');
    res = await fetch(`${BASE_URL}/api/export`, {
        method: 'POST',
        headers: { 'Cookie': getCookieHeader() }
    });
    data = await res.json();
    if (res.status === 401 && data.code === 'REAUTH_REQUIRED') {
        console.log('Success (Expected 401):', data.error);
    } else {
        console.error('Failed (Expected 401 REAUTH_REQUIRED):', res.status, data);
        process.exit(1);
    }

    // 5. Verify Password (Wrong)
    console.log('5. Verifying with WRONG password...');
    res = await fetch(`${BASE_URL}/auth/verify-password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Cookie': getCookieHeader()
        },
        body: JSON.stringify({ password: 'wrong' })
    });
    if (res.status === 401) {
        console.log('Success (Expected 401 on wrong pass).');
    } else {
        console.error('Failed (Expected 401):', res.status);
    }

    // 6. Verify Password (Correct)
    console.log('6. Verifying with CORRECT password...');
    res = await fetch(`${BASE_URL}/auth/verify-password`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Cookie': getCookieHeader()
        },
        body: JSON.stringify({ password: PASSWORD })
    });
    if (res.ok) {
        data = await res.json();
        console.log('Re-auth successful:', data.message);
        parseCookies(res); // Important: Update cookies with new Fresh token
    } else {
        console.error('Failed re-auth:', await res.text());
        process.exit(1);
    }

    // 7. Export Again (Should be fresh now)
    console.log('7. Testing export again (Should be fresh)...');
    res = await fetch(`${BASE_URL}/api/export`, {
        method: 'POST',
        headers: { 'Cookie': getCookieHeader() }
    });
    data = await res.json();
    if (res.ok) {
        console.log('Success (Expected):', data.message);
        console.log('--- ALL TESTS PASSED ---');
    } else {
        console.error('Failed (Unexpected):', data);
        process.exit(1);
    }
}

runTest().catch(e => console.error(e));
