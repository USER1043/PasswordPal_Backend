// using native fetch
const BASE_URL = 'http://localhost:3000';
const EMAIL = 'test@example.com';
const PASSWORD = 'password123';

let cookies = {};

function parseCookies(response) {
    const raw = response.headers.get('set-cookie');
    if (!raw) return;
    const parts = raw.split(/,(?=\s*[^;]+=[^;]+)/);
    parts.forEach(part => {
        const nameVal = part.split(';')[0].trim();
        const [name, val] = nameVal.split('=');
        cookies[name] = val;
    });
}

function getCookieHeader() {
    return Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
}

async function runHappyPath() {
    console.log('--- Quick Health Check ---');

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
    console.log('Login successful.');

    // 2. Export Immediate (Fresh)
    console.log('2. Testing immediate export (Fresh session)...');
    res = await fetch(`${BASE_URL}/api/export`, {
        method: 'POST',
        headers: { 'Cookie': getCookieHeader() }
    });
    let data = await res.json();
    if (res.ok) {
        console.log('Success:', data.message);
        console.log('--- System is healthy and accepting fresh tokens ---');
    } else {
        console.error('Failed:', data);
        process.exit(1);
    }
}

runHappyPath().catch(e => console.error(e));
