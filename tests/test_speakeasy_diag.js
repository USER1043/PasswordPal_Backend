// Quick diagnostic test for speakeasy TOTP verification
// Run from PasswordPal_Backend directory: node tests/test_speakeasy_diag.js
import speakeasy from 'speakeasy';

const secret = speakeasy.generateSecret({
    name: 'PasswordPal (test@example.com)',
    issuer: 'PasswordPal',
    length: 20,
});

console.log('=== TOTP Diagnostic Test ===');
console.log('Secret (base32):', secret.base32);
console.log('Server time:', new Date().toISOString());
console.log('Current time step:', Math.floor(Date.now() / 30000));

const validCode = speakeasy.totp({
    secret: secret.base32,
    encoding: 'base32',
});
console.log('Generated code:', validCode);
console.log('Code type:', typeof validCode);

const verified = speakeasy.totp.verify({
    secret: secret.base32,
    encoding: 'base32',
    token: validCode,
    window: 2,
});
console.log('Verification result:', verified);

// Test String() coercion for leading zeros
const code_as_number = parseInt(validCode, 10);
console.log('\nLeading zeros test:');
console.log('  Original code:', JSON.stringify(validCode));
console.log('  As number:', code_as_number);
console.log('  Back to string:', JSON.stringify(String(code_as_number)));
console.log('  Leading zeros LOST?', validCode !== String(code_as_number));

// Verify with wider window
const verified_wide = speakeasy.totp.verify({
    secret: secret.base32,
    encoding: 'base32',
    token: validCode,
    window: 6,
});
console.log('\nVerification with window=6:', verified_wide);

console.log('\n=== Result ===');
console.log(verified ? 'PASS: speakeasy works correctly' : 'FAIL: speakeasy bug detected!');
