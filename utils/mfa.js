import bcrypt from 'bcryptjs';

/**
 * Generates a set of random backup codes.
 * Uses a character set that avoids ambiguous characters (like I, l, 1, O, 0).
 * 
 * @param {number} count - Number of codes to generate (default 10).
 * @param {number} length - Length of each code (default 10).
 * @returns {Array<string>} - Array of plaintext backup codes.
 */
export function generateBackupCodes(count = 10, length = 10) {
  const codes = [];
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Avoid ambiguous chars
  for (let i = 0; i < count; i++) {
    let code = '';
    for (let j = 0; j < length; j++) {
      code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    codes.push(code);
  }
  return codes;
}

/**
 * Hashes an array of plaintext codes using bcrypt.
 * This is used before storing codes in the database for security.
 * 
 * @param {Array<string>} codes - Array of plaintext codes.
 * @param {number} saltRounds - BCrypt salt rounds (default 10).
 * @returns {Array<string>} - Array of hashed codes.
 */
export function hashBackupCodes(codes, saltRounds = 10) {
  return codes.map((c) => bcrypt.hashSync(c, saltRounds));
}

export default { generateBackupCodes, hashBackupCodes };
