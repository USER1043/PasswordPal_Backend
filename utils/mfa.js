import bcrypt from 'bcryptjs';

// Generate N random backup codes of given length
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

// Hash an array of codes using bcrypt
export function hashBackupCodes(codes, saltRounds = 10) {
  return codes.map((c) => bcrypt.hashSync(c, saltRounds));
}

export default { generateBackupCodes, hashBackupCodes };
