import { generateBackupCodes, hashBackupCodes } from '../utils/mfa.js';
import bcrypt from 'bcryptjs';

(async () => {
  console.log('Generating backup codes...');
  const codes = generateBackupCodes(10, 10);
  console.log('Plain codes:');
  console.log(codes.join('\n'));

  console.log('\nHashing codes (bcrypt)...');
  const hashes = hashBackupCodes(codes, 10);
  console.log('Hashed codes JSON:');
  console.log(JSON.stringify(hashes, null, 2));

  // Simulate verifying the first code
  const testCode = codes[0];
  const match = await bcrypt.compare(testCode, hashes[0]);
  console.log(`\nVerification of first code returns: ${match}`);
})();
