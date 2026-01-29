import app from './app.js';
import { testConnection } from './config/db.js';

const PORT = process.env.PORT || 3000;

(async () => {
  const result = await testConnection();
  if (!result.ok) {
    console.error('Warning: DB connectivity test failed on startup.');
  }

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
})();