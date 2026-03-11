// server.js
// Entry point for the PasswordPal Backend application.
// This file initializes the database connection test and starts the Express server.

import app from './app.js';
import { startHealthCheck } from './config/db.js';

// Define the port to run the server on, defaulting to 3000 if not specified in environment variables.
const PORT = process.env.PORT || 3000;

(async () => {
  // 1. Start Database Connectivity Polling
  // Before starting the server, start the health check routine.
  await startHealthCheck();

  // 2. Start the Server
  // Listen for incoming requests on the specified port.
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
})();