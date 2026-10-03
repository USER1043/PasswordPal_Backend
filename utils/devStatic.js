import express from 'express';

/**
 * Serves the local-only `scripts/` folder (demo pages, SQL, test scripts).
 * Never mounted in production: it would publish the schema and migrations
 * to anyone without a login.
 */
export function mountDevScripts(app, env = process.env.NODE_ENV) {
  if (env === 'production') return false;
  app.use('/scripts', express.static('scripts'));
  return true;
}
