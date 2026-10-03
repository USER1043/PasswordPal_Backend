import { describe, it, expect } from 'vitest';
import request from 'supertest';
import express from 'express';
import { mountDevScripts } from '../utils/devStatic.js';

const build = (env) => {
  const app = express();
  mountDevScripts(app, env);
  return app;
};

describe('scripts/ static mount', () => {
  it('returns 404 for scripts/init_db.sql in production', async () => {
    const res = await request(build('production')).get('/scripts/init_db.sql');
    expect(res.status).toBe(404);
  });

  it('still serves the file outside production', async () => {
    const res = await request(build('development')).get('/scripts/init_db.sql');
    expect(res.status).toBe(200);
  });
});
