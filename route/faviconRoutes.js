import express from 'express';
import { getFavicon } from '../controllers/faviconController.js';

const router = express.Router();

router.get('/', getFavicon);

export default router;
