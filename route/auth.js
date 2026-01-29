import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { getUserByEmail } from '../config/db.js';

const router = express.Router();

// Login - verify email and password against users table
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Get user from custom users table
    let user;
    try {
      user = await getUserByEmail(email);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Verify password against auth_key_hash
    const passwordMatch = await bcrypt.compare(password, user.auth_key_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT tokens
    const accessToken = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '15m',
    });
    const refreshToken = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });

    // Set HttpOnly cookies
    res.cookie('sb-access-token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });

    res.cookie('sb-refresh-token', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: 'Login successful',
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Refresh - rotate JWT tokens
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies['sb-refresh-token'];
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token provided' });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
    // Issue new tokens
    const newAccessToken = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET, {
      expiresIn: '15m',
    });
    const newRefreshToken = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET, {
      expiresIn: '7d',
    });

    res.cookie('sb-access-token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('sb-refresh-token', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ message: 'Token refreshed successfully' });
  } catch (err) {
    res.clearCookie('sb-access-token');
    res.clearCookie('sb-refresh-token');
    return res.status(401).json({ error: 'Session expired, please login again' });
  }
});

// Logout
router.post('/logout', async (req, res) => {
  res.clearCookie('sb-access-token');
  res.clearCookie('sb-refresh-token');
  return res.status(200).json({ message: 'Logged out successfully' });
});

export default router;
