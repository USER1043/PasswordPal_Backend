import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Mock dependencies
// Mock dependencies
// Mock dependencies: We mock the userModel functions to control their behavior during tests.
vi.mock("../models/userModel.js", () => ({
  getUserByEmail: vi.fn(), // Mock fetching user by email
  incrementFailedLogin: vi.fn(), // Mock incrementing failed login attempts
  resetFailedLogin: vi.fn(), // Mock resetting failed login attempts
}));

vi.mock("../config/db.js", () => ({
  supabase: {
    from: vi.fn().mockReturnThis(),
    update: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    select: vi.fn().mockReturnThis(),
    single: vi.fn(),
  },
}));

import router from "../route/auth.js";
import * as db from "../models/userModel.js";

// Setup app
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth", router);

process.env.JWT_SECRET = "test-secret";

describe("Auth Routes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("POST /auth/login", () => {
    it("should login successfully with correct credentials", async () => {
      // Setup: Create a hashed password and a mock user object
      const hashedPassword = await bcrypt.hash("password123", 1);
      const user = {
        id: "123",
        email: "test@example.com",
        auth_key_hash: hashedPassword,
        lockout_until: null,
      };

      // Mock the database response to return this user
      db.getUserByEmail.mockResolvedValue(user);
      db.resetFailedLogin.mockResolvedValue(true);

      // Action: Send a POST request to login with correct credentials
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "test@example.com", password: "password123" });

      // Assertions: Verify success response and cookie setting
      expect(res.status).toBe(200);
      expect(res.body.message).toBe("Login successful");
      expect(res.headers["set-cookie"]).toBeDefined(); // Should set the JWT cookie
    });

    it("should return 401 on wrong password and increment failures", async () => {
      // Setup: Mock user with a known password hash
      const hashedPassword = await bcrypt.hash("password123", 1);
      const user = {
        id: "123",
        email: "test@example.com",
        auth_key_hash: hashedPassword,
        lockout_until: null,
      };
      db.getUserByEmail.mockResolvedValue(user);

      // Action: Attempt login with WRONG password
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "test@example.com", password: "WRONG" });

      // Assertions: Verify 401 Unauthorized and that we tracked the failed attempt
      expect(res.status).toBe(401);
      expect(db.incrementFailedLogin).toHaveBeenCalledWith("test@example.com");
    });

    it("should return 429 if user is locked out", async () => {
      // Setup: Create a future date to simulate an active lockout
      const future = new Date();
      future.setMinutes(future.getMinutes() + 10);

      const user = {
        id: "123",
        email: "test@example.com",
        auth_key_hash: "hash",
        lockout_until: future.toISOString(), // User is locked out until this time
      };
      db.getUserByEmail.mockResolvedValue(user);

      // Action: Attempt login
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "test@example.com", password: "any" });

      // Assertions: Should be blocked with 429 Too Many Requests
      expect(res.status).toBe(429);
      expect(res.body.error).toContain("Too many attempts");
    });
  });

  describe("POST /auth/verify-password", () => {
    it("should return 200 and fresh token on success", async () => {
      // Setup: Mock user and valid session token
      const hashedPassword = await bcrypt.hash("password123", 1);
      const user = {
        id: "123",
        email: "test@example.com",
        auth_key_hash: hashedPassword,
      };

      // Create a fake JWT token to simulate logged-in state
      const token = jwt.sign(
        { email: "test@example.com" },
        process.env.JWT_SECRET,
      );

      db.getUserByEmail.mockResolvedValue(user);

      // Action: Verify password with a valid session cookie
      const res = await request(app)
        .post("/auth/verify-password")
        .set("Cookie", [`sb-access-token=${token}`])
        .send({ password: "password123" });

      // Assertions: Should return success and indicate session is now 'fresh'
      expect(res.status).toBe(200);
      expect(res.body.fresh).toBe(true);
    });
  });
});
