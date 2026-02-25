import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

// Mock dependencies
// Mock dependencies
// Mock dependencies: We mock the userModel functions to control their behavior during tests.
vi.mock("../models/userModel.js", () => ({
  getUserByEmail: vi.fn(),
  createUser: vi.fn(),
  getUserById: vi.fn(),
  incrementFailedLogin: vi.fn(),
  resetFailedLogin: vi.fn(),
}));

// Mock login attempt tracking (rate-limiting)
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));

// Mock db config (though not directly used if model helpers are mocked)
vi.mock("../config/db.js", () => ({
  supabase: {},
}));

// Import the router after mocks
import router from "../route/auth.js";
import * as db from "../models/userModel.js";

// Setup app
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth", router);

process.env.JWT_SECRET = "test-secret";

describe("Auth Routes (Zero Knowledge)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("POST /auth/register", () => {
    it("should register a user successfully", async () => {
      db.createUser.mockResolvedValue({ id: "123", email: "test@example.com" });

      const payload = {
        email: "test@example.com",
        salt: "salt123",
        wrapped_mek: "mek123",
        auth_hash: "client_hash_value",
      };

      const res = await request(app)
        .post("/auth/register")
        .send(payload);

      expect(res.status).toBe(201);
      expect(db.createUser).toHaveBeenCalled();
      // Verify that createUser was called with a hashed version of auth_hash
      const calledArg = db.createUser.mock.calls[0][0];
      expect(calledArg.email).toBe(payload.email);
      expect(calledArg.salt).toBe(payload.salt);
      expect(calledArg.wrapped_mek).toBe(payload.wrapped_mek);
      // server_hash should be an Argon2 hash, not the plain auth_hash
      expect(calledArg.server_hash).not.toBe(payload.auth_hash);
      expect(calledArg.server_hash).toContain("$argon2");
    });

    it("should return 400 if fields are missing", async () => {
      const res = await request(app)
        .post("/auth/register")
        .send({ email: "test@example.com" }); // Missing others

      expect(res.status).toBe(400);
    });
  });

  describe("GET /auth/params", () => {
    it("should return salt and wrapped_mek", async () => {
      const user = {
        salt: "some_salt",
        wrapped_mek: "some_mek",
      };
      db.getUserByEmail.mockResolvedValue(user);

      const res = await request(app)
        .get("/auth/params?email=test@example.com");

      expect(res.status).toBe(200);
      expect(res.body).toEqual(user);
    });

    it("should return 404 if user not found", async () => {
      db.getUserByEmail.mockResolvedValue(null);

      const res = await request(app)
        .get("/auth/params?email=unknown@example.com");

      expect(res.status).toBe(404);
    });
  });

  describe("POST /auth/login", () => {
    it("should login successfully with correct credentials", async () => {
      // Setup: Create a hashed password and a mock user object
      const validHash = await argon2.hash("client_auth_hash");
      const user = {
        id: "123",
        email: "test@example.com",
        server_hash: validHash,
      };

      // Mock the database response to return this user
      db.getUserByEmail.mockResolvedValue(user);

      // Action: Send a POST request to login with correct credentials
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "test@example.com", auth_hash: "client_auth_hash" });

      // Assertions: Verify success response and cookie setting
      expect(res.status).toBe(200);
      expect(res.body.message).toBe("Login successful");
      expect(res.headers["set-cookie"]).toBeDefined(); // Should set the JWT cookie
    });

    it("should return 401 on wrong auth_hash", async () => {
      // Setup: Mock user with a known password hash
      const validHash = await argon2.hash("client_auth_hash");
      const user = {
        id: "123",
        email: "test@example.com",
        server_hash: validHash,
      };
      db.getUserByEmail.mockResolvedValue(user);

      // Action: Attempt login with WRONG password
      const res = await request(app)
        .post("/auth/login")
        .send({ email: "test@example.com", auth_hash: "WRONG_HASH" });

      // Assertions: Verify 401 Unauthorized and that we tracked the failed attempt
      expect(res.status).toBe(401);
    });
  });

  describe("POST /auth/verify-password", () => {
    it("should return 200 and fresh token on success", async () => {
      const validHash = await argon2.hash("client_auth_hash");
      const user = {
        id: "123",
        email: "test@example.com",
        server_hash: validHash,
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
        .send({ auth_hash: "client_auth_hash" });

      // Assertions: Should return success and indicate session is now 'fresh'
      expect(res.status).toBe(200);
      expect(res.body.fresh).toBe(true);
    });
  });
});
