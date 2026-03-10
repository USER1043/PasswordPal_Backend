# PasswordPal Backend

A secure, zero-knowledge backend API for the PasswordPal password manager, built with Node.js, Express, and Supabase.

## Features

- **Zero-Knowledge Architecture**: The server never sees or stores user passwords. Authentication relies on double-hashing and secure cryptographic proofs.
- **Secure Authentication**: 
  - Argon2id for password hashing.
  - JSON Web Tokens (JWT) for session management (Access & Refresh tokens).
  - HttpOnly, SameSite=Strict cookies to preventing XSS and CSRF attacks.
- **Multi-Factor Authentication (MFA)**:
  - Time-based One-Time Password (TOTP) support (compatible with Google Authenticator, Authy, etc.).
  - Backup codes for account recovery.
  - Trusted device recognition.
- **Database Integration**:
  - PostgreSQL via Supabase.
  - Row Level Security (RLS) compliancy infrastructure.

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: PostgreSQL (Supabase)
- **Authentication**: JWT, Argon2, Crypto-JS
- **MFA**: Speakeasy, QRCode
- **Testing**: Vitest, Supertest

## Prerequisites

- Node.js (v18+ recommended)
- A Supabase project (for PostgreSQL database)

## Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd PasswordPal_Backend
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Environment Configuration:**
    Create a `.env` file in the root directory with the following variables:

    ```env
    PORT=3000
    NODE_ENV=development
    
    # Supabase Configuration
    SUPABASE_URL=your_supabase_project_url
    SUPABASE_SECRET_KEY=your_supabase_service_role_key
    
    # Security Secrets
    JWT_SECRET=your_super_secret_jwt_key
    ```

4.  **Database Initialization:**
    Run the initialization script to set up the necessary tables in your PostgreSQL database

## Running the Server

-   **Development Mode (with hot-reload):**
    ```bash
    npm run dev
    ```

-   **Production Mode:**
    ```bash
    npm start
    ```

The server will start on `http://localhost:3000` (or your configured POORT).

## Running Tests

Run the test suite using Vitest:

```bash
npm test
```

## API Endpoints

### Authentication (`/auth`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/register` | Register a new user with ZK parameters (salt, wrapped MEK, auth hash). |
| `GET` | `/params` | Retrieve salt and wrapped MEK for login (Step 1). |
| `POST` | `/login` | Authenticate user using auth hash (Step 2). |
| `POST` | `/refresh` | Refresh access token using httpOnly refresh cookie. |
| `POST` | `/logout` | Clear session cookies. |
| `POST` | `/verify-password` | Step-up authentication for sensitive actions. |

### Multi-Factor Authentication (`/auth/totp`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/setup` | Initiate TOTP setup (returns QR code). |
| `POST` | `/verify-setup` | Verify and enable TOTP with a code. |
| `POST` | `/verify-login` | Complete login with 2FA code. |
| `GET` | `/status` | Check if MFA is enabled for the current user. |
| `POST` | `/disable` | Disable MFA. |
| `POST` | `/backup-codes/generate` | Generate recovery codes. |
| `POST` | `/backup-codes/redeem` | Login using a backup code. |

## Security Notes

-   **Zero Knowledge**: The `auth_hash` sent during registration is hashed *again* by the server before storage (`server_hash`). This ensures that even if the database is compromised, the original `auth_hash` (which acts as a password derivative) is not exposed.
-   **Master Encryption Key (MEK)**: The `wrapped_mek` is stored on the server but can only be unwrapped by the client using the user's password, ensuring client-side encryption of vault data.

