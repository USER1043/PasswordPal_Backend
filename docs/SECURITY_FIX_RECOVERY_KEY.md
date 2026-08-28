# Security Fix: Recovery Key Hash Vulnerability

## Vulnerability Description

**CRITICAL SECURITY ISSUE:** The recovery system was sending the raw Master Encryption Key (MEK) to the server during password recovery, breaking the zero-knowledge architecture.

### Original Vulnerable Flow

```
Client (Frontend)                          Server (Backend)
─────────────────────────────────────────────────────────────
1. User enters recovery key (raw MEK)
2. Re-wraps MEK with new password
3. Sends RAW MEK to server → /auth/recover
   {
     email,
     recovery_key: "raw-MEK-base64",  ← VULNERABILITY
     new_salt,
     new_wrapped_mek,
     new_auth_hash
   }
4. Server hashes the raw MEK for verification
5. Server updates user credentials
```

**Security Impact:**
- ❌ Raw MEK (Master Encryption Key) exposed in network traffic
- ❌ Raw MEK exposed in server logs/requests
- ❌ Raw MEK exposed in server memory during processing
- ❌ Complete vault decryption key sent to server
- ❌ Breaks zero-knowledge architecture

## Security Fix Implementation

### Fixed Flow (Using Argon2id Consistently)

```
Client (Frontend)                          Server (Backend)
─────────────────────────────────────────────────────────────
1. User enters recovery key (raw MEK)
2. Re-wraps MEK with new password
3. Client hashes recovery key: Argon2id(raw MEK)
   Security Parameters:
   - Memory (m): 64 MiB (65536 KiB)
   - Time/Iterations (t): 3 passes
   - Parallelism (p): 4 lanes/threads
   - Algorithm: Argon2id
   - Version: 0x13
4. Sends ONLY HASH to server → /auth/recover
   {
     email,
     recovery_key_hash: "argon2id-hash",  ← SECURE
     new_salt,
     new_wrapped_mek,
     new_auth_hash
   }
5. Server verifies Argon2id hash against stored Argon2id hash
6. Server updates user credentials
```

**Security Improvements:**
- ✅ Raw MEK never leaves client device
- ✅ Only Argon2id hash sent to server (using same security parameters as rest of system)
- ✅ Server cannot derive MEK from Argon2id hash
- ✅ Maintains zero-knowledge architecture
- ✅ Consistent security across entire system
- ✅ Defense-in-depth: Argon2id memory-hard hashing

## Code Changes

### 1. Rust: crypto.rs (New Function)

**Added Argon2id hashing function:**
```rust
/// Hashes the recovery key using Argon2id with consistent security parameters
/// Used for client-side hashing before sending to server during recovery
///
/// Security Parameters (matching the rest of the system):
/// - Memory (m): 64 MiB (65536 KiB)
/// - Time/Iterations (t): 3 passes
/// - Parallelism (p): 4 lanes/threads
/// - Algorithm: Argon2id
/// - Version: 0x13 (latest)
pub fn hash_recovery_key(recovery_key: &str) -> Result<String, String> {
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4), // m=64MiB, t=3, p=4
    ).map_err(|e| format!("Failed to create Argon2 instance: {}", e))?;

    let salt = argon2::password_hash::SaltString::generate(&mut rand_core::OsRng);
    
    let password_hash = argon2
        .hash_password(recovery_key.as_bytes(), &salt)
        .map_err(|e| format!("Argon2 hashing failed: {}", e))?;

    Ok(password_hash.to_string())
}
```

### 2. Rust: auth.rs (New Tauri Command)

**Added Tauri command for client-side hashing:**
```rust
/// Hash the recovery key using Argon2id with consistent security parameters
/// This is called client-side before sending to server for zero-knowledge recovery
#[tauri::command]
pub fn hash_recovery_key_command(recovery_key: String) -> Result<String, String> {
    crypto::hash_recovery_key(&recovery_key)
}
```

### 3. Rust: lib.rs (Register Command)

**Added new command to Tauri invoke handler:**
```rust
.invoke_handler(tauri::generate_handler![
    // ... existing commands ...
    commands::auth::hash_recovery_key_command,  // ← Added
    // ... rest of commands ...
])
```

### 4. Frontend: RecoveryPage.tsx

**Before:**
```typescript
await apiClient.post("/auth/recover", {
    email,
    recovery_key: recoveryKey.trim(),  // ← Raw MEK sent
    new_salt: recoverData.new_salt,
    new_wrapped_mek: recoverData.new_wrapped_mek,
    new_auth_hash: recoverData.new_auth_hash,
});
```

**After:**
```typescript
// Hash recovery key client-side using Argon2id before sending to server
// Using the same security parameters as the rest of the system:
// Memory (m): 64 MiB, Time/Iterations (t): 3 passes, Parallelism (p): 4 lanes/threads
const recoveryKeyHash = await invoke<string>("hash_recovery_key_command", {
    recoveryKey: recoveryKey.trim(),
});

await apiClient.post("/auth/recover", {
    email,
    recovery_key_hash: recoveryKeyHash,  // ← Argon2id hash sent
    new_salt: recoverData.new_salt,
    new_wrapped_mek: recoverData.new_wrapped_mek,
    new_auth_hash: recoverData.new_auth_hash,
});
```

### 5. Frontend: authService.ts

**Updated registration to use Argon2id:**
```typescript
// SECURITY: Hash recovery key using Argon2id with consistent security parameters
const recoveryKeyHash = await invoke<string>("hash_recovery_key_command", {
    recoveryKey: verifyKeys.recovery_key,
});

await apiClient.post("/auth/register", {
    email,
    salt: verifyKeys.salt,
    wrapped_mek: verifyKeys.wrapped_mek,
    auth_hash: verifyKeys.auth_hash,
    recovery_key_hash: recoveryKeyHash,  // ← Argon2id hash
});
```

### 6. Backend: authController.js

**Added consistent Argon2id configuration:**
```javascript
// Configure Argon2id with consistent security parameters
// Memory (m): 64 MiB, Time/Iterations (t): 3 passes, Parallelism (p): 4 lanes/threads
const argon2Options = {
  memoryCost: 65536, // 64 MiB in KiB
  timeCost: 3,       // 3 iterations
  parallelism: 4,     // 4 threads
  hashLength: 32,
  type: argon2.argon2id,
};
```

**Updated register function:**
```javascript
export const register = async (req, res) => {
  const { email, salt, wrapped_mek, auth_hash, recovery_key_hash } = req.body;

  const server_hash = await argon2.hash(auth_hash, argon2Options);

  const user = await createUser({
    email,
    salt,
    server_hash,
    wrapped_mek,
  });

  // SECURITY: Store the Argon2id hash directly (no double-hashing)
  const { error: rkError } = await supabase
    .from("recovery_keys")
    .insert({ user_id: user.id, key_hash: recovery_key_hash });
  // ...
}
```

**Updated recover function:**
```javascript
export const recover = async (req, res) => {
  // Server receives Argon2id hash instead of raw MEK
  const { email, recovery_key_hash, new_salt, new_wrapped_mek, new_auth_hash } = req.body;

  // Verify Argon2id hash directly against stored Argon2id hash
  const keyMatches = await argon2.verify(rkRow.key_hash, recovery_key_hash, argon2Options);
  
  const new_server_hash = await argon2.hash(new_auth_hash, argon2Options);
  
  // Rotate recovery key hash for forward secrecy
  const rotatedHash = await argon2.hash(recovery_key_hash, argon2Options);
  // ...
}
```

**Updated all Argon2 operations to use consistent parameters**
- All `argon2.hash()` calls updated to use `argon2Options`
- All `argon2.verify()` calls updated to use `argon2Options`

### 7. Backend: route/auth.js

**Updated validation schema:**
```javascript
const recoverBodySchema = Joi.object({
  email: Joi.string().email().required(),
  recovery_key_hash: Joi.string().required(), // Argon2id hash (not just hex)
  new_salt: Joi.string().required(),
  new_wrapped_mek: Joi.string().required(),
  new_auth_hash: Joi.string().required(),
});

router.post("/recover", validateRequest(recoverBodySchema), recover);
```

## Security Analysis

### Before Fix
- **Zero-Knowledge:** ❌ BROKEN - Server receives raw MEK
- **Server Knowledge:** ❌ Could potentially decrypt vault data
- **Network Security:** ❌ Raw MEK in HTTP requests
- **Memory Safety:** ❌ Raw MEK in server memory
- **Hash Consistency:** ❌ SHA-256 used instead of Argon2id

### After Fix
- **Zero-Knowledge:** ✅ MAINTAINED - Server only receives Argon2id hash
- **Server Knowledge:** ✅ Cannot derive MEK from Argon2id hash
- **Network Security:** ✅ Only Argon2id hash transmitted
- **Memory Safety:** ✅ Raw MEK never on server
- **Hash Consistency:** ✅ Argon2id used everywhere with same parameters
- **Brute Force Resistance:** ✅ Memory-hard Argon2id with 64 MiB, 3 iterations, 4 threads

### Why Argon2id Instead of SHA-256

**Security Advantages of Argon2id:**
1. **Memory-hard:** Requires 64 MiB memory per hash attempt, making GPU/ASIC attacks expensive
2. **Configurable parameters:** Can adjust security as hardware improves
3. **Proven security:** Recommended by OWASP for password hashing
4. **Consistency:** Same algorithm used throughout the system
5. **Future-proof:** Can increase parameters without changing algorithm

**SHA-256 Disadvantages:**
1. **Fast:** Designed for speed, not brute-force resistance
2. **Not memory-hard:** Vulnerable to GPU/ASIC attacks
3. **No parameters:** Cannot adjust security over time
4. **Inconsistent:** Different from rest of system's security model

### Security Parameters Justification

**Chosen Parameters (m=64 MiB, t=3, p=4):**
- **Memory (m): 65536 KiB (64 MiB)** - High enough to prevent GPU attacks, manageable for servers
- **Time (t): 3 iterations** - Balanced between security and user experience
- **Parallelism (p): 4 threads** - Utilizes modern multi-core CPUs effectively
- **Algorithm: Argon2id** - Resistant to side-channel attacks
- **Version: 0x13** - Latest stable version

### Remaining Security Considerations

1. **Recovery Key Still Powerful:** The recovery key is still the raw MEK and can decrypt all vault data
2. **User Responsibility:** Users must securely store their recovery key
3. **Client-Side Exposure:** Recovery key exists in client memory during recovery
4. **UI Display:** Recovery key shown in plain text during registration

### Recommended Future Enhancements

1. **Shamir's Secret Sharing:** Split recovery key into multiple parts
2. **Hardware Security Keys:** Use YubiKey or similar for recovery
3. **Time-Limited Display:** Auto-hide recovery key after X seconds
4. **Secure Element Storage:** Store recovery key in device secure enclave
5. **Multi-Factor Recovery:** Require additional verification for recovery

## Testing Recommendations

1. **End-to-End Recovery Test:** Verify complete recovery flow works with Argon2id
2. **Invalid Hash Test:** Verify rejection of incorrect recovery key hash
3. **Network Capture Test:** Verify only Argon2id hash in network traffic
4. **Memory Analysis Test:** Verify raw MEK not in server memory
5. **Performance Test:** Ensure Argon2id hashing doesn't degrade UX significantly
6. **Backward Compatibility:** Ensure existing users can still recover (may need migration)

## Migration Notes

**Breaking Changes:** 
- API contract changed for `/auth/recover` endpoint
- Frontend and backend must be deployed together
- Old recovery flows will fail until both sides updated
- Recovery key hash format changed from SHA-256 hex to Argon2id string

**Database Migration:**
- Existing SHA-256 recovery key hashes in database will become invalid
- Users will need to re-register or implement a migration strategy
- Consider providing a migration endpoint that accepts old SHA-256 hashes temporarily

**Deployment Strategy:**
1. Deploy backend with dual-hash support (accept both SHA-256 and Argon2id temporarily)
2. Deploy frontend with Argon2id hashing
3. Monitor system and ensure all new registrations use Argon2id
4. After migration period, remove SHA-256 support
5. Force password reset for users with old SHA-256 hashes

## Impact Assessment

**Affected Users:** All users who use recovery key functionality

**Breaking Changes:** 
- API contract changed for `/auth/recover` endpoint
- Frontend and backend must be deployed together
- Old recovery flows will fail until both sides updated
- Existing recovery key hashes may need migration

**Migration:** 
- Database migration may be required for existing users
- User action may be required for users with old-format hashes
- Consider temporary dual-hash support during transition

## Credits

**Vulnerability Discovered By:** User questioning during code review
**Security Analysis:** Zero-knowledge architecture review
**Fix Implementation:** Client-side Argon2id hashing with consistent security parameters
**Parameter Consistency:** Standardized on m=64 MiB, t=3, p=4 across entire system