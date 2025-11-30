# Custom Key Exchange Protocol Specification

## Protocol Name
**Authenticated ECDH with ECDSA Signatures and HKDF**

## Overview

This is a custom three-way authenticated key exchange protocol designed to prevent Man-in-the-Middle (MITM) attacks while establishing a shared session key for end-to-end encrypted messaging.

## Design Goals

1. **Mutual Authentication**: Both parties verify each other's identity
2. **Forward Secrecy**: Ephemeral keys for each session
3. **MITM Prevention**: Digital signatures authenticate public keys
4. **Replay Protection**: Nonces and timestamps prevent replay attacks
5. **Standardized Crypto**: Use only NIST-approved algorithms

## Cryptographic Primitives

- **Key Agreement**: ECDH (Elliptic Curve Diffie-Hellman) with P-256 curve
- **Signatures**: ECDSA with P-256 curve and SHA-256
- **KDF**: PBKDF2-based derivation (HKDF-like)
- **Symmetric Encryption**: AES-256-GCM (for subsequent messages)

## Protocol Participants

- **Alice** (Initiator): User initiating the key exchange
- **Bob** (Responder): User responding to the key exchange
- **Server** (Relay): Message relay (untrusted, cannot decrypt)

## Notation

- `A`, `B` = Alice and Bob
- `SK_A`, `PK_A` = Alice's long-term ECDSA signing key pair
- `SK_B`, `PK_B` = Bob's long-term ECDSA signing key pair
- `eph_SK_A`, `eph_PK_A` = Alice's ephemeral ECDH key pair
- `eph_SK_B`, `eph_PK_B` = Bob's ephemeral ECDH key pair
- `Sign(SK, data)` = ECDSA signature
- `Verify(PK, data, sig)` = ECDSA verification
- `ECDH(SK, PK)` = ECDH shared secret derivation
- `HKDF(secret, salt)` = HKDF key derivation
- `||` = Concatenation
- `N_A`, `N_B` = Nonces (128-bit random)
- `T_A`, `T_B` = Timestamps (Unix milliseconds)

## Protocol Steps

### Prerequisites

1. Alice and Bob have already registered and have long-term ECDSA key pairs
2. Public keys `PK_A` and `PK_B` are stored on the server
3. Private keys `SK_A` and `SK_B` are stored encrypted in each user's browser

### Step 1: Initiation (Alice → Server → Bob)

Alice wants to establish a secure channel with Bob.

**Alice computes:**
```
1. Generate ephemeral ECDH key pair: (eph_SK_A, eph_PK_A)
2. Generate nonce: N_A = random(128 bits)
3. Get current timestamp: T_A = now()
4. Create message: M1 = eph_PK_A || N_A || T_A
5. Sign message: Sig_A = Sign(SK_A, M1)
6. Send to server: {eph_PK_A, Sig_A, N_A, T_A, recipient: Bob}
```

**Server actions:**
```
1. Store key exchange request in database
2. Set status = 'INITIATED'
3. Set expiration = T_A + 10 minutes
4. Notify Bob (via polling or push)
```

### Step 2: Response (Bob → Server → Alice)

Bob retrieves the pending key exchange request.

**Bob computes:**
```
1. Retrieve Alice's long-term public key: PK_A (from server)
2. Reconstruct message: M1 = eph_PK_A || N_A || T_A
3. Verify timestamp: |now() - T_A| < 5 minutes
4. Verify signature: Verify(PK_A, M1, Sig_A)
   → If verification fails, ABORT (possible MITM attack!)
   
5. Generate ephemeral ECDH key pair: (eph_SK_B, eph_PK_B)
6. Generate nonce: N_B = random(128 bits)
7. Get current timestamp: T_B = now()
8. Create message: M2 = eph_PK_B || N_B || T_B
9. Sign message: Sig_B = Sign(SK_B, M2)

10. Derive shared secret: SS = ECDH(eph_SK_B, eph_PK_A)
11. Derive session key: 
    salt = N_A || N_B
    K_session = HKDF(SS, salt)
    
12. Send to server: {eph_PK_B, Sig_B, N_B, T_B}
```

**Server actions:**
```
1. Update key exchange record
2. Set status = 'RESPONDED'
3. Store Bob's data
```

### Step 3: Completion (Alice)

Alice retrieves Bob's response.

**Alice computes:**
```
1. Retrieve Bob's long-term public key: PK_B (from server)
2. Retrieve Bob's response: {eph_PK_B, Sig_B, N_B, T_B}
3. Reconstruct message: M2 = eph_PK_B || N_B || T_B
4. Verify timestamp: |now() - T_B| < 5 minutes
5. Verify signature: Verify(PK_B, M2, Sig_B)
   → If verification fails, ABORT (possible MITM attack!)
   
6. Derive shared secret: SS = ECDH(eph_SK_A, eph_PK_B)
7. Derive session key:
    salt = N_A || N_B
    K_session = HKDF(SS, salt)
    
8. Send confirmation to server
```

**Server actions:**
```
1. Set status = 'CONFIRMED'
2. Record confirmation timestamp
```

### Result

Both Alice and Bob now have the same `K_session` which will be used to encrypt all subsequent messages with AES-256-GCM.

## Protocol Flow Diagram

```
Alice                           Server                           Bob
  |                                |                               |
  |-- [eph_PK_A, Sig_A, N_A, T_A] |                               |
  |                                |-- Stored in DB                |
  |                                |                               |
  |                                |    [Pending Key Exchange] --|
  |                                |                 <Check pending>
  |                                |                               |
  |                                | <-- Retrieve PK_A from DB     |
  |                                |                 Verify(Sig_A) |
  |                                |                 Generate keys |
  |                                |  [eph_PK_B, Sig_B, N_B, T_B]--|
  |                                |<-- Derive K_session           |
  |                                |                               |
  |<-- [eph_PK_B, Sig_B, N_B, T_B] |                               |
  |    Verify(Sig_B)               |                               |
  |    Derive K_session            |                               |
  |                                |                               |
  |-- [Confirm]                    |                               |
  |                                |                               |
  |========== Encrypted Channel Established ======================|
  |                                |                               |
```

## Security Properties

### 1. Mutual Authentication
✅ Both parties verify each other's signatures  
✅ Attacker cannot impersonate without private key

### 2. MITM Prevention
✅ If attacker modifies `eph_PK_A` or `eph_PK_B`, signature verification fails  
✅ Both parties must have valid signatures from known public keys

### 3. Forward Secrecy
✅ Ephemeral ECDH keys used for each session  
✅ Compromise of long-term keys doesn't reveal past session keys  
✅ `eph_SK_A` and `eph_SK_B` are deleted after session key derivation

### 4. Replay Protection
✅ Nonces `N_A` and `N_B` are included in signed data  
✅ Timestamps prevent old messages from being replayed  
✅ Server tracks used nonces

### 5. Key Independence
✅ Different sessions have different `K_session`  
✅ Nonces ensure unique session keys even if same key pairs used

## Why This Protocol is Unique

1. **Three-way handshake**: Unlike standard ECDH (2-way)
2. **ECDSA signatures**: Added authentication layer
3. **Dual-nonce HKDF**: Both nonces mixed into key derivation
4. **Server-mediated**: Relay allows asynchronous communication
5. **Timestamp validation**: Additional replay protection

## Comparison with Standard Protocols

| Feature | Our Protocol | DH | ECDH | Station-to-Station |
|---------|--------------|----|----- |-------------------|
| MITM Protection | ✅ (ECDSA) | ❌ | ❌ | ✅ (Signatures) |
| Forward Secrecy | ✅ | ✅ | ✅ | ✅ |
| Nonce-based KDF | ✅ | ❌ | ❌ | ⚠️ |
| Timestamp Replay Protection | ✅ | ❌ | ❌ | ❌ |
| Async-friendly | ✅ | ❌ | ❌ | ❌ |

## Attack Resistance

### MITM Attack
**Attack**: Attacker intercepts and replaces public keys  
**Defense**: Signature verification fails because attacker cannot forge signatures

### Replay Attack
**Attack**: Attacker replays captured key exchange messages  
**Defense**: Timestamps and nonces prevent replay

### Impersonation
**Attack**: Attacker pretends to be Alice or Bob  
**Defense**: Cannot create valid signatures without private keys

### Key Compromise Impersonation (KCI)
**Attack**: Attacker compromises Alice's key, tries to impersonate Bob to Alice  
**Defense**: Bob's signature still required; attacker cannot forge Bob's signature

## Implementation Notes

### Cryptographic Parameters
- **Curve**: NIST P-256 (secp256r1)
- **Hash**: SHA-256
- **Signature Encoding**: ECDSA with IEEE P1363 format
- **HKDF Iterations**: 1000 (PBKDF2-based derivation)
- **Session Key Length**: 256 bits (for AES-256)

### Constants
```javascript
const MAX_TIMESTAMP_AGE = 5 * 60 * 1000; // 5 minutes
const CLOCK_SKEW_TOLERANCE = 60 * 1000;  // 1 minute
const NONCE_LENGTH = 16; // 128 bits
const SESSION_EXPIRY = 10 * 60 * 1000; // 10 minutes
```

### Error Handling
- Invalid signature → Abort, log security event
- Expired timestamp → Reject, log warning
- Missing nonce → Reject, log error
- Server unreachable → Retry with exponential backoff

## Future Enhancements

1. **Perfect Forward Secrecy**: Automatic key rotation every N messages
2. **Deniability**: Add deniable authentication (like Signal's X3DH)
3. **Post-Quantum**: Upgrade to post-quantum key exchange (e.g., Kyber)
4. **Group Chat**: Extend protocol for multi-party key agreement
5. **Fingerprint Verification**: Out-of-band public key verification

## References

1. NIST SP 800-56A Rev. 3 - Recommendation for Pair-Wise Key-Establishment Schemes
2. RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
3. FIPS 186-4 - Digital Signature Standard (ECDSA)
4. Signal Protocol - X3DH Key Agreement Protocol

---

**Protocol Version**: 1.0  
**Last Updated**: 2025-11-30  
**Status**: Educational/Experimental
