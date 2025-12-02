# E2E Encrypted Messaging System

A secure, end-to-end encrypted messaging application with custom key exchange protocol, implementing modern cryptography standards and demonstrating defense against common attacks.

## 🎯 Project Overview

This is a comprehensive information security project implementing:
- **End-to-End Encryption** using AES-256-GCM
- **Custom ECDH Key Exchange Protocol** with ECDSA signatures
- **Replay Attack Protection** with nonces, timestamps, and sequence numbers
- **MITM Attack Prevention** using digital signatures
- **Complete Security Audit Logging**

### Key Features

✅ Client-side only encryption (server never sees plaintext)  
✅ Private keys stored encrypted in IndexedDB  
✅ **Two-Factor Authentication (2FA)** with TOTP (Time-based One-Time Password)  
✅ Web Crypto API for all cryptographic operations  
✅ Custom authenticated key exchange protocol  
✅ Real-time attack detection and logging  
✅ File sharing with chunked encryption  
✅ Security dashboard with audit logs  

## 🏗️ Technology Stack

### Frontend
- **React.js** with Vite
- **Web Crypto API** (SubtleCrypto) for encryption
- **IndexedDB** for encrypted key storage
- **Axios** for API communication

### Backend
- **Node.js + Express**
- **MongoDB** for metadata storage
- **bcrypt** for password hashing
- **JWT** for authentication
- **Winston** for logging

### Cryptography
- **ECC P-256** for user identity keys (ECDSA signatures)
- **ECDH** for ephemeral key exchange
- **AES-256-GCM** for message/file encryption
- **PBKDF2** (HKDF-like) for session key derivation
- **Random IVs** (96-bit) for each message

## 📁 Project Structure

```
infosecproj/
├── backend/
│   ├── src/
│   │   ├── models/          # MongoDB schemas
│   │   ├── routes/          # API endpoints
│   │   ├── middleware/      # Auth, logging, replay protection
│   │   └── server.js        # Express server
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── crypto/          # Web Crypto implementations
│   │   ├── components/      # React components
│   │   ├── services/        # API service
│   │   └── App.jsx
│   └── package.json
├── attacks/                  # Attack demonstrations
│   ├── mitm-demo/
│   └── replay-demo/
└── docs/                     # Documentation
    ├── architecture.md
    ├── protocol-spec.md
    └── threat-model.md
```

## 🚀 Quick Start

### Prerequisites
- Node.js (v16+)
- MongoDB (running on localhost:27017)
- Modern web browser (Chrome/Firefox/Edge)

### 1. Backend Setup

```bash
cd backend
npm install
npm run dev
# Server will run on http://localhost:4000
```

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
# App will run on http://localhost:5173
```

### 3. MongoDB Setup

The app will automatically connect to `mongodb://localhost:27017/secure-chat`.  
Make sure MongoDB is running:

```bash
# Windows
mongod

# Or use MongoDB Compass
```

## 📖 Usage Guide

### 1. Registration
1. Click "Register" on the home screen
2. Enter username and password (min 8 characters)
3. **Private key generation happens automatically** (ECC P-256)
4. Private key is encrypted with your password and stored in IndexedDB
5. Only public key is sent to server
6. **(Optional)** Set up Two-Factor Authentication for enhanced security

### 2. Two-Factor Authentication (2FA) Setup
1. After registration or from your profile, click "Enable 2FA"
2. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)
3. Or manually enter the secret key shown
4. Enter the 6-digit verification code from your app
5. 2FA is now enabled for your account
6. **Important**: Save your backup codes in a secure location

### 3. Login
1. Enter credentials
2. If 2FA is enabled, you'll be prompted for your 6-digit code
3. Enter the code from your authenticator app
4. Private key is decrypted from IndexedDB using your password
5. JWT token issued for API authentication

### 4. Starting a Secure Conversation

#### Option A: Automated Key Exchange (Recommended)
1. Select a contact from the sidebar
2. Click "🔑 Start Key Exchange"
3. Enter your password to access private key
4. Protocol executes:
   - Alice sends signed ECDH public key
   - Bob receives, verifies signature, sends his signed ECDH public key
   - Both derive same session key using ECDH + HKDF
5. Messages are now encrypted end-to-end

#### Option B: Manual Session Key Import
1. Share a pre-generated session key out-of-band
2. Click "📥 Import Key"
3. Paste base64 session key
4. Start messaging

### 5. Sending Messages
- Type message in input field
- Click "Send"
- Message is encrypted client-side with AES-256-GCM
- Server stores only ciphertext, IV, nonce, sequence number
- Recipient decrypts locally

### 6. Viewing Security Logs
- Click "📊 Logs" in header
- View authentication attempts
- See detected replay attacks
- Monitor system security events

## 🔐 Security Features

### 1. End-to-End Encryption
- All encryption/decryption happens in browser
- Server stores only encrypted ciphertext
- Private keys never transmitted

### 2. Custom Key Exchange Protocol

**Our Unique Variant:**
```
Alice                                    Bob
  |                                       |
  |-- Signed ECDH PubKey -->             |
  |   (signed with Alice's ECDSA key)    |
  |                                       |
  |         <-- Signed ECDH PubKey ----   |
  |           (signed with Bob's key)     |
  |                                       |
  Both derive session key:
  sessionKey = HKDF(ECDH(Alice_eph, Bob_eph), nonceA || nonceB)
```

**Why signatures prevent MITM:**
- Attacker cannot forge signatures without private keys
- If public keys are modified in transit, signature verification fails
- Both parties authenticate each other before deriving session key

### 3. Replay Attack Protection

**Three-layer defense:**
1. **Nonce**: Random 128-bit value, checked for uniqueness
2. **Timestamp**: Messages rejected if older than 5 minutes
3. **Sequence Number**: Monotonically increasing per conversation

Server validates all three before accepting messages.

### 4. Security Logging

All security events logged to MongoDB:
- Authentication attempts (success/failure)
- Key exchange sessions
- Replay attack detections
- Invalid signature attempts
- Decryption failures

## 🎯 Attack Demonstrations

### MITM Attack Demo

Located in `attacks/mitm-demo/`:

**Without Signatures (Vulnerable):**
```bash
node attacks/mitm-demo/attack-nosig.js
# Shows successful MITM interception
```

**With Signatures (Protected):**
```bash
node attacks/mitm-demo/attack-withsig.js
# Signature verification fails, attack prevented
```

### Replay Attack Demo

Located in `attacks/replay-demo/`:

```bash
node attacks/replay-demo/replay-attack.js
# Attempts to resend captured message
# Server detects duplicate nonce and rejects
```

## 📊 Testing & Verification

### Manual Testing Checklist

- [ ] Register two users
- [ ] Perform key exchange between users
- [ ] Send encrypted messages
- [ ] Verify server database contains only ciphertext
- [ ] Check private key in IndexedDB (encrypted)
- [ ] Attempt replay attack (should be rejected)
- [ ] View security logs
- [ ] Export session key and import on different device

### Wireshark Packet Capture

1. Start Wireshark on loopback interface
2. Filter: `tcp.port == 4000`
3. Observe POST /api/messages
4. Verify only encrypted data in payload

### BurpSuite Testing

1. Configure browser to use Burp proxy
2. Intercept key exchange messages
3. Attempt to modify ECDH public key
4. Observe signature verification failure on client

## 📝 Security Analysis (STRIDE)

See [docs/threat-model.md](docs/threat-model.md) for complete analysis.

**Summary:**
- **Spoofing**: Prevented by digital signatures
- **Tampering**: Prevented by AES-GCM authentication tags
- **Repudiation**: Mitigated by comprehensive logging
- **Information Disclosure**: Prevented by E2E encryption
- **Denial of Service**: Rate limiting (to implement)
- **Elevation of Privilege**: JWT authentication + authorization

## 🔬 Cryptographic Specifications

### Key Sizes
- **User Identity Keys**: ECC P-256 (256-bit)
- **Ephemeral ECDH Keys**: P-256
- **Session Keys**: AES-256 (256-bit)
- **Nonces**: 128-bit
- **IVs**: 96-bit (GCM recommended size)

### Algorithms
- **Asymmetric**: ECDH (key exchange), ECDSA (signatures)
- **Symmetric**: AES-256-GCM
- **Hash**: SHA-256
- **KDF**: PBKDF2 (100,000 iterations for key storage, 1,000 for HKDF-like derivation)

### Security Properties
✅ Confidentiality (AES-256-GCM)  
✅ Integrity (GCM authentication tags)  
✅ Authenticity (ECDSA signatures)  
✅ Forward Secrecy (ephemeral ECDH keys)  
✅ Replay Protection (nonce + timestamp + sequence)  

## 🐛 Known Limitations

1. **Session Key Management**: Currently uses sessionStorage (cleared on tab close). Production would use persistent encrypted storage.
2. **Key Backup**: No automatic backup mechanism. Users must manually export keys.
3. **Multi-Device**: Private keys don't sync between devices.
4. **Group Chat**: Not implemented (only 1-to-1 messaging).
5. **Perfect Forward Secrecy**: Session keys are long-lived. Should implement key rotation.

## 📚 Documentation

- [Architecture Diagram](docs/architecture.md)
- [Complete Protocol Specification](docs/protocol-spec.md)
- [STRIDE Threat Model](docs/threat-model.md)
- [Wireshark Capture Guide](attacks/wireshark-capture.md)

## 🎓 Learning Outcomes

This project demonstrates:
1. Practical application of symmetric and asymmetric cryptography
2. Designing secure key exchange protocols
3. Implementing replay attack protection
4. Understanding and preventing MITM attacks
5. Security logging and threat modeling
6. Proper use of Web Crypto API
7. Secure key storage practices

## 📄 License

Educational project for information security coursework.

## 👥 Contributors

[Your Names Here]

---

**⚠️ Disclaimer**: This is an educational project. Do NOT use in production without professional security audit.
