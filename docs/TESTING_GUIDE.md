# Testing Guide - E2E Encrypted Messaging System
## Step-by-Step Testing for Complete Beginners

> **⚠️ NOTE**: This guide assumes you have ZERO technical knowledge. We'll walk through everything step by step.

---

## Table of Contents
1. [Prerequisites - What You Need](#prerequisites)
2. [Setting Up the Environment](#setup)
3. [Testing User Registration](#test-registration)
4. [Testing User Login](#test-login)
5. [Testing Two-Factor Authentication (2FA)](#test-2fa)
6. [Testing Key Exchange Protocol](#test-key-exchange)
7. [Testing Encrypted Messaging](#test-messaging)
8. [Testing Security Logs](#test-logs)
9. [Testing Attack Demonstrations](#test-attacks)
10. [Verifying Encryption in Database](#verify-encryption)

---

## 1. Prerequisites - What You Need {#prerequisites}

### Software to Install (in order):
1. **Node.js** (v16 or higher)
   - Download from: https://nodejs.org/
   - Click the big green "Download" button
   - Run the installer, keep clicking "Next"
   - Verify installation: Open Command Prompt (type `cmd` in Windows search) and type:
     ```
     node --version
     ```
     You should see something like `v22.14.0`

2. **MongoDB**
   - Download from: https://www.mongodb.com/try/download/community
   - Choose "Windows" and download MSI file
   - Run installer, keep defaults
   - Verify MongoDB is running (it should start automatically)

3. **Git** (for downloading the code) 
   - Download from: https://git-scm.com/
   - Run installer, keep all defaults

4. **A Web Browser**
   - Chrome, Firefox, or Edge (any modern browser)

5. **A Text Editor** (optional, for viewing code)
   - VS Code: https://code.visualstudio.com/

---

## 2. Setting Up the Environment {#setup}

### Step 1: Download the Project
1. Open Command Prompt (Press Windows Key, type `cmd`, press Enter)
2. Change to your Desktop:
   ```
   cd Desktop
   ```
3. Clone the repository:
   ```
   git clone https://github.com/Saoudi222467/i222467_i222512_i222618_InfoSec.git
   ```
4. Go into the project folder:
   ```
   cd i222467_i222512_i222618_InfoSec
   ```

### Step 2: Start MongoDB
1. MongoDB should have started automatically when you installed it
2. To verify it's running, open **MongoDB Compass** (search for it in Windows)
3. You should see "localhost:27017" - this means MongoDB is running ✅

### Step 3: Install Backend Dependencies
1. In Command Prompt, navigate to backend:
   ```
   cd backend
   ```
2. Install packages:
   ```
   npm install
   ```
3. Wait for it to finish (may take 1-2 minutes)
4. You should see **"added 202 packages"** and **"0 vulnerabilities"** ✅

### Step 4: Start the Backend Server
1. Still in the backend folder, run:
   ```
   npm run dev
   ```
2. You should see:
   ```
   Server running on http://localhost:4000
   Connected to MongoDB successfully
   ```
3. **Keep this window open!** The server needs to stay running.

### Step 5: Install Frontend Dependencies  
1. Open a **NEW** Command Prompt window (don't close the backend one!)
2. Navigate to the project:
   ```
   cd Desktop\i222467_i222512_i222618_InfoSec
   ```
3. Go to frontend folder:
   ```
   cd frontend
   ```
4. Install packages:
   ```
   npm install
   ```
5. Wait for completion

### Step 6: Start the Frontend
1. In the frontend folder, run:
   ```
   npm run dev
   ```
2. You should see:
   ```
   Local:   http://localhost:5174/
   ```
3. **Keep this window open too!**

### Step 7: Open the App  
1. Open your web browser
2. Go to: **http://localhost:5174/**
3. You should see the **Login page** with  cream and teal colors ✅

---

## 3. Testing User Registration {#test-registration}

### What to Look For:
- Private key generation (client-side)
- Password-based encryption of private key
- Key storage in IndexedDB (browser database)
- Public key sent to server

### Steps to Test:

1. **Open the App**: Go to http://localhost:5174/
2. **See the Login Page**: You should see "Welcome Back" with a cream colored card
3. **Click "Register"**: The link is RIGHT BELOW the "Sign In" button
4. **Fill in the Registration Form**:
   - Username: `testuser1`
   - Password: `password123`  (at least 8 characters)
   - Confirm Password: `password123`
  
5. **Watch the Status Messages** (top of form):
   - "Generating cryptographic keys..." ⏳
   - "Exporting public key..." ⏳
   - "Registering with server..." ⏳
   - "Encrypting and storing private key securely..." ⏳
   - "Registration successful! You can now log in." ✅

6. ** after 2 seconds, you'll be redirected back to Login**

### What Just Happened (Behind the Scenes):
✅ A key pair (public + private) was generated using ECC P-256  
✅ Private key was encrypted with YOUR password using PBKDF2  
✅ Encrypted private key was stored in IndexedDB (browser storage)  
✅ Only the PUBLIC key was sent to the server  
✅ Password was hashed with bcryptjs before sending to server  

### Verify in Browser DevTools:
1. Press **F12** to open Developer Tools
2. Click **"Application"** tab (Chrome) or **"Storage"** tab (Firefox)
3. Expand **"IndexedDB"** → **"SecureMessagingKeys"** → **"users"**
4. You should see your userId with an encrypted private key ✅
5. The private key looks like gibberish - this is GOOD! It's encrypted.

---

## 4. Testing User Login {#test-login}

### What to Look For:
- Password verification
- Private key retrieval and decryption
- JWT token issuance

### Steps to Test:

1. **You should already be on the Login page** (after registration)
2. **Enter your credentials**:
   - Username: `testuser1`
   - Password: `password123`
3. **Click "Sign In"**
4. **Watch the Status Messages**:
   - "Authenticating..." ⏳
   - "Retrieving encryption keys..." ⏳
   - "Login successful!" ✅

5. **You'll be redirected to the Chat Interface**

### What Just Happened:
✅ Server verified your password hash  
✅ Your encrypted private key was retrieved from IndexedDB  
✅ Private key was decrypted using your password  
✅ JWT token was issued for this session  
✅ You're now logged in!  

### Test Wrong Password:
1. Log out (click "Logout" in top right)
2. Try to login with WRONG password: `wrongpassword`
3. You should see: **"Failed to decrypt private key. Wrong password?"** ❌
4. This proves the private key is encrypted properly!

---

##5. Testing Two-Factor Authentication (2FA) {#test-2fa}

### What You Need:
- A phone with an authenticator app (Google Authenticator, Authy, Microsoft Authenticator)
- Or use a browser extension like "Authenticator" for Chrome/Edge

### Overview:
Two-Factor Authentication (2FA) is now integrated into the registration flow! When you register a new account, you'll be given the option to enable 2FA immediately. If enabled, you'll need to enter a 6-digit code from your authenticator app every time you log in.

---

### Test 1: Registering with 2FA Enabled

1. **Start Registration**: Go to http://localhost:5174/ and click "Register"
2. **Fill in Registration Form**:
   - Username: `user2fa`
   - Password: `password123`
   - Confirm Password: `password123`
3. **Click "Create Account"**
4. **Wait for Key Generation**: You'll see status messages about generating keys and storing them securely
5. **2FA Setup Screen Appears**: After registration succeeds, you should see:
   - Title: "🔐 Two-Factor Authentication"
   - Description: "Add an extra layer of security to your account"
   - Two buttons: "✓ Yes, Enable 2FA" and "Skip for Now"

6. **Click "✓ Yes, Enable 2FA"**
7. **QR Code Appears**: You'll see:
   - "Step 1: Scan QR Code"
   - A QR code image
   - Instructions to use your authenticator app

8. **Scan QR Code**:
   - Open Google Authenticator (or Authy/Microsoft Authenticator) on your phone
   - Tap "+" to add a new account
   - Choose "Scan QR Code"
   - Point your camera at the QR code on screen
   - The app will show "SecureChat (user2fa)" with a 6-digit code

9. **Enter Verification Code**:
   - Look at the 6-digit code in your authenticator app
   - Type it into the input field on screen
   - Click "Verify and Enable"
   - **Expected**: "2FA enabled successfully! Redirecting to login..."
   - You'll be redirected to the login page after 2 seconds

### What Just Happened:
✅ Your account was created with encryption keys  
✅ A 2FA secret was generated on the server  
✅ QR code was created containing the secret  
✅ Your authenticator app stored the secret locally  
✅ Your verification code proved you have the secret  
✅ 2FA is now enabled for your account  

---

### Test 2: Login with 2FA Enabled

1. **At Login Page**: Enter your credentials:
   - Username: `user2fa`
   - Password: `password123`
2. **Click "Sign In"**
3. **2FA Prompt Appears**:
   - Username and password fields become disabled
   - New field appears: "2FA Code"
   - Placeholder shows: "000000"
   - Instructions: "Enter the 6-digit code from your authenticator app"

4. **Open Authenticator App**: Look at the code for "SecureChat (user2fa)"
5. **Enter the 6-Digit Code**: Type it into the 2FA Code field
6. **Click "Sign In"** again
7. **Expected**: Successfully log in to chat interface ✅

### What Just Happened:
✅ Server verified your password  
✅ Server detected you have 2FA enabled  
✅ Login paused to request 2FA code  
✅ Server verified the code matches your secret  
✅ Both factors authenticated - you're now logged in!  

---

### Test 3: Login with Wrong 2FA Code

1. **Logout** and return to login page
2. **Enter credentials** and click "Sign In"
3. **When 2FA prompt appears**, enter a WRONG code: `000000`
4. **Click "Sign In"**
5. **Expected**: Error message "Invalid 2FA token" ❌
6. **Try again** with the correct code from your auth app
7. **Expected**: Successfully log in ✅

---

### Test 4: Registering Without 2FA (Skip Option)

1. **Register a different user**:
   - Go to registration page
   - Username: `plainuser`
   - Password: `password123`
   - Confirm Password: `password123`
2. **Click "Create Account"**
3. **When 2FA setup screen appears**, click "Skip for Now"
4. **Expected**: Immediately redirected to login page

5. **Login without 2FA**:
   - Username: `plainuser`
   - Password: `password123`
   - Click "Sign In"
6. **Expected**: Log in directly to chat - NO 2FA prompt! ✅

---

### Test 5: Verify in Database

1. **Open MongoDB Compass**
2. **Connect to `localhost:27017`**
3. **Navigate to**: `secure-chat` database → `users` collection

4.**Find user with 2FA**:
   - Look for username: `user2fa`
   - Check fields:
     - `twoFactorEnabled`: should be `true` ✅
     - `twoFactorSecret`: should contain a base32 string ✅

5. **Find user without 2FA**:
   - Look for username: `plainuser`
   - Check fields:
     - `twoFactorEnabled`: should be `false` ✅
     - `twoFactorSecret`: should be `null` ✅

6. **Check Security Logs**:
   - Navigate to `securitylogs` collection
   - Look for events:
     - `AUTH_2FA_SETUP` - when QR code was generated
     - `AUTH_2FA_ENABLED` - when verification succeeded
     - `AUTH_2FA_LOGIN_SUCCESS` - when user logged in with 2FA
     - `AUTH_2FA_LOGIN_FAILED` - if wrong code was entered

---

### Understanding the 2FA Flow

**Registration Flow (with 2FA)**:
``` 
User Registers → Keys Generated → Account Created
   ↓
2FA Setup Screen
   ↓
User clicks "Enable 2FA"
   ↓
Server generates TOTP secret → Creates QR code
   ↓
User scans QR with auth app
   ↓
User enters 6-digit verification code
   ↓
Server verifies code → Enables 2FA
   ↓
Redirect to Login
```

**Login Flow (with 2FA enabled)**:
```
User enters username/password → Server verifies
   ↓
Server checks: 2FA enabled?
   ↓
YES → Request 2FA code
   ↓
User enters code from auth app
   ↓
Server verifies TOTP code
   ↓
Both factors valid → Grant access
```

---

### Important Notes:

⚠️ **Losing Access**: If you lose your phone or uninstall your authenticator app, you will NOT be able to login! In a production system, you would need:
- Backup codes
- Account recovery system
- Admin assistance

⚠️ **Time Synchronization**: TOTP codes are time-based (change every 30 seconds). Make sure your phone's time is accurate!

⚠️ **One-Time Setup**: You only scan the QR code ONCE during registration. After that, your authenticator app will generate codes automatically.

✅ **Security Benefit**: Even if someone steals your password, they can't login without your phone!



---

## 6. Testing Key Exchange Protocol {#test-key-exchange}

### What You Need:
- Two different browsers (or two incognito/private windows)
- Two user accounts

### Setup:
1. **Register a second user**:
   - Open an incognito window: Ctrl+Shift+N (Chrome) or Ctrl+Shift+P (Firefox)
   - Go to: http://localhost:5174/
   - Register as `testuser2` with password `password123`

2. **Now you have**:
   - Regular browser: `testuser1` logged in
   - Incognito browser: log in as `testuser2`

### Test the Key Exchange:

**In testuser1's browser**:
1. Look at the left sidebar - you should see `testuser2` listed
2. Click on `testuser2` to select them
3. You'll see: **"⚠️ No session key - run key exchange"**
4. Click the **"🔑 Start Key Exchange"** button
5. A popup will ask for your password - enter `password123`
6. You'll see: **"Key exchange initiated!"** with an ID
7. Status shows: **"Waiting for response..."**

**What Just Happened**:
✅ testuser1 generated an ephemeral ECDH key pair  
✅ Public ECDH key was signed with testuser1's private key (ECDSA)  
✅ Signed message was sent to server  
✅ Waiting for testuser2 to respond  

**In testuser2's browser**:
1. Select `testuser1` from the sidebar
2. You should also see the option to start key exchange
3. Click **"🔑 Start Key Exchange"**
4. Enter password when prompted
5. The system will detect the pending key exchange and complete it automatically

**Both browsers now show**:
- **"✅ End-to-end encrypted"** ✅
- A green lock icon or similar indicator
- The message input is now enabled

### What Just Happened (The Full Protocol):
1. ✅ testuser1 sent: ECDH public key + signature + nonce
2. ✅ testuser2 verified the signature (proves it's really testuser1)
3. ✅ testuser2 sent back: their ECDH public key + signature + nonce
4. ✅ testuser1 verified testuser2's signature
5. ✅ Both users performed ECDH to derive the same shared secret
6. ✅ Shared secret + both nonces were used with HKDF to derive session key
7. ✅ Session key is stored in sessionStorage (cleared when tab closes)

---

## 7. Testing Encrypted Messaging {#test-messaging}

### Prerequisites:
- Complete key exchange (from previous section)
- Both users should see "✅ End-to-end encrypted"

### Test Sending Messages:

**In testuser1's browser**:
1. Type a message in the input box: `Hello from user1!`
2. Click **"Send"** (or press Enter)
3. The message appears in YOUR chat as a **teal bubble** (your own message)

**In testuser2's browser**:
1. You should see the message appear as a **cream/light bubble** (other person's message)
2. The message says: `Hello from user1!`
3. Type a reply: `Hi from user2!`
4. Click Send

**In testuser1's browser**:
- You now see user2's reply ✅

### What Just Happened:
✅ Message was encrypted client-side with AES-256-GCM  
✅ A random IV (initialization vector) was generated  
✅ Nonce, timestamp, and sequence number were added  
✅ Server received only CIPHERTEXT (encrypted data)  
✅ Recipient decrypted the message client-side  
✅ Server NEVER saw the plaintext message  

### Test Replay Protection:

1. Open Browser DevTools (F12)
2. Go to "Network" tab
3. Send a message: `Test replay`
4. In Network tab, find the POST request to `/api/messages`
5. Right-click → "Copy" → "Copy as cURL" (or "Copy as fetch")
6. Open the Console tab (in DevTools)
7. Paste the copied command and run it again
8. You should see: **"Replay attack detected"** or **"Duplicate nonce"** ❌
9. The message won't appear twice - replay was blocked ✅

---

## 8. Testing Security Logs {#test-logs}

### Where to Find Logs:

**In the App**:
1. Click **"📊 Logs"** button in the header (top right)
2. You'll see a dashboard with:
   - **Total Events** - number of security events logged
   - **Attacks Detected** - any suspicious activity
   - **Replay Attempts** - blocked replay attacks
   - **Successful Logins**

3. Below the stats, there's a table showing:
   - **Time** - when the event occurred
   - **Event Type** - what happened (login, key exchange, etc.)
   - **Severity** - INFO, WARNING, ERROR, CRITICAL
   - **Details** - more information about the event

### What to Look For:
✅ USER_LOGIN events for each login  
✅ KEY_EXCHANGE_INITIATED when you start key exchange  
✅ MESSAGE_SENT events for each message  
✅ LOGIN_FAILED if you tried wrong password  
✅ REPLAY_ATTACK_DETECTED if you tested replay attacks  

### Check Logs in Database:

1. Open **MongoDB Compass**
2. Connect to `localhost:27017`
3. Select database: `secure-chat`
4. Click on collection: `securitylogs`
5. You should see all logged events with timestamps ✅

---

## 9. Testing Attack Demonstrations {#test-attacks}

### A. Test MITM Attack (Man-in-the-Middle)

The project includes attack demonstration scripts in the `attacks/` folder.

**To test MITM without signatures** (vulnerable):
1. Open Command Prompt
2. Navigate to attack scripts:
   ```
   cd Desktop\i222467_i222512_i222618_InfoSec\attacks\mitm-demo
   ```
3. Run the vulnerable demonstration:
   ```
   node attack-nosig.js
   ```
4. You'll see: Attacker can successfully intercept ❌

**To test MITM with signatures** (protected):
1. Run the protected demonstration:
   ```
   node attack-withsig.js
   ```
2. You'll see: **"Signature verification failed"** - Attack blocked! ✅

### B. Test Replay Attack

**From the UI** (already tested in section 7):
- Try to resend a captured message
- System detects duplicate nonce
- Message is rejected ✅

**Using script**:
1. Navigate to:
   ```
   cd Desktop\i222467_i222512_i222618_InfoSec\attacks\replay-demo
   ```
2. Run:
   ```
   node replay-attack.js
   ```
3. Script attempts to repolay a message
4. Server rejects it due to duplicate nonce/timestamp ✅

---

## 10. Verifying Encryption in Database {#verify-encryption}

### This is the MOST IMPORTANT test - proving E2EE works!

1. **Send a message** in the chat: `This message is secret!`

2. **Open MongoDB Compass**

3. **Navigate to the messages**:
   - Database: `secure-chat`
   - Collection: `messages`

4. **Find your message**:
   - Click on the newest document (last one in the list)
   - You'll see fields like:
     ```javascript
     {
       sender: "testuser1_id",
       receiver: "testuser2_id",
       ciphertext: "gH7sK9mP3qL2vB8nX...",  // Encrypted gibberish!
       iv: "xY4zT1pR9mK3sL8f",
       nonce: "aB5cD9eF3gH7jK2mN...",
       timestamp: "2025-12-02T15:30:45.123Z",
       sequenceNumber: 1
     }
     ```

5. **Verify**:
   ✅ The `ciphertext` is UNREADABLE gibberish  
   ✅ NO `plaintext` or `message` field exists  
   ✅ Server only has encrypted data  
   ✅ End-to-end encryption confirmed!  

6. **Try to decrypt manually** (optional advanced test):
   - You CAN'T! Only the recipient can decrypt it with their session key
   - Even if you have access to the database, you can't read messages
   - This proves true E2EE ✅

---

## Quick Troubleshooting

### Problem: "Cannot connect to MongoDB"
**Solution**:
1. Check if MongoDB is running (open MongoDB Compass)
2. Restart MongoDB service:
   - Open Services app (Windows search: "services")
   - Find "MongoDB Server"
   - Right-click → Restart

### Problem: "Port 4000 is already in use"
**Solution**:
1. Close any running backend servers
2. Or kill the process:
   ```
   netstat -ano | findstr :4000
   taskkill /PID <process_id> /F
   ```

### Problem: "npm install fails"
**Solution**:
1. Delete `node_modules` folder
2. Delete `package-lock.json`
3. Run `npm install` again

### Problem: "Can't see messages"
**Solution**:
1. Make sure BOTH users completed key exchange
2. Check that status shows "✅ End-to-end encrypted"
3. Refresh both browsers and try again

### Problem: "Private key not found"
**Solution**:
1. Clear browser storage (F12 → Application → Clear storage)
2. Register again (this generates new keys)

---

## Summary Checklist

After completing all tests, you should have verified:

- [x] ✅ User registration with key generation
- [x] ✅ Private keys encrypted and stored locally
- [x] ✅ User login with key decryption
- [x] ✅ Key exchange protocol with signatures
- [x] ✅ End-to-end encrypted messaging
- [x] ✅ Replay attack protection
- [x] ✅ MITM attack prevention
- [x] ✅ Security logging
- [x] ✅ Messages encrypted in database
- [x] ✅ All cryptography client-side only

**Congratulations!** 🎉 You've successfully tested a complete E2E encrypted messaging system!
