/**
 * MITM Attack Demonstration - WITHOUT Digital Signatures
 * 
 * This demonstrates how an attacker can perform a successful Man-in-the-Middle
 * attack on a basic Diffie-Hellman key exchange WITHOUT authentication.
 * 
 * Attack Scenario:
 * 1. Alice initiates key exchange with Bob
 * 2. Attacker intercepts Alice's public key
 * 3. Attacker sends their own public key to Bob (pretending to be Alice)
 * 4. Attacker intercepts Bob's public key
 * 5. Attacker sends their own public key to Alice (pretending to be Bob)
 * 6. Attacker now has two session keys:
 *    - One with Alice (Alice thinks it's with Bob)
 *    - One with Bob (Bob thinks it's with Alice)
 * 7. Attacker can decrypt and read all messages
 * 
 * This is why our system uses ECDSA signatures!
 */

const crypto = require('crypto');

console.log('='.repeat(70));
console.log('MITM ATTACK DEMONSTRATION - WITHOUT SIGNATURES (Vulnerable)');
console.log('='.repeat(70));
console.log('');

// Alice generates her key pair
console.log('Step 1: Alice generates ECDH key pair');
const alice = crypto.createECDH('prime256v1');
const alicePublicKey = alice.generateKeys();
console.log(`Alice's public key: ${alicePublicKey.toString('base64').substring(0, 40)}...`);
console.log('');

// Bob generates his key pair
console.log('Step 2: Bob generates ECDH key pair');
const bob = crypto.createECDH('prime256v1');
const bobPublicKey = bob.generateKeys();
console.log(`Bob's public key: ${bobPublicKey.toString('base64').substring(0, 40)}...`);
console.log('');

// ATTACKER intercepts and generates their own key pair
console.log('⚠️  Step 3: ATTACKER INTERCEPTS! Generates own ECDH key pair');
const attacker = crypto.createECDH('prime256v1');
const attackerPublicKey = attacker.generateKeys();
console.log(`Attacker's public key: ${attackerPublicKey.toString('base64').substring(0, 40)}...`);
console.log('');

console.log('💀 Step 4: Attacker replaces public keys in transit');
console.log('   - Sends attacker\'s key to Bob (Bob thinks it\'s from Alice)');
console.log('   - Sends attacker\'s key to Alice (Alice thinks it\'s from Bob)');
console.log('');

// Alice computes shared secret (but with attacker's key, not Bob's)
console.log('Step 5: Alice computes shared secret with attacker (thinks it\'s Bob)');
const aliceSharedSecret = alice.computeSecret(attackerPublicKey);
console.log(`Alice's "shared secret": ${aliceSharedSecret.toString('hex').substring(0, 32)}...`);
console.log('');

// Bob computes shared secret (but with attacker's key, not Alice's)
console.log('Step 6: Bob computes shared secret with attacker (thinks it\'s Alice)');
const bobSharedSecret = bob.computeSecret(attackerPublicKey);
console.log(`Bob's "shared secret": ${bobSharedSecret.toString('hex').substring(0, 32)}...`);
console.log('');

// Attacker computes shared secrets with both
console.log('💀 Step 7: Attacker computes BOTH shared secrets');
const attackerAliceSecret = attacker.computeSecret(alicePublicKey);
const attackerBobSecret = attacker.computeSecret(bobPublicKey);
console.log(`Secret with Alice: ${attackerAliceSecret.toString('hex').substring(0, 32)}...`);
console.log(`Secret with Bob:   ${attackerBobSecret.toString('hex').substring(0, 32)}...`);
console.log('');

// Verify attacker has the same secrets
console.log('✅ Step 8: Verification');
console.log(`Attacker-Alice secret matches Alice's secret: ${attackerAliceSecret.equals(aliceSharedSecret)}`);
console.log(`Attacker-Bob secret matches Bob's secret:     ${attackerBobSecret.equals(bobSharedSecret)}`);
console.log('');

// Demonstrate message interception
console.log('💀 Step 9: Alice sends encrypted message to "Bob"');
const aliceSessionKey = aliceSharedSecret.slice(0, 32);
const aliceCipher = crypto.createCipheriv('aes-256-gcm', aliceSessionKey, Buffer.alloc(12));
const message = 'Hello Bob! This is a secret message.';
let encrypted = aliceCipher.update(message, 'utf8', 'hex');
encrypted += aliceCipher.final('hex');
const authTag = aliceCipher.getAuthTag();
console.log(`Encrypted message: ${encrypted.substring(0, 40)}...`);
console.log('');

console.log('💀 Step 10: Attacker intercepts and decrypts Alice\'s message');
const attackerDecipher = crypto.createDecipheriv('aes-256-gcm', attackerAliceSecret.slice(0, 32), Buffer.alloc(12));
attackerDecipher.setAuthTag(authTag);
let decrypted = attackerDecipher.update(encrypted, 'hex', 'utf8');
decrypted += attackerDecipher.final('utf8');
console.log(`Decrypted message: "${decrypted}"`);
console.log('');

console.log('❌ ATTACK SUCCESSFUL!');
console.log('The attacker can read all messages between Alice and Bob.');
console.log('');
console.log('='.repeat(70));
console.log('WHY THIS WORKS:');
console.log('- No authentication of public keys');
console.log('- No way to verify the sender\'s identity');
console.log('- Alice and Bob cannot detect the attacker is in the middle');
console.log('='.repeat(70));
console.log('');
console.log('✅ OUR SOLUTION: Digital Signatures with ECDSA');
console.log('- Each public key is signed with the sender\'s long-term private key');
console.log('- Recipients verify the signature before computing shared secret');
console.log('- Attacker cannot forge signatures without the private key');
console.log('- If public key is modified, signature verification fails');
console.log('='.repeat(70));
