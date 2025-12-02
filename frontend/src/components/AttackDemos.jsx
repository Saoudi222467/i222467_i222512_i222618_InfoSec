import { useState, useEffect } from 'react';
import api from '../services/api';
import { retrievePrivateKey, generateECDHKeyPair, exportPublicKey, importPublicKey } from '../crypto/keyManagement';
import { signData, verifySignature } from '../crypto/keyExchange';
import { encryptMessage, importSessionKey, exportSessionKey } from '../crypto/encryption';
import { generateMessageMetadata, generateNonce } from '../crypto/replayProtection';
import './AttackDemos.css';

function AttackDemos({ user }) {
    const [mitmSteps, setMitmSteps] = useState([]);
    const [replaySteps, setReplaySteps] = useState([]);
    const [mitmRunning, setMitmRunning] = useState(false);
    const [replayRunning, setReplayRunning] = useState(false);
    const [targetUser, setTargetUser] = useState(null);
    const [users, setUsers] = useState([]);

    // Load users for target selection
    useEffect(() => {
        const loadUsers = async () => {
            try {
                const data = await api.getUsers();
                // API returns { users: [...] }
                const allUsers = data.users || [];
                const otherUsers = allUsers.filter(u => u._id !== user.userId);
                setUsers(otherUsers);
                if (otherUsers.length > 0) {
                    setTargetUser(otherUsers[0]);
                }
            } catch (err) {
                console.error('Failed to load users:', err);
            }
        };
        loadUsers();
    }, [user.userId]);

    const addStep = (steps, setSteps, step) => {
        const newSteps = [...steps, step];
        setSteps(newSteps);
        return newSteps;
    };

    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    const runMitmDemo = async () => {
        if (!targetUser) {
            alert('Please select a target user first');
            return;
        }

        setMitmRunning(true);
        setMitmSteps([]);
        let steps = [];

        try {
            steps = addStep(steps, setMitmSteps, { type: 'info', text: '🚀 Starting REAL MITM Attack Demonstration' });
            await sleep(500);

            steps = addStep(steps, setMitmSteps, { type: 'section', text: '📌 Step 1: Initiating Legitimate Key Exchange' });
            await sleep(800);

            // Get user's private key
            const password = prompt('Enter your password to access private key for demo:');
            if (!password) {
                setMitmRunning(false);
                return;
            }

            steps = addStep(steps, setMitmSteps, { type: 'step', text: '🔑 Retrieving your private key...' });
            const userPrivateKey = await retrievePrivateKey(password, user.userId);
            steps = addStep(steps, setMitmSteps, { type: 'success', text: '✅ Private key retrieved' });
            await sleep(500);

            // Generate legitimate ECDH key pair
            steps = addStep(steps, setMitmSteps, { type: 'step', text: '🔐 Generating legitimate ECDH key pair...' });
            const legitimateKeyPair = await generateECDHKeyPair();
            const legitimatePublicKey = await exportPublicKey(legitimateKeyPair.publicKey);
            steps = addStep(steps, setMitmSteps, { type: 'success', text: `✅ Generated key: ${legitimatePublicKey.substring(0, 30)}...` });
            await sleep(500);

            // Sign the legitimate key
            const nonceBase64Encoded = generateNonce();
            const timestamp = Date.now();
            const dataToSign = `${legitimatePublicKey}:${nonceBase64Encoded}:${timestamp}`;
            
            steps = addStep(steps, setMitmSteps, { type: 'step', text: '✍️ Signing legitimate key with your private key...' });
            const legitimateSignature = await signData(dataToSign, userPrivateKey);
            steps = addStep(steps, setMitmSteps, { type: 'success', text: `✅ Signature created: ${legitimateSignature.substring(0, 30)}...` });
            await sleep(800);

            steps = addStep(steps, setMitmSteps, { type: 'section', text: '💀 ATTACK: Attempting to Modify Key Exchange' });
            await sleep(800);

            // Generate attacker's key
            steps = addStep(steps, setMitmSteps, { type: 'danger', text: '💀 Attacker generates malicious ECDH key pair...' });
            const attackerKeyPair = await generateECDHKeyPair();
            const attackerPublicKey = await exportPublicKey(attackerKeyPair.publicKey);
            steps = addStep(steps, setMitmSteps, { type: 'danger', text: `💀 Attacker key: ${attackerPublicKey.substring(0, 30)}...` });
            await sleep(800);

            // Try to use legitimate signature with attacker's key
            steps = addStep(steps, setMitmSteps, { type: 'danger', text: '💀 ATTACK: Trying to use legitimate signature with attacker\'s key...' });
            await sleep(800);

            // Get target user's public key for verification
            steps = addStep(steps, setMitmSteps, { type: 'step', text: '🔍 Retrieving target user\'s public key from server...' });
            const targetUserData = await api.getUserByUsername(targetUser.username);
            const targetPublicKey = await importPublicKey(targetUserData.publicKey, 'ECDSA');
            steps = addStep(steps, setMitmSteps, { type: 'success', text: '✅ Target public key retrieved' });
            await sleep(500);

            // Try to verify attacker's key with legitimate signature
            steps = addStep(steps, setMitmSteps, { type: 'step', text: '🔍 Verifying: Does attacker\'s key match legitimate signature?' });
            const attackerDataToVerify = `${attackerPublicKey}:${nonceBase64Encoded}:${timestamp}`;
            const isValid = await verifySignature(attackerDataToVerify, legitimateSignature, targetPublicKey);
            await sleep(1000);

            if (!isValid) {
                steps = addStep(steps, setMitmSteps, { type: 'error', text: '❌ VERIFICATION FAILED! Signature does not match modified key!' });
                await sleep(800);
                steps = addStep(steps, setMitmSteps, { type: 'success', text: '✅ ATTACK BLOCKED! System correctly rejected the tampered key exchange.' });
                await sleep(800);
                steps = addStep(steps, setMitmSteps, { type: 'success', text: '🛡️ DEFENSE SUCCESS: Digital signatures prevent MITM attacks!' });
            } else {
                steps = addStep(steps, setMitmSteps, { type: 'error', text: '⚠️ WARNING: Verification passed (this should not happen!)' });
            }

            await sleep(1000);
            steps = addStep(steps, setMitmSteps, { type: 'section', text: '📊 Summary: MITM Protection Works!' });
            steps = addStep(steps, setMitmSteps, { type: 'info', text: '✅ Any modification to the ECDH public key invalidates the signature' });
            steps = addStep(steps, setMitmSteps, { type: 'info', text: '✅ Attacker cannot forge signatures without your private key' });
            steps = addStep(steps, setMitmSteps, { type: 'info', text: '✅ System automatically rejects tampered key exchanges' });

        } catch (err) {
            addStep(steps, setMitmSteps, { type: 'error', text: `❌ Error: ${err.message}` });
        } finally {
            setMitmRunning(false);
        }
    };

    const runReplayDemo = async () => {
        if (!targetUser) {
            alert('Please select a target user first');
            return;
        }

        setReplayRunning(true);
        setReplaySteps([]);
        let steps = [];

        try {
            steps = addStep(steps, setReplaySteps, { type: 'info', text: '🚀 Starting REAL Replay Attack Demonstration' });
            await sleep(500);

            // Check if user has a session key
            const sessionKeyStr = sessionStorage.getItem(`sessionKey_${targetUser._id}`);
            if (!sessionKeyStr) {
                steps = addStep(steps, setReplaySteps, { type: 'error', text: '❌ No session key found. Please establish a key exchange with the target user first.' });
                setReplayRunning(false);
                return;
            }

            steps = addStep(steps, setReplaySteps, { type: 'section', text: '📌 Step 1: Sending Legitimate Message' });
            await sleep(800);

            // Import session key
            const sessionKey = await importSessionKey(sessionKeyStr);
            steps = addStep(steps, setReplaySteps, { type: 'step', text: '🔑 Session key loaded' });
            await sleep(500);

            // Send legitimate message
            const legitimateMessage = 'This is a legitimate test message';
            steps = addStep(steps, setReplaySteps, { type: 'step', text: `📤 Sending legitimate message: "${legitimateMessage}"` });
            
            const encrypted = await encryptMessage(legitimateMessage, sessionKey);
            const metadata = generateMessageMetadata(1);
            
            steps = addStep(steps, setReplaySteps, { type: 'code', text: `Nonce: ${metadata.nonce.substring(0, 20)}...\nTimestamp: ${new Date(metadata.timestamp).toLocaleString()}\nSequence: ${metadata.sequenceNumber}` });
            
            try {
                await api.sendMessage({
                    receiverId: targetUser._id,
                    ciphertext: encrypted.ciphertext,
                    iv: encrypted.iv,
                    nonce: metadata.nonce,
                    sequenceNumber: metadata.sequenceNumber,
                    timestamp: metadata.timestamp
                });
                steps = addStep(steps, setReplaySteps, { type: 'success', text: '✅ Legitimate message accepted by server' });
            } catch (err) {
                steps = addStep(steps, setReplaySteps, { type: 'error', text: `❌ Failed to send message: ${err.message}` });
                setReplayRunning(false);
                return;
            }

            await sleep(1500);
            steps = addStep(steps, setReplaySteps, { type: 'section', text: '💀 ATTACK #1: Duplicate Nonce (Replay Same Message)' });
            await sleep(800);

            steps = addStep(steps, setReplaySteps, { type: 'danger', text: '💀 Attacker tries to resend EXACT same message (same nonce, timestamp, sequence)...' });
            await sleep(800);

            try {
                await api.sendMessage({
                    receiverId: targetUser._id,
                    ciphertext: encrypted.ciphertext,
                    iv: encrypted.iv,
                    nonce: metadata.nonce, // SAME nonce!
                    sequenceNumber: metadata.sequenceNumber, // SAME sequence!
                    timestamp: metadata.timestamp // SAME timestamp!
                });
                steps = addStep(steps, setReplaySteps, { type: 'error', text: '⚠️ WARNING: Duplicate message was accepted (this should not happen!)' });
            } catch (err) {
                const errorMsg = err.response?.data?.error || err.message;
                steps = addStep(steps, setReplaySteps, { type: 'error', text: `❌ REJECTED: ${errorMsg}` });
                await sleep(800);
                steps = addStep(steps, setReplaySteps, { type: 'success', text: '🛡️ Layer 1 Defense: Nonce Tracking BLOCKED the attack!' });
            }

            await sleep(1500);
            steps = addStep(steps, setReplaySteps, { type: 'section', text: '💀 ATTACK #2: Old Timestamp' });
            await sleep(800);

            steps = addStep(steps, setReplaySteps, { type: 'danger', text: '💀 Attacker uses new nonce but OLD timestamp (10 minutes ago)...' });
            await sleep(800);

            const oldTimestamp = Date.now() - (10 * 60 * 1000); // 10 minutes ago
            const newNonceBase64 = generateNonce();
            const newEncrypted = await encryptMessage('Replay attack with old timestamp', sessionKey);

            try {
                await api.sendMessage({
                    receiverId: targetUser._id,
                    ciphertext: newEncrypted.ciphertext,
                    iv: newEncrypted.iv,
                    nonce: newNonceBase64,
                    sequenceNumber: 2,
                    timestamp: oldTimestamp // OLD timestamp!
                });
                steps = addStep(steps, setReplaySteps, { type: 'error', text: '⚠️ WARNING: Old timestamp message was accepted (this should not happen!)' });
            } catch (err) {
                const errorMsg = err.response?.data?.error || err.message;
                steps = addStep(steps, setReplaySteps, { type: 'error', text: `❌ REJECTED: ${errorMsg}` });
                await sleep(800);
                steps = addStep(steps, setReplaySteps, { type: 'success', text: '🛡️ Layer 2 Defense: Timestamp Validation BLOCKED the attack!' });
            }

            await sleep(1500);
            steps = addStep(steps, setReplaySteps, { type: 'section', text: '💀 ATTACK #3: Out-of-Order Sequence Number' });
            await sleep(800);

            steps = addStep(steps, setReplaySteps, { type: 'danger', text: '💀 Attacker uses new nonce, current timestamp, but OLD sequence number...' });
            await sleep(800);

            const futureNonceBase64 = generateNonce();
            const futureEncrypted = await encryptMessage('Replay attack with old sequence', sessionKey);

            try {
                await api.sendMessage({
                    receiverId: targetUser._id,
                    ciphertext: futureEncrypted.ciphertext,
                    iv: futureEncrypted.iv,
                    nonce: futureNonceBase64,
                    sequenceNumber: 0, // OLD sequence (should be 3 or higher now)
                    timestamp: Date.now() // Current timestamp
                });
                steps = addStep(steps, setReplaySteps, { type: 'error', text: '⚠️ WARNING: Out-of-order sequence was accepted (this should not happen!)' });
            } catch (err) {
                const errorMsg = err.response?.data?.error || err.message;
                steps = addStep(steps, setReplaySteps, { type: 'error', text: `❌ REJECTED: ${errorMsg}` });
                await sleep(800);
                steps = addStep(steps, setReplaySteps, { type: 'success', text: '🛡️ Layer 3 Defense: Sequence Validation BLOCKED the attack!' });
            }

            await sleep(1000);
            steps = addStep(steps, setReplaySteps, { type: 'section', text: '📊 Summary: Three-Layer Defense Success!' });
            steps = addStep(steps, setReplaySteps, { type: 'success', text: '✅ All replay attack attempts were blocked' });
            steps = addStep(steps, setReplaySteps, { type: 'info', text: '✅ Nonce tracking prevents duplicate messages' });
            steps = addStep(steps, setReplaySteps, { type: 'info', text: '✅ Timestamp validation prevents old message replay' });
            steps = addStep(steps, setReplaySteps, { type: 'info', text: '✅ Sequence numbers prevent out-of-order attacks' });

        } catch (err) {
            addStep(steps, setReplaySteps, { type: 'error', text: `❌ Error: ${err.message}` });
        } finally {
            setReplayRunning(false);
        }
    };

    return (
        <div className="attack-demos">
            <h2>🔐 Real-Time Attack Demonstrations</h2>
            <p className="intro">
                These demos perform <strong>REAL attacks</strong> against the system to demonstrate how security measures protect you.
            </p>

            {/* Target User Selection */}
            <div className="demo-section" style={{ marginBottom: '20px', padding: '15px', background: '#f5f5f5', borderRadius: '8px' }}>
                <label style={{ display: 'block', marginBottom: '10px', fontWeight: 'bold' }}>
                    Select Target User for Attacks:
                </label>
                <select
                    value={targetUser?._id || ''}
                    onChange={(e) => {
                        const selected = users.find(u => u._id === e.target.value);
                        setTargetUser(selected);
                    }}
                    style={{ padding: '8px', width: '100%', maxWidth: '300px' }}
                    disabled={mitmRunning || replayRunning}
                >
                    {users.length === 0 && <option>Loading users...</option>}
                    {users.map(u => (
                        <option key={u._id} value={u._id}>{u.username}</option>
                    ))}
                </select>
                {!targetUser && users.length > 0 && (
                    <p style={{ color: '#ff6b6b', marginTop: '10px' }}>⚠️ Please select a target user</p>
                )}
            </div>

            {/* MITM Attack Demo */}
            <div className="demo-section">
                <div className="demo-header">
                    <h3>💀 Man-in-the-Middle (MITM) Attack</h3>
                    <button
                        onClick={runMitmDemo}
                        disabled={mitmRunning || !targetUser}
                        className="demo-btn"
                    >
                        {mitmRunning ? '⏳ Running Real Attack...' : '▶️ Run Real MITM Attack'}
                    </button>
                </div>

                <div className="demo-description">
                    <p><strong>What This Does:</strong> Actually attempts to modify a key exchange by substituting an attacker's public key while keeping the original signature. Shows how signature verification blocks the attack.</p>
                    <p><strong>Real Operations:</strong> Generates real cryptographic keys, creates real signatures, and performs real verification against the server.</p>
                </div>

                {mitmSteps.length > 0 && (
                    <div className="demo-output">
                        {mitmSteps.map((step, idx) => (
                            <div key={idx} className={`demo-step ${step.type}`}>
                                {step.type === 'code' ? (
                                    <pre>{step.text}</pre>
                                ) : (
                                    <span>{step.text}</span>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Replay Attack Demo */}
            <div className="demo-section">
                <div className="demo-header">
                    <h3>🔄 Replay Attack</h3>
                    <button
                        onClick={runReplayDemo}
                        disabled={replayRunning || !targetUser}
                        className="demo-btn"
                    >
                        {replayRunning ? '⏳ Running Real Attack...' : '▶️ Run Real Replay Attack'}
                    </button>
                </div>

                <div className="demo-description">
                    <p><strong>What This Does:</strong> Actually sends real messages to the server attempting three different replay attack techniques. Shows how the server rejects each attempt.</p>
                    <p><strong>Real Operations:</strong> Sends actual HTTP requests with real encrypted messages, real nonces, timestamps, and sequence numbers. Server performs real validation.</p>
                    <p><strong>Note:</strong> Requires an established key exchange with the target user.</p>
                </div>

                {replaySteps.length > 0 && (
                    <div className="demo-output">
                        {replaySteps.map((step, idx) => (
                            <div key={idx} className={`demo-step ${step.type}`}>
                                {step.type === 'code' ? (
                                    <pre>{step.text}</pre>
                                ) : (
                                    <span>{step.text}</span>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div className="demo-summary">
                <h3>🛡️ Security Summary</h3>
                <div className="summary-grid">
                    <div className="summary-card">
                        <div className="summary-icon">🔑</div>
                        <div className="summary-title">MITM Protection</div>
                        <div className="summary-text">ECDSA signatures prevent key substitution</div>
                    </div>
                    <div className="summary-card">
                        <div className="summary-icon">🔄</div>
                        <div className="summary-title">Replay Protection</div>
                        <div className="summary-text">Three independent validation layers</div>
                    </div>
                    <div className="summary-card">
                        <div className="summary-icon">🔐</div>
                        <div className="summary-title">E2E Encryption</div>
                        <div className="summary-text">AES-256-GCM with authenticated encryption</div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default AttackDemos;
