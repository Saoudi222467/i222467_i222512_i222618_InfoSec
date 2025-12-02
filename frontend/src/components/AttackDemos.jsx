import { useState } from 'react';
import './AttackDemos.css';

function AttackDemos() {
    const [mitmSteps, setMitmSteps] = useState([]);
    const [replaySteps, setReplaySteps] = useState([]);
    const [mitmRunning, setMitmRunning] = useState(false);
    const [replayRunning, setReplayRunning] = useState(false);

    const runMitmDemo = async () => {
        setMitmRunning(true);
        setMitmSteps([]);
        const steps = [];

        const addStep = (step) => {
            steps.push(step);
            setMitmSteps([...steps]);
        };

        await sleep(500);
        addStep({ type: 'info', text: '🚀 Starting MITM Attack Demonstration' });

        await sleep(1000);
        addStep({ type: 'section', text: '📌 Scenario WITHOUT Signatures (Vulnerable)' });

        await sleep(800);
        addStep({ type: 'step', text: '1️⃣ Alice generates ECDH public key: PubKey_A' });

        await sleep(800);
        addStep({ type: 'step', text: '2️⃣ Alice sends PubKey_A → Server → Bob' });

        await sleep(800);
        addStep({ type: 'danger', text: '💀 ATTACKER INTERCEPTS!' });

        await sleep(800);
        addStep({ type: 'step', text: '3️⃣ Attacker generates their own key: PubKey_Evil' });

        await sleep(800);
        addStep({ type: 'danger', text: '💀 Attacker substitutes: PubKey_Evil → Bob (Bob thinks it\'s from Alice)' });

        await sleep(800);
        addStep({ type: 'step', text: '4️⃣ Bob generates his key: PubKey_B and sends to Alice' });

        await sleep(800);
        addStep({ type: 'danger', text: '💀 Attacker intercepts and substitutes: PubKey_Evil → Alice (Alice thinks it\'s from Bob)' });

        await sleep(1000);
        addStep({ type: 'error', text: '❌ RESULT: Attacker can decrypt ALL messages!' });

        await sleep(1500);
        addStep({ type: 'section', text: '📌 Scenario WITH Signatures (Protected) ✅' });

        await sleep(800);
        addStep({ type: 'step', text: '1️⃣ Alice generates ECDH public key: PubKey_A' });

        await sleep(800);
        addStep({ type: 'step', text: '2️⃣ Alice signs PubKey_A with her private key: Signature_A = ECDSA(PubKey_A, Alice_PrivKey)' });

        await sleep(800);
        addStep({ type: 'step', text: '3️⃣ Alice sends {PubKey_A, Signature_A} to Bob' });

        await sleep(800);
        addStep({ type: 'danger', text: '💀 Attacker tries to substitute PubKey_Evil' });

        await sleep(800);
        addStep({ type: 'step', text: '4️⃣ Bob receives {PubKey_Evil, Signature_A}' });

        await sleep(800);
        addStep({ type: 'step', text: '5️⃣ Bob verifies: ECDSA_verify(PubKey_Evil, Signature_A, Alice_PubKey)' });

        await sleep(1000);
        addStep({ type: 'error', text: '❌ VERIFICATION FAILED! Signature doesn\'t match modified key!' });

        await sleep(1000);
        addStep({ type: 'success', text: '✅ ATTACK BLOCKED! Bob rejects the key exchange.' });

        await sleep(1000);
        addStep({ type: 'success', text: '🛡️ OUR DEFENSE: Digital signatures make tampering impossible!' });

        setMitmRunning(false);
    };

    const runReplayDemo = async () => {
        setReplayRunning(true);
        setReplaySteps([]);
        const steps = [];

        const addStep = (step) => {
            steps.push(step);
            setReplaySteps([...steps]);
        };

        await sleep(500);
        addStep({ type: 'info', text: '🚀 Starting Replay Attack Demonstration' });

        await sleep(1000);
        addStep({ type: 'section', text: '📌 Step 1: Legitimate Message Sent' });

        await sleep(800);
        addStep({ type: 'step', text: 'Alice sends encrypted message with:' });
        addStep({ type: 'code', text: 'Nonce: abc-123-def-456\nTimestamp: 2025-12-02 21:30:00\nSequence: 42' });

        await sleep(800);
        addStep({ type: 'success', text: '✅ Server accepts and stores nonce' });

        await sleep(1500);
        addStep({ type: 'section', text: '📌 Attack Attempt #1: Duplicate Nonce' });

        await sleep(800);
        addStep({ type: 'danger', text: '💀 Attacker captures message and tries to resend exact same message' });

        await sleep(800);
        addStep({ type: 'step', text: 'Server checks: Has nonce abc-123-def-456 been used?' });

        await sleep(800);
        addStep({ type: 'error', text: '❌ REJECTED! Duplicate nonce detected' });

        await sleep(800);
        addStep({ type: 'success', text: '🛡️ Layer 1 Defense: Nonce Tracking BLOCKED the attack!' });

        await sleep(1500);
        addStep({ type: 'section', text: '📌 Attack Attempt #2: New Nonce, Old Timestamp' });

        await sleep(800);
        addStep({ type: 'danger', text: '💀 Attacker generates new nonce but uses old timestamp (10 min ago)' });

        await sleep(800);
        addStep({ type: 'step', text: 'Server checks: Is timestamp recent (< 5 min)?' });

        await sleep(800);
        addStep({ type: 'error', text: '❌ REJECTED! Message too old (10 minutes)' });

        await sleep(800);
        addStep({ type: 'success', text: '🛡️ Layer 2 Defense: Timestamp Validation BLOCKED the attack!' });

        await sleep(1500);
        addStep({ type: 'section', text: '📌 Attack Attempt #3: Valid Nonce & Timestamp, Old Sequence' });

        await sleep(800);
        addStep({ type: 'danger', text: '💀 Attacker uses new nonce, current timestamp, but old sequence (40)' });

        await sleep(800);
        addStep({ type: 'step', text: 'Server checks: Expected sequence 43, received 40' });

        await sleep(800);
        addStep({ type: 'error', text: '❌ REJECTED! Out-of-order sequence number' });

        await sleep(800);
        addStep({ type: 'success', text: '🛡️ Layer 3 Defense: Sequence Validation BLOCKED the attack!' });

        await sleep(1500);
        addStep({ type: 'success', text: '✅ THREE-LAYER DEFENSE SUCCESS!' });
        addStep({ type: 'info', text: 'Even if attacker bypasses 2 layers, the 3rd layer still blocks!' });

        setReplayRunning(false);
    };

    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    return (
        <div className="attack-demos">
            <h2>🔐 Attack Demonstrations</h2>
            <p className="intro">
                Interactive demonstrations showing how our security measures protect against common attacks.
            </p>

            {/* MITM Attack Demo */}
            <div className="demo-section">
                <div className="demo-header">
                    <h3>💀 Man-in-the-Middle (MITM) Attack</h3>
                    <button
                        onClick={runMitmDemo}
                        disabled={mitmRunning}
                        className="demo-btn"
                    >
                        {mitmRunning ? '⏳ Running...' : '▶️ Run MITM Demo'}
                    </button>
                </div>

                <div className="demo-description">
                    <p><strong>Attack Scenario:</strong> An attacker tries to intercept the key exchange and substitute their own public keys to decrypt all communications.</p>
                    <p><strong>Our Defense:</strong> ECDSA digital signatures ensure that any modification to public keys is immediately detected.</p>
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
                        disabled={replayRunning}
                        className="demo-btn"
                    >
                        {replayRunning ? '⏳ Running...' : '▶️ Run Replay Demo'}
                    </button>
                </div>

                <div className="demo-description">
                    <p><strong>Attack Scenario:</strong> An attacker captures a valid encrypted message and tries to resend it later.</p>
                    <p><strong>Our Defense:</strong> Three-layer protection (Nonce + Timestamp + Sequence) ensures replay attempts are blocked.</p>
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
