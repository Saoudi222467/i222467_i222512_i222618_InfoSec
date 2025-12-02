import { useState } from 'react';
import api from '../services/api';
import {
    generateUserKeyPair,
    exportPublicKey,
    storePrivateKey
} from '../crypto/keyManagement';
import './Register.css';

function Register({ onSuccess, onSwitchToLogin }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [status, setStatus] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setStatus('');

        // Validation
        if (!username || !password || !confirmPassword) {
            setError('All fields are required');
            return;
        }

        if (password.length < 8) {
            setError('Password must be at least 8 characters');
            return;
        }

        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        setLoading(true);

        try {
            // Step 1: Generate key pair
            setStatus('Generating cryptographic keys...');
            const keyPair = await generateUserKeyPair();

            // Step 2: Export public key
            setStatus('Exporting public key...');
            const publicKeyBase64 = await exportPublicKey(keyPair.publicKey);

            // Step 3: Register with server
            setStatus('Registering with server...');
            const result = await api.register(username, password, publicKeyBase64);

            // Step 4: Store private key in IndexedDB (encrypted with password)
            setStatus('Encrypting and storing private key securely...');
            await storePrivateKey(keyPair.privateKey, password, result.userId);

            setStatus('Registration successful! You can now log in.');

            // Clear form
            setUsername('');
            setPassword('');
            setConfirmPassword('');

            // Call success callback after 2 seconds
            setTimeout(() => {
                if (onSuccess) onSuccess();
            }, 2000);

        } catch (err) {
            console.error('Registration failed:', err);
            setError(err.response?.data?.error || err.message || 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="register-container">
            <div className="register-card">
                <h2>🔐 Create Account</h2>
                <p className="subtitle">Secure end-to-end encrypted messaging</p>

                <form onSubmit={handleSubmit} className="register-form">
                    <div className="form-group">
                        <label htmlFor="username">Username</label>
                        <input
                            id="username"
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="Choose a username"
                            disabled={loading}
                            autoComplete="username"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="password">Password</label>
                        <input
                            id="password"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="At least 8 characters"
                            disabled={loading}
                            autoComplete="new-password"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="confirmPassword">Confirm Password</label>
                        <input
                            id="confirmPassword"
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            placeholder="Re-enter password"
                            disabled={loading}
                            autoComplete="new-password"
                        />
                    </div>

                    {error && <div className="error-message">⚠️ {error}</div>}
                    {status && <div className="status-message">✓ {status}</div>}

                    <button type="submit" disabled={loading} className="submit-btn">
                        {loading ? 'Registering...' : 'Create Account'}
                    </button>

                    <div className="auth-switch">
                        Already have an account?{' '}
                        <button type="button" onClick={onSwitchToLogin} className="switch-btn">
                            Login
                        </button>
                    </div>
                </form>

                <div className="security-notice">
                    <p>🔒 Your private key will be encrypted and stored locally.</p>
                    <p>⚠️ Never shared with the server!</p>
                </div>
            </div>
        </div>
    );
}

export default Register;
