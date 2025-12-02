import { useState } from 'react';
import api from '../services/api';
import { hasStoredKeys, retrievePrivateKey } from '../crypto/keyManagement';
import './Login.css';

function Login({ onLogin, onSwitchToRegister }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [twoFactorToken, setTwoFactorToken] = useState('');
    const [requires2FA, setRequires2FA] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [status, setStatus] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setStatus('');

        if (!username || !password) {
            setError('Username and password are required');
            return;
        }

        if (requires2FA && (!twoFactorToken || twoFactorToken.length !== 6)) {
            setError('Please enter a valid 6-digit 2FA code');
            return;
        }

        setLoading(true);

        try {
            // Step 1: Authenticate with server
            setStatus('Authenticating...');
            const result = await api.login(username, password, twoFactorToken || null);

            // Check if 2FA is required
            if (result.requiresTwoFactor) {
                setRequires2FA(true);
                setStatus('2FA required. Please enter your 6-digit code.');
                setLoading(false);
                return;
            }

            // Check if user has stored keys
            const hasKeys = await hasStoredKeys(result.userId);

            if (!hasKeys) {
                throw new Error('No encryption keys found. Please register again.');
            }

            // Step 2: Retrieve private key from IndexedDB
            setStatus('Retrieving encryption keys...');
            try {
                await retrievePrivateKey(password, result.userId);
            } catch (keyError) {
                throw new Error('Failed to decrypt private key. Wrong password?');
            }

            // Step 3: Store auth data
            localStorage.setItem('token', result.token);
            localStorage.setItem('userId', result.userId);
            localStorage.setItem('username', result.username);
            localStorage.setItem('publicKey', result.publicKey);
            localStorage.setItem('twoFactorEnabled', result.twoFactorEnabled || false);

            setStatus('Login successful!');

            // Call login callback
            setTimeout(() => {
                if (onLogin) onLogin(result);
            }, 500);

        } catch (err) {
            console.error('Login failed:', err);
            setError(err.response?.data?.error || err.message || 'Login failed');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="login-container">
            <div className="login-card">
                <h2>🔓 Welcome Back</h2>
                <p className="subtitle">Sign in to your secure account</p>

                <form onSubmit={handleSubmit} className="login-form">
                    <div className="form-group">
                        <label htmlFor="username">Username</label>
                        <input
                            id="username"
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="Enter your username"
                            disabled={loading || requires2FA}
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
                            placeholder="Enter your password"
                            disabled={loading || requires2FA}
                            autoComplete="current-password"
                        />
                    </div>

                    {requires2FA && (
                        <div className="form-group">
                            <label htmlFor="twoFactorToken">2FA Code</label>
                            <input
                                id="twoFactorToken"
                                type="text"
                                value={twoFactorToken}
                                onChange={(e) => setTwoFactorToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                placeholder="000000"
                                maxLength={6}
                                disabled={loading}
                                autoComplete="one-time-code"
                                autoFocus
                                className="twofa-input"
                            />
                            <p className="hint">Enter the 6-digit code from your authenticator app</p>
                        </div>
                    )}

                    {error && <div className="error-message">⚠️ {error}</div>}
                    {status && <div className="status-message">✓ {status}</div>}

                    <button type="submit" disabled={loading} className="submit-btn">
                        {loading ? 'Signing in...' : 'Sign In'}
                    </button>

                    <div className="auth-switch">
                        Don't have an account?{' '}
                        <button type="button" onClick={onSwitchToRegister} className="switch-btn">
                            Register
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

export default Login;
