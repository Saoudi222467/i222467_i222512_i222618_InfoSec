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

    // 2FA Setup States
    const [showTwoFactorSetup, setShowTwoFactorSetup] = useState(false);
    const [twoFactorData, setTwoFactorData] = useState(null);
    const [twoFactorToken, setTwoFactorToken] = useState('');
    const [registeredUserId, setRegisteredUserId] = useState(null);

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

            setStatus('Registration successful!');

            // Store userId and token for 2FA setup
            setRegisteredUserId(result.userId);
            localStorage.setItem('token', await generateTempToken(result.userId));

            // Show 2FA setup screen instead of redirecting
            setTimeout(() => {
                setShowTwoFactorSetup(true);
                setStatus('');
            }, 1000);

        } catch (err) {
            console.error('Registration failed:', err);
            setError(err.response?.data?.error || err.message || 'Registration failed');
        } finally {
            setLoading(false);
        }
    };

    const generateTempToken = async (userId) => {
        // For 2FA setup, we need to be authenticated
        // The registration already returns the userId, we'll use password for now
        // In production, you'd want to auto-login after registration
        try {
            const loginResult = await api.login(username, password);
            return loginResult.token;
        } catch (err) {
            console.error('Auto-login failed:', err);
            return null;
        }
    };

    const handleEnable2FA = async () => {
        setLoading(true);
        setError('');
        setStatus('');

        try {
            setStatus('Generating 2FA secret...');
            const result = await api.setup2FA();
            setTwoFactorData({
                qrCode: result.qrCode,
                secret: result.secret
            });
            setStatus('Scan the QR code with your authenticator app');
        } catch (err) {
            console.error('2FA setup failed:', err);
            setError(err.response?.data?.error || err.message || 'Failed to setup 2FA');
        } finally {
            setLoading(false);
        }
    };

    const handleVerify2FA = async () => {
        if (!twoFactorToken || twoFactorToken.length !== 6) {
            setError('Please enter a valid 6-digit code');
            return;
        }

        setLoading(true);
        setError('');
        setStatus('');

        try {
            setStatus('Verifying code...');
            await api.verify2FA(twoFactorToken);
            setStatus('2FA enabled successfully! Redirecting to login...');

            // Clear token from storage
            localStorage.removeItem('token');

            // Redirect to login after success
            setTimeout(() => {
                if (onSuccess) onSuccess();
            }, 2000);
        } catch (err) {
            console.error('2FA verification failed:', err);
            setError(err.response?.data?.error || err.message || 'Invalid code. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const handleSkip2FA = () => {
        // Clear token and redirect to login
        localStorage.removeItem('token');
        if (onSuccess) onSuccess();
    };

    // Show 2FA setup screen after registration
    if (showTwoFactorSetup) {
        return (
            <div className="register-container">
                <div className="register-card twofa-setup-card">
                    <h2>🔐 Two-Factor Authentication</h2>
                    <p className="subtitle">Add an extra layer of security to your account</p>

                    {!twoFactorData ? (
                        <div className="twofa-prompt">
                            <p className="twofa-description">
                                Two-factor authentication (2FA) provides additional security by requiring
                                a code from your phone in addition to your password when logging in.
                            </p>

                            <div className="twofa-options">
                                <button
                                    onClick={handleEnable2FA}
                                    disabled={loading}
                                    className="submit-btn enable-2fa-btn"
                                >
                                    {loading ? 'Setting up...' : '✓ Yes, Enable 2FA'}
                                </button>

                                <button
                                    onClick={handleSkip2FA}
                                    disabled={loading}
                                    className="skip-btn"
                                >
                                    Skip for Now
                                </button>
                            </div>
                        </div>
                    ) : (
                        <div className="twofa-verification">
                            <p className="twofa-step">Step 1: Scan QR Code</p>
                            <p className="twofa-instruction">
                                Open your authenticator app (Google Authenticator, Authy, or Microsoft Authenticator)
                                and scan this QR code:
                            </p>

                            <div className="qr-code-container">
                                <img src={twoFactorData.qrCode} alt="2FA QR Code" className="qr-code" />
                            </div>

                            <p className="twofa-step">Step 2: Enter Verification Code</p>
                            <p className="twofa-instruction">
                                Enter the 6-digit code from your authenticator app:
                            </p>

                            <div className="form-group">
                                <input
                                    type="text"
                                    value={twoFactorToken}
                                    onChange={(e) => setTwoFactorToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                    placeholder="000000"
                                    maxLength={6}
                                    disabled={loading}
                                    className="twofa-input"
                                    autoFocus
                                />
                            </div>

                            <button
                                onClick={handleVerify2FA}
                                disabled={loading || twoFactorToken.length !== 6}
                                className="submit-btn"
                            >
                                {loading ? 'Verifying...' : 'Verify and Enable'}
                            </button>

                            <button
                                onClick={handleSkip2FA}
                                disabled={loading}
                                className="skip-btn"
                            >
                                Cancel
                            </button>
                        </div>
                    )}

                    {error && <div className="error-message">⚠️ {error}</div>}
                    {status && <div className="status-message">✓ {status}</div>}
                </div>
            </div>
        );
    }

    // Show registration form
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
