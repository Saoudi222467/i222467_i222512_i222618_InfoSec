import { useState } from 'react';
import api from '../services/api';
import './TwoFactorSetup.css';

function TwoFactorSetup({ onClose, onSetupComplete }) {
    const [step, setStep] = useState(1); // 1: setup, 2: verify
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [verifyToken, setVerifyToken] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    const handleSetup = async () => {
        setLoading(true);
        setError('');

        try {
            const response = await api.setup2FA();
            setQrCode(response.qrCode);
            setSecret(response.secret);
            setStep(2);
            setSuccess('QR code generated! Scan with Google Authenticator');
        } catch (err) {
            setError(err.response?.data?.error || 'Failed to setup 2FA');
        } finally {
            setLoading(false);
        }
    };

    const handleVerify = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        if (!verifyToken || verifyToken.length !== 6) {
            setError('Please enter a valid 6-digit token');
            setLoading(false);
            return;
        }

        try {
            await api.verify2FA(verifyToken);
            setSuccess('2FA enabled successfully!');

            setTimeout(() => {
                if (onSetupComplete) onSetupComplete();
                if (onClose) onClose();
            }, 2000);
        } catch (err) {
            setError(err.response?.data?.error || 'Invalid token');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="modal-overlay">
            <div className="modal-content twofa-modal">
                <div className="modal-header">
                    <h2>🔐 Two-Factor Authentication</h2>
                    <button onClick={onClose} className="close-btn">✕</button>
                </div>

                {step === 1 && (
                    <div className="twofa-step">
                        <p className="info-text">
                            Add an extra layer of security to your account. You'll need a 6-digit code from your authenticator app each time you log in.
                        </p>

                        <div className="instructions">
                            <h3>How to set up:</h3>
                            <ol>
                                <li>Download Google Authenticator or similar app</li>
                                <li>Click "Generate QR Code" below</li>
                                <li>Scan the QR code with your app</li>
                                <li>Enter the 6-digit code to verify</li>
                            </ol>
                        </div>

                        {error && <div className="error-message">{error}</div>}

                        <button
                            onClick={handleSetup}
                            disabled={loading}
                            className="primary-btn"
                        >
                            {loading ? 'Generating...' : 'Generate QR Code'}
                        </button>
                    </div>
                )}

                {step === 2 && (
                    <div className="twofa-step">
                        <div className="qr-container">
                            <img src={qrCode} alt="QR Code" className="qr-code" />
                        </div>

                        <div className="secret-container">
                            <p className="label">Manual Entry Key:</p>
                            <code className="secret">{secret}</code>
                            <p className="hint">Use this if you can't scan the QR code</p>
                        </div>

                        <form onSubmit={handleVerify} className="verify-form">
                            <label htmlFor="token">Enter 6-digit code from your app:</label>
                            <input
                                id="token"
                                type="text"
                                value={verifyToken}
                                onChange={(e) => setVerifyToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                placeholder="000000"
                                maxLength={6}
                                className="token-input"
                                disabled={loading}
                                autoFocus
                            />

                            {error && <div className="error-message">{error}</div>}
                            {success && <div className="success-message">{success}</div>}

                            <button
                                type="submit"
                                disabled={loading || verifyToken.length !== 6}
                                className="primary-btn"
                            >
                                {loading ? 'Verifying...' : 'Verify & Enable 2FA'}
                            </button>
                        </form>
                    </div>
                )}
            </div>
        </div>
    );
}

export default TwoFactorSetup;
