import { useState, useEffect, useRef } from 'react';
import api from '../services/api';
import { retrievePrivateKey, importPublicKey } from '../crypto/keyManagement';
import {
    initiateKeyExchange,
    respondToKeyExchange,
    completeKeyExchange,
    signData,
    verifySignature
} from '../crypto/keyExchange';
import {
    encryptMessage,
    decryptMessage,
    encryptFile,
    decryptFile,
    exportSessionKey,
    importSessionKey
} from '../crypto/encryption';
import {
    generateMessageMetadata,
    validateMessageMetadata
} from '../crypto/replayProtection';
import './ChatApp.css';

function ChatApp({ user, onLogout }) {
    const [users, setUsers] = useState([]);
    const [selectedUser, setSelectedUser] = useState(null);
    const [messages, setMessages] = useState([]);
    const [newMessage, setNewMessage] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [status, setStatus] = useState('');
    const [sessionKey, setSessionKey] = useState(null);
    const [sequenceNumber, setSequenceNumber] = useState(0);
    const [view, setView] = useState('chat'); // 'chat', 'logs'
    const messagesEndRef = useRef(null);

    // Load users on mount
    useEffect(() => {
        loadUsers();
    }, []);

    // Load messages when user is selected
    useEffect(() => {
        if (selectedUser) {
            loadMessages();
            // Check if we have a session key for this user
            const storedKey = sessionStorage.getItem(`sessionKey_${selectedUser._id}`);
            if (storedKey) {
                importSessionKey(storedKey).then(setSessionKey);
            }
        }
    }, [selectedUser]);

    // Scroll to bottom on new messages
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    const loadUsers = async () => {
        try {
            const data = await api.getUsers();
            // Filter out current user
            setUsers(data.users.filter(u => u._id !== user.userId));
        } catch (err) {
            console.error('Failed to load users:', err);
        }
    };

    const loadMessages = async () => {
        if (!selectedUser) return;

        try {
            const data = await api.getConversation(selectedUser._id);
            setMessages(data.messages || []);
        } catch (err) {
            console.error('Failed to load messages:', err);
            setError('Failed to load messages');
        }
    };

    const handleInitiateKeyExchange = async () => {
        setLoading(true);
        setError('');
        setStatus('Initiating key exchange...');

        try {
            const password = prompt('Enter your password to access private key:');
            if (!password) {
                setLoading(false);
                setStatus('');
                return;
            }

            // Retrieve our private key
            const privateKey = await retrievePrivateKey(password, user.userId);

            // Initiate key exchange
            const { ecdhKeyPair, message: keyExchangeMsg } = await initiateKeyExchange(privateKey);

            // Send to server
            const response = await api.initiateKeyExchange({
                responderUsername: selectedUser.username,
                ecdhPublicKey: keyExchangeMsg.ecdhPublicKey,
                signature: keyExchangeMsg.signature,
                nonce: keyExchangeMsg.nonce,
                timestamp: keyExchangeMsg.timestamp
            });

            setStatus('Waiting for response... Share the key exchange ID with the other user.');

            // Store ephemeral key pair temporarily
            sessionStorage.setItem(`ecdhKeyPair_${response.keyExchangeId}`, JSON.stringify({
                keyExchangeId: response.keyExchangeId,
                nonce: keyExchangeMsg.nonce
            }));

            // Store ECDH private key (we'll need this later)
            // In a production app, you'd want better storage
            window.ecdhPrivateKey = ecdhKeyPair.privateKey;

            alert(`Key exchange initiated! ID: ${response.keyExchangeId}\nWaiting for ${selectedUser.username} to respond...`);

        } catch (err) {
            console.error('Key exchange initiation failed:', err);
            setError(err.message || 'Key exchange failed');
        } finally {
            setLoading(false);
            setStatus('');
        }
    };

    const handleSendMessage = async (e) => {
        e.preventDefault();
        if (!newMessage.trim() || !sessionKey) return;

        setLoading(true);
        setError('');

        try {
            // Encrypt message
            const encrypted = await encryptMessage(newMessage, sessionKey);

            // Generate replay protection metadata
            const metadata = generateMessageMetadata(sequenceNumber);

            // Send to server
            await api.sendMessage({
                receiverId: selectedUser._id,
                ciphertext: encrypted.ciphertext,
                iv: encrypted.iv,
                nonce: metadata.nonce,
                sequenceNumber: metadata.sequenceNumber,
                timestamp: metadata.timestamp
            });

            setSequenceNumber(prev => prev + 1);
            setNewMessage('');

            // Reload messages
            await loadMessages();

        } catch (err) {
            console.error('Failed to send message:', err);
            setError(err.response?.data?.error || 'Failed to send message');
        } finally {
            setLoading(false);
        }
    };

    const decryptAndDisplayMessage = async (msg) => {
        if (!sessionKey) return '🔒 [Encrypted - No session key]';

        try {
            // Validate replay protection
            const validation = await validateMessageMetadata(
                {
                    nonce: msg.nonce,
                    timestamp: msg.timestamp,
                    sequenceNumber: msg.sequenceNumber
                },
                selectedUser._id
            );

            if (!validation.valid) {
                return `⚠️ [Replay attack detected: ${validation.reason}]`;
            }

            // Decrypt
            const plaintext = await decryptMessage(
                msg.ciphertext,
                msg.iv,
                sessionKey
            );

            return plaintext;
        } catch (err) {
            console.error('Decryption failed:', err);
            return '❌ [Decryption failed]';
        }
    };

    const handleManualSessionKey = async () => {
        const keyBase64 = prompt('Enter session key (base64):');
        if (!keyBase64) return;

        try {
            const key = await importSessionKey(keyBase64);
            setSessionKey(key);
            sessionStorage.setItem(`sessionKey_${selectedUser._id}`, keyBase64);
            setStatus('Session key imported!');
            setTimeout(() => setStatus(''), 3000);
        } catch (err) {
            setError('Failed to import session key');
        }
    };

    const handleExportSessionKey = async () => {
        if (!sessionKey) {
            setError('No session key to export');
            return;
        }

        try {
            const keyBase64 = await exportSessionKey(sessionKey);
            alert(`Session Key (share securely):\n\n${keyBase64}`);
        } catch (err) {
            setError('Failed to export session key');
        }
    };

    return (
        <div className="chat-app">
            {/* Header */}
            <div className="chat-header">
                <div className="header-left">
                    <h1>🔐 Secure Chat</h1>
                    <span className="username-badge">{user.username}</span>
                </div>
                <div className="header-right">
                    <button onClick={() => setView('chat')} className={view === 'chat' ? 'active' : ''}>
                        💬 Chat
                    </button>
                    <button onClick={() => setView('logs')} className={view === 'logs' ? 'active' : ''}>
                        📊 Logs
                    </button>
                    <button onClick={onLogout} className="logout-btn">
                        Logout
                    </button>
                </div>
            </div>

            {view === 'chat' && (
                <div className="chat-container">
                    {/* Sidebar - Users List */}
                    <div className="users-sidebar">
                        <h3>Contacts</h3>
                        <div className="users-list">
                            {users.map(u => (
                                <div
                                    key={u._id}
                                    className={`user-item ${selectedUser?._id === u._id ? 'active' : ''}`}
                                    onClick={() => setSelectedUser(u)}
                                >
                                    <div className="user-avatar">{u.username[0].toUpperCase()}</div>
                                    <div className="user-info">
                                        <div className="user-name">{u.username}</div>
                                        <div className="user-status">
                                            {sessionKey && selectedUser?._id === u._id ? '🔓 Encrypted' : '🔒 No session key'}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Main Chat Area */}
                    <div className="chat-main">
                        {selectedUser ? (
                            <>
                                {/* Chat Header */}
                                <div className="chat-user-header">
                                    <div>
                                        <h2>{selectedUser.username}</h2>
                                        <p className="encryption-status">
                                            {sessionKey ? '✅ End-to-end encrypted' : '⚠️ No session key - run key exchange'}
                                        </p>
                                    </div>
                                    <div className="chat-actions">
                                        {!sessionKey && (
                                            <>
                                                <button onClick={handleInitiateKeyExchange} className="action-btn">
                                                    🔑 Start Key Exchange
                                                </button>
                                                <button onClick={handleManualSessionKey} className="action-btn">
                                                    📥 Import Key
                                                </button>
                                            </>
                                        )}
                                        {sessionKey && (
                                            <button onClick={handleExportSessionKey} className="action-btn">
                                                📤 Export Key
                                            </button>
                                        )}
                                    </div>
                                </div>

                                {/* Messages */}
                                <div className="messages-container">
                                    {messages.map((msg, idx) => (
                                        <MessageBubble
                                            key={msg._id || idx}
                                            message={msg}
                                            isOwn={msg.senderId === user.userId}
                                            decrypt={() => decryptAndDisplayMessage(msg)}
                                        />
                                    ))}
                                    <div ref={messagesEndRef} />
                                </div>

                                {/* Message Input */}
                                <form onSubmit={handleSendMessage} className="message-input-form">
                                    {error && <div className="error-banner">{error}</div>}
                                    {status && <div className="status-banner">{status}</div>}

                                    <div className="input-row">
                                        <input
                                            type="text"
                                            value={newMessage}
                                            onChange={(e) => setNewMessage(e.target.value)}
                                            placeholder={sessionKey ? "Type a message..." : "No session key - set up encryption first"}
                                            disabled={!sessionKey || loading}
                                            className="message-input"
                                        />
                                        <button
                                            type="submit"
                                            disabled={!sessionKey || !newMessage.trim() || loading}
                                            className="send-btn"
                                        >
                                            {loading ? '⏳' : '📤'} Send
                                        </button>
                                    </div>
                                </form>
                            </>
                        ) : (
                            <div className="no-user-selected">
                                <div className="empty-state">
                                    <h3>👈 Select a contact to start messaging</h3>
                                    <p>All messages are end-to-end encrypted</p>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {view === 'logs' && (
                <SecurityLogs />
            )}
        </div>
    );
}

// Message bubble component
function MessageBubble({ message, isOwn, decrypt }) {
    const [decrypted, setDecrypted] = useState(null);

    useEffect(() => {
        decrypt().then(setDecrypted);
    }, []);

    return (
        <div className={`message-bubble ${isOwn ? 'own' : 'other'}`}>
            <div className="message-content">
                {decrypted || '🔄 Decrypting...'}
            </div>
            <div className="message-meta">
                {new Date(message.createdAt).toLocaleTimeString()}
            </div>
        </div>
    );
}

// Security logs component
function SecurityLogs() {
    const [logs, setLogs] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        loadLogs();
        loadStats();
    }, []);

    const loadLogs = async () => {
        setLoading(true);
        try {
            const data = await api.getSecurityLogs({ limit: 50 });
            setLogs(data.logs);
        } catch (err) {
            console.error('Failed to load logs:', err);
        } finally {
            setLoading(false);
        }
    };

    const loadStats = async () => {
        try {
            const data = await api.getLogStats();
            setStats(data);
        } catch (err) {
            console.error('Failed to load stats:', err);
        }
    };

    return (
        <div className="security-logs">
            <h2>Security Audit Logs</h2>

            {stats && (
                <div className="stats-grid">
                    <div className="stat-card">
                        <div className="stat-value">{stats.totalLogs}</div>
                        <div className="stat-label">Total Events</div>
                    </div>
                    <div className="stat-card warning">
                        <div className="stat-value">{stats.attacksDetected}</div>
                        <div className="stat-label">Attacks Detected</div>
                    </div>
                    <div className="stat-card error">
                        <div className="stat-value">{stats.replayAttacks}</div>
                        <div className="stat-label">Replay Attempts</div>
                    </div>
                    <div className="stat-card success">
                        <div className="stat-value">{stats.successfulLogins}</div>
                        <div className="stat-label">Successful Logins</div>
                    </div>
                </div>
            )}

            <div className="logs-table">
                {loading ? (
                    <div className="loading">Loading logs...</div>
                ) : (
                    <table>
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Event Type</th>
                                <th>Severity</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {logs.map((log, idx) => (
                                <tr key={log._id || idx} className={`severity-${log.severity.toLowerCase()}`}>
                                    <td>{new Date(log.timestamp).toLocaleString()}</td>
                                    <td>{log.eventType}</td>
                                    <td>
                                        <span className={`severity-badge ${log.severity.toLowerCase()}`}>
                                            {log.severity}
                                        </span>
                                    </td>
                                    <td>{JSON.stringify(log.details)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}

export default ChatApp;
