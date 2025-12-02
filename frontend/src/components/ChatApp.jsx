import { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
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
    validateMessageMetadata,
    clearReplayProtectionData
} from '../crypto/replayProtection';
import AttackDemos from './AttackDemos';
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
    const [view, setView] = useState('chat'); // 'chat', 'logs', 'attacks'
    const [selectedFile, setSelectedFile] = useState(null);
    const [uploadProgress, setUploadProgress] = useState(0);
    const messagesEndRef = useRef(null);
    const fileInputRef = useRef(null);
    const socketRef = useRef(null);
    const selectedUserRef = useRef(selectedUser);
    const sessionKeyRef = useRef(sessionKey);
    
    // Update refs when values change
    useEffect(() => {
        selectedUserRef.current = selectedUser;
    }, [selectedUser]);
    
    useEffect(() => {
        sessionKeyRef.current = sessionKey;
    }, [sessionKey]);

    // Set up socket connection for real-time updates
    useEffect(() => {
        if (!user) return;

        const socket = io(import.meta.env.VITE_API_URL?.replace('/api', '') || 'http://localhost:4000', {
            transports: ['websocket', 'polling']
        });

        socket.on('connect', () => {
            console.log('✓ Socket connected');
            // Join user's room
            socket.emit('join', user.userId);
        });

        // Listen for new messages in real-time
        const messageHandler = async (data) => {
            console.log('✓ Received new message via socket:', data);
            // Check current selectedUser from ref
            const currentSelectedUser = selectedUserRef.current;
            if (currentSelectedUser && (data.senderId === currentSelectedUser._id || data.receiverId === currentSelectedUser._id)) {
                // Reload messages to show the new one
                await loadMessages();
            }
        };
        socket.on('message_received', messageHandler);

        // Listen for key exchange response from responder
        const keyExchangeHandler = async (data) => {
            console.log('✓ Received key exchange response notification:', data);
            
            // Check if this is for the currently selected user (use refs to avoid stale closure)
            const currentSelectedUser = selectedUserRef.current;
            const currentSessionKey = sessionKeyRef.current;
            if (!currentSelectedUser || currentSessionKey) return;

            // Check if we have a pending initiation for this key exchange
            const pendingInitKey = Object.keys(sessionStorage)
                .find(k => {
                    if (!k.startsWith('ecdhKeyPair_')) return false;
                    try {
                        const pendingData = JSON.parse(sessionStorage.getItem(k));
                        return pendingData.keyExchangeId === data.keyExchangeId;
                    } catch {
                        return false;
                    }
                });

            if (pendingInitKey) {
                const pendingData = JSON.parse(sessionStorage.getItem(pendingInitKey));
                
                // Verify this is for the selected user
                if (pendingData.responderId === data.responder.userId) {
                    setStatus('✅ Responder accepted! Finalizing secure connection...');
                    
                    try {
                        // Import our ECDH private key back
                        const initiatorECDHPrivateKey = await window.crypto.subtle.importKey(
                            'jwk',
                            pendingData.privateKeyJwk,
                            { name: 'ECDH', namedCurve: 'P-256' },
                            true,
                            ['deriveKey', 'deriveBits']
                        );

                        // Prepare responder message object
                        const responderMessage = {
                            ecdhPublicKey: data.responder.ecdhPublicKey,
                            signature: data.responder.signature,
                            nonce: data.responder.nonce,
                            timestamp: data.responder.timestamp
                        };

                        // Import responder's user public key for signature verification
                        const currentSelectedUser = selectedUserRef.current;
                        if (!currentSelectedUser || !currentSelectedUser.publicKey) {
                            throw new Error('Responder public key not found. Please refresh and try again.');
                        }
                        
                        const responderUserPublicKey = await importPublicKey(
                            currentSelectedUser.publicKey,
                            'ECDSA'
                        );

                        // Complete key exchange (verifies signature and generates session key)
                        const { sessionKey: newSessionKey } = await completeKeyExchange(
                            responderMessage,
                            responderUserPublicKey,
                            initiatorECDHPrivateKey,
                            pendingData.nonce
                        );

                        // Store session key
                        setSessionKey(newSessionKey);
                        const exportedSessionKey = await exportSessionKey(newSessionKey);
                        sessionStorage.setItem(`sessionKey_${currentSelectedUser._id}`, exportedSessionKey);

                        // Cleanup pending data
                        sessionStorage.removeItem(pendingInitKey);

                        setStatus('✅ Secure connection established!');
                        alert(`Secure connection established with ${currentSelectedUser.username}!`);
                    } catch (err) {
                        console.error('Failed to complete key exchange from socket notification:', err);
                        setError(err.message || 'Failed to complete key exchange');
                    }
                }
            }
        };
        socket.on('key_exchange_response', keyExchangeHandler);

        socketRef.current = socket;

        return () => {
            if (socketRef.current) {
                socketRef.current.disconnect();
                socketRef.current = null;
            }
        };
    }, [user]); // Only depend on user, not selectedUser or sessionKey

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

    // Poll for pending key exchanges
    useEffect(() => {
        const checkPendingExchanges = async () => {
            if (!user) return;
            try {
                const data = await api.getPendingKeyExchanges();
                if (data.keyExchanges && data.keyExchanges.length > 0) {
                    // Check if we have a pending exchange from the selected user
                    if (selectedUser) {
                        const pendingFromSelected = data.keyExchanges.find(
                            ke => ke.initiatorId._id === selectedUser._id
                        );
                        if (pendingFromSelected) {
                            setStatus(`🔔 Incoming key exchange request from ${selectedUser.username}!`);
                            // Auto-show respond button via state or just rely on UI
                        }
                    }
                }
            } catch (err) {
                console.error('Error checking pending exchanges:', err);
            }
        };

        // Poll every 5 seconds
        const interval = setInterval(checkPendingExchanges, 5000);
        return () => clearInterval(interval);
    }, [user, selectedUser]);

    // Poll for key exchange confirmation (if we initiated)
    useEffect(() => {
        // Wait a bit before starting to poll (give time for initiation to complete)
        const initialDelay = setTimeout(() => {
            const checkConfirmation = async () => {
                if (!selectedUser || sessionKey) return;

                // Check if we have a pending initiation in session storage
                const pendingInitKey = Object.keys(sessionStorage)
                    .find(k => k.startsWith('ecdhKeyPair_') &&
                        JSON.parse(sessionStorage.getItem(k)).responderId === selectedUser._id);

                if (pendingInitKey) {
                    const pendingData = JSON.parse(sessionStorage.getItem(pendingInitKey));

                    try {
                        // Try to confirm (this will only succeed if responder has responded)
                        const response = await api.confirmKeyExchange(pendingData.keyExchangeId);

                        if (response.status === 'CONFIRMED' && response.responder) {
                            setStatus('✅ Responder accepted! Finalizing secure connection...');

                            // Import our ECDH private key back
                            const initiatorECDHPrivateKey = await window.crypto.subtle.importKey(
                                'jwk',
                                pendingData.privateKeyJwk,
                                { name: 'ECDH', namedCurve: 'P-256' },
                                true,
                                ['deriveKey', 'deriveBits']
                            );

                            // Prepare responder message object
                            const responderMessage = {
                                ecdhPublicKey: response.responder.ecdhPublicKey,
                                signature: response.responder.signature,
                                nonce: response.responder.nonce,
                                timestamp: response.responder.timestamp
                            };

                            // Import responder's user public key for signature verification
                            // Ensure we have the public key
                            if (!selectedUser || !selectedUser.publicKey) {
                                throw new Error('Responder public key not found. Please refresh and try again.');
                            }
                            
                            const responderUserPublicKey = await importPublicKey(
                                selectedUser.publicKey,
                                'ECDSA'
                            );

                            // Complete key exchange (verifies signature and generates session key)
                            const { sessionKey: newSessionKey } = await completeKeyExchange(
                                responderMessage,
                                responderUserPublicKey,
                                initiatorECDHPrivateKey,
                                pendingData.nonce
                            );

                            // Store session key
                            setSessionKey(newSessionKey);
                            const exportedSessionKey = await exportSessionKey(newSessionKey);
                            sessionStorage.setItem(`sessionKey_${selectedUser._id}`, exportedSessionKey);

                            // Cleanup pending data
                            sessionStorage.removeItem(pendingInitKey);

                            setStatus('✅ Secure connection established!');
                            alert(`Secure connection established with ${selectedUser.username}!`);
                        }
                    } catch (err) {
                        // Ignore 404/400 errors as they mean "not ready yet" - these are expected
                        // Only log unexpected errors
                        const status = err.response?.status || err.status;
                        if (status !== 404 && status !== 400) {
                            console.error('Error checking confirmation:', err);
                        }
                        // Silently ignore expected 404/400 errors
                    }
                }
            };

            const interval = setInterval(checkConfirmation, 3000); // Check every 3s
            
            // Cleanup function
            return () => {
                clearInterval(interval);
            };
        }, 2000); // Wait 2 seconds before starting to poll

        return () => {
            clearTimeout(initialDelay);
        };
    }, [selectedUser, sessionKey]);

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

            setStatus(`⏳ Waiting for ${selectedUser.username} to respond...`);

            // Export and store ephemeral private key
            const exportedKey = await window.crypto.subtle.exportKey('jwk', ecdhKeyPair.privateKey);

            sessionStorage.setItem(`ecdhKeyPair_${response.keyExchangeId}`, JSON.stringify({
                keyExchangeId: response.keyExchangeId,
                nonce: keyExchangeMsg.nonce,
                responderId: selectedUser._id,
                privateKeyJwk: exportedKey // Store key to survive reload
            }));

            // Don't show alert - status message is enough
            console.log(`✓ Key exchange initiated! ID: ${response.keyExchangeId}`);

        } catch (err) {
            console.error('Key exchange initiation failed:', err);
            setError(err.message || 'Key exchange failed');
        } finally {
            setLoading(false);
            setStatus('');
        }
    };

    const handleCheckPending = async () => {
        setLoading(true);
        try {
            const data = await api.getPendingKeyExchanges();
            if (data.keyExchanges && data.keyExchanges.length > 0) {
                // Find one for current selected user
                const pending = data.keyExchanges.find(ke => ke.initiatorId._id === selectedUser?._id);

                if (pending) {
                    const confirm = window.confirm(`Found pending key exchange from ${pending.initiatorId.username}. Respond now?`);
                    if (confirm) {
                        await handleRespondToExchange(pending);
                    }
                } else {
                    alert('No pending key exchanges found for this user.');
                }
            } else {
                alert('No pending key exchanges found.');
            }
        } catch (err) {
            console.error('Failed to check pending:', err);
            setError('Failed to check pending exchanges');
        } finally {
            setLoading(false);
        }
    };

    const handleRespondToExchange = async (pendingExchange) => {
        try {
            const password = prompt('Enter your password to access private key:');
            if (!password) return;

            setStatus('Responding to key exchange...');

            // Get our private key
            const responderPrivateKey = await retrievePrivateKey(password, user.userId);

            // Prepare initiator message object
            const initiatorMessage = {
                ecdhPublicKey: pendingExchange.initiatorECDHPublicKey,
                signature: pendingExchange.initiatorSignature,
                nonce: pendingExchange.initiatorNonce,
                timestamp: pendingExchange.initiatorTimestamp
            };

            // Import initiator's public key for signature verification
            // Ensure we have the public key
            if (!pendingExchange.initiatorId || !pendingExchange.initiatorId.publicKey) {
                throw new Error('Initiator public key not found in exchange data');
            }
            
            // Log for debugging (first 50 chars only)
            const publicKeyPreview = typeof pendingExchange.initiatorId.publicKey === 'string' 
                ? pendingExchange.initiatorId.publicKey.substring(0, 50) 
                : 'Not a string';
            console.log('Importing initiator public key (preview):', publicKeyPreview);
            
            const initiatorUserPublicKey = await importPublicKey(
                pendingExchange.initiatorId.publicKey,
                'ECDSA'
            );

            // Respond to key exchange (this verifies signature and generates session key)
            const { sessionKey, message: responseMsg } = await respondToKeyExchange(
                initiatorMessage,
                initiatorUserPublicKey,
                responderPrivateKey
            );

            // Send response to server
            const response = await api.respondToKeyExchange({
                keyExchangeId: pendingExchange._id,
                ecdhPublicKey: responseMsg.ecdhPublicKey,
                signature: responseMsg.signature,
                nonce: responseMsg.nonce,
                timestamp: responseMsg.timestamp
            });

            // Store session key (responder already has it from respondToKeyExchange)
            setSessionKey(sessionKey);
            const exportedKey = await exportSessionKey(sessionKey);
            sessionStorage.setItem(`sessionKey_${selectedUser._id}`, exportedKey);

            setStatus('✅ Key exchange complete! Secure connection established.');
            alert('Key exchange successful! You can now send encrypted messages.');

        } catch (err) {
            console.error('Failed to respond to exchange:', err);
            setError(err.message || 'Failed to respond to key exchange');
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
            // Validate replay protection - treat loaded messages as historical
            // Only newly received messages (via socket) should have strict validation
            const validation = await validateMessageMetadata(
                {
                    nonce: msg.nonce,
                    timestamp: msg.timestamp,
                    sequenceNumber: msg.sequenceNumber
                },
                selectedUser._id,
                { isHistorical: true } // Messages loaded from DB are historical
            );

            if (!validation.valid) {
                // For historical messages, still try to decrypt even if validation fails
                // (they're from the database, so they're legitimate)
                console.warn('Validation warning for historical message:', validation.reason);
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
            // Check if this is likely a key mismatch (most common cause)
            if (err.message && (err.message.includes('invalid key') || err.message.includes('OperationError'))) {
                // Check if message is older than current session (if we can determine)
                const messageDate = new Date(msg.createdAt || msg.timestamp);
                const now = new Date();
                const messageAge = now - messageDate;
                
                // If message is more than 1 hour old, it's likely from a previous session
                if (messageAge > 60 * 60 * 1000) {
                    return '🔑 [Message encrypted with previous session key]\n\nThis message was sent before the current encryption session. Old messages cannot be decrypted with the new key.';
                }
                return '🔑 [Cannot decrypt - wrong session key]\n\nThis message may have been encrypted with a different session key. Try clearing the session and starting a new key exchange.';
            }
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

    const handleFileSelect = (e) => {
        const file = e.target.files[0];
        if (file) {
            // 10MB limit
            if (file.size > 10 * 1024 * 1024) {
                setError('File too large. Maximum size is 10MB.');
                return;
            }
            setSelectedFile(file);
            setError('');
        }
    };

    const handleFileUpload = async () => {
        if (!selectedFile || !sessionKey) return;

        setLoading(true);
        setError('');
        setUploadProgress(0);

        try {
            // Read file as ArrayBuffer
            const fileData = await selectedFile.arrayBuffer();

            // Encrypt file
            setStatus('Encrypting file...');
            const encryptedFile = await encryptFile(fileData, sessionKey);

            // Generate replay protection metadata
            const metadata = generateMessageMetadata(sequenceNumber);

            // Send to server
            setStatus('Uploading encrypted file...');
            await api.sendMessage({
                receiverId: selectedUser._id,
                type: 'file',
                fileName: selectedFile.name,
                fileSize: selectedFile.size,
                fileType: selectedFile.type,
                encryptedChunks: encryptedFile.chunks,
                totalChunks: encryptedFile.totalChunks,
                nonce: metadata.nonce,
                sequenceNumber: metadata.sequenceNumber,
                timestamp: metadata.timestamp
            });

            setSequenceNumber(prev => prev + 1);
            setSelectedFile(null);
            setStatus('File sent successfully!');
            if (fileInputRef.current) fileInputRef.current.value = '';

            // Reload messages
            await loadMessages();

        } catch (err) {
            console.error('Failed to upload file:', err);
            setError(err.response?.data?.error || 'Failed to upload file');
        } finally {
            setLoading(false);
            setUploadProgress(0);
            setTimeout(() => setStatus(''), 3000);
        }
    };

    const handleFileDownload = async (msg) => {
        if (!sessionKey) {
            setError('No session key for decryption');
            return;
        }

        try {
            setStatus('Decrypting file...');

            // Decrypt file chunks
            const decryptedData = await decryptFile(msg.encryptedChunks, sessionKey);

            // Create blob and download
            const blob = new Blob([decryptedData], { type: msg.fileType || 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = msg.fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            setStatus('File downloaded successfully!');
            setTimeout(() => setStatus(''), 3000);
        } catch (err) {
            console.error('Failed to download file:', err);
            setError('Failed to decrypt and download file');
        }
    };

    const handleClearSession = async () => {
        if (!selectedUser) {
            setError('Please select a user first');
            return;
        }

        const confirm = window.confirm(
            `Clear all session data for ${selectedUser.username}?\n\nThis will:\n` +
            `- Remove session key\n` +
            `- Reset sequence numbers\n` +
            `- Clear replay protection data\n` +
            `- Remove pending key exchanges\n` +
            `- Delete ALL chat messages from database\n\n` +
            `⚠️ WARNING: This cannot be undone!\n\n` +
            `You'll need to run key exchange again.`
        );

        if (!confirm) return;

        try {
            setStatus('Clearing session data and deleting messages...');
            setLoading(true);

            // Delete all messages in the conversation from database
            try {
                await api.deleteConversation(selectedUser._id);
                console.log('✓ All messages deleted from database');
            } catch (err) {
                console.error('Failed to delete messages from database:', err);
                // Continue with clearing session data even if message deletion fails
            }

            // Clear session key
            setSessionKey(null);
            sessionStorage.removeItem(`sessionKey_${selectedUser._id}`);

            // Clear sequence number
            setSequenceNumber(0);

            // Clear chat messages from view
            setMessages([]);

            // Clear replay protection data
            await clearReplayProtectionData(selectedUser._id);

            // Clear pending key exchanges for this user
            Object.keys(sessionStorage).forEach(key => {
                if (key.startsWith('ecdhKeyPair_')) {
                    try {
                        const data = JSON.parse(sessionStorage.getItem(key));
                        if (data.responderId === selectedUser._id) {
                            sessionStorage.removeItem(key);
                        }
                    } catch (e) {
                        // Ignore parse errors
                    }
                }
            });

            setStatus('✅ Session data and all messages cleared! You can start a new key exchange.');
            setTimeout(() => setStatus(''), 3000);
        } catch (err) {
            console.error('Failed to clear session:', err);
            setError('Failed to clear session data');
        } finally {
            setLoading(false);
        }
    };

    const handleRefreshMessages = async () => {
        if (!selectedUser) return;
        
        setLoading(true);
        setError('');
        try {
            await loadMessages();
            setStatus('✅ Messages refreshed');
            setTimeout(() => setStatus(''), 2000);
        } catch (err) {
            console.error('Failed to refresh messages:', err);
            setError('Failed to refresh messages');
        } finally {
            setLoading(false);
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
                    <button onClick={() => setView('attacks')} className={view === 'attacks' ? 'active' : ''}>
                        💀 Attack Demos
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
                                        <button onClick={handleRefreshMessages} className="action-btn" title="Refresh messages">
                                            🔄 Refresh
                                        </button>
                                        {!sessionKey && (
                                            <>
                                                <button onClick={handleInitiateKeyExchange} className="action-btn">
                                                    🔑 Start Key Exchange
                                                </button>
                                                <button onClick={handleCheckPending} className="action-btn">
                                                    🔄 Check Pending
                                                </button>
                                                <button onClick={handleManualSessionKey} className="action-btn">
                                                    📥 Import Key
                                                </button>
                                            </>
                                        )}
                                        {sessionKey && (
                                            <>
                                                <button onClick={handleExportSessionKey} className="action-btn">
                                                    📤 Export Key
                                                </button>
                                                <button onClick={handleClearSession} className="action-btn" title="Clear session key and reset sequence numbers">
                                                    🗑️ Clear Session
                                                </button>
                                            </>
                                        )}
                                    </div>
                                </div>

                                {/* Messages */}
                                <div className="messages-container">
                                    {messages.map((msg, idx) => (
                                        msg.type === 'file' ? (
                                            <FileMessageBubble
                                                key={msg._id || idx}
                                                message={msg}
                                                isOwn={msg.senderId === user.userId}
                                                onDownload={() => handleFileDownload(msg)}
                                            />
                                        ) : (
                                            <MessageBubble
                                                key={msg._id || idx}
                                                message={msg}
                                                isOwn={msg.senderId === user.userId}
                                                decrypt={() => decryptAndDisplayMessage(msg)}
                                            />
                                        )
                                    ))}
                                    <div ref={messagesEndRef} />
                                </div>

                                {/* Message Input */}
                                <form onSubmit={handleSendMessage} className="message-input-form">
                                    {error && <div className="error-banner">{error}</div>}
                                    {status && <div className="status-banner">{status}</div>}

                                    {/* File Upload Section */}
                                    {selectedFile && (
                                        <div className="file-preview">
                                            <div className="file-info">
                                                <span>📎 {selectedFile.name}</span>
                                                <span className="file-size">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                                            </div>
                                            <div className="file-actions">
                                                <button
                                                    type="button"
                                                    onClick={handleFileUpload}
                                                    disabled={!sessionKey || loading}
                                                    className="upload-btn"
                                                >
                                                    {loading ? '⏳ Encrypting...' : '📤 Send File'}
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => {
                                                        setSelectedFile(null);
                                                        if (fileInputRef.current) fileInputRef.current.value = '';
                                                    }}
                                                    className="cancel-btn"
                                                >
                                                    ❌ Cancel
                                                </button>
                                            </div>
                                        </div>
                                    )}

                                    <div className="input-row">
                                        <input
                                            type="text"
                                            value={newMessage}
                                            onChange={(e) => setNewMessage(e.target.value)}
                                            placeholder={sessionKey ? "Type a message..." : "No session key - set up encryption first"}
                                            disabled={!sessionKey || loading || selectedFile}
                                            className="message-input"
                                        />
                                        <input
                                            ref={fileInputRef}
                                            type="file"
                                            onChange={handleFileSelect}
                                            style={{ display: 'none' }}
                                            disabled={!sessionKey || loading}
                                        />
                                        <button
                                            type="button"
                                            onClick={() => fileInputRef.current?.click()}
                                            disabled={!sessionKey || loading}
                                            className="attach-btn"
                                            title="Attach encrypted file"
                                        >
                                            📎
                                        </button>
                                        <button
                                            type="submit"
                                            disabled={!sessionKey || !newMessage.trim() || loading || selectedFile}
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

            {view === 'attacks' && (
                <AttackDemos user={user} />
            )}
        </div>
    );
}

// Message bubble component
function MessageBubble({ message, isOwn, decrypt }) {
    const [decrypted, setDecrypted] = useState(null);
    const [isDecrypting, setIsDecrypting] = useState(true);

    useEffect(() => {
        setIsDecrypting(true);
        decrypt()
            .then(result => {
                setDecrypted(result);
                setIsDecrypting(false);
            })
            .catch(err => {
                console.error('Decryption error in MessageBubble:', err);
                setDecrypted('❌ [Decryption error]');
                setIsDecrypting(false);
            });
    }, [decrypt]);

    return (
        <div className={`message-bubble ${isOwn ? 'own' : 'other'}`}>
            <div className="message-content">
                {isDecrypting ? '🔄 Decrypting...' : decrypted}
            </div>
            <div className="message-meta">
                {new Date(message.createdAt).toLocaleTimeString()}
            </div>
        </div>
    );
}

// File message bubble component
function FileMessageBubble({ message, isOwn, onDownload }) {
    return (
        <div className={`message-bubble file-bubble ${isOwn ? 'own' : 'other'}`}>
            <div className="file-message-content">
                <div className="file-icon">📎</div>
                <div className="file-details">
                    <div className="file-name">🔐 {message.fileName}</div>
                    <div className="file-size">{(message.fileSize / 1024).toFixed(1)} KB · {message.totalChunks} chunk(s)</div>
                    <div className="file-encrypted">✅ End-to-end encrypted</div>
                </div>
                <button onClick={onDownload} className="download-btn" title="Decrypt and download">
                    ⬇️ Download
                </button>
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
