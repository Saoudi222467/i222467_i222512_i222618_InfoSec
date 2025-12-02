import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:4000/api';

// Create axios instance with default config
const axiosInstance = axios.create({
    baseURL: API_BASE_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

// Add auth token to requests
axiosInstance.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => Promise.reject(error)
);

// Suppress console errors for expected 404s on key exchange confirm endpoint
axiosInstance.interceptors.response.use(
    (response) => response,
    (error) => {
        // Suppress console logging for expected 404/400 errors on confirm endpoint
        if (error.config?.url?.includes('/keyexchange/confirm') && 
            (error.response?.status === 404 || error.response?.status === 400)) {
            // These are expected - key exchange not ready yet
            // Don't log to console, just return the error
            return Promise.reject(error);
        }
        // For other errors, let them through normally (axios will log them)
        return Promise.reject(error);
    }
);

// API service functions
export const api = {
    // Authentication
    register: async (username, password, publicKey) => {
        const response = await axiosInstance.post('/auth/register', {
            username,
            password,
            publicKey
        });
        return response.data;
    },

    login: async (username, password, twoFactorToken = null) => {
        const response = await axiosInstance.post('/auth/login', {
            username,
            password,
            twoFactorToken
        });
        return response.data;
    },

    getUsers: async () => {
        const response = await axiosInstance.get('/auth/users');
        return response.data;
    },

    getUserByUsername: async (username) => {
        const response = await axiosInstance.get(`/auth/user/${username}`);
        return response.data;
    },

    // Messages
    sendMessage: async (messageData) => {
        const response = await axiosInstance.post('/messages', messageData);
        return response.data;
    },

    getConversation: async (otherUserId) => {
        const response = await axiosInstance.get(`/messages/conversation/${otherUserId}`);
        return response.data;
    },

    deleteMessage: async (messageId) => {
        const response = await axiosInstance.delete(`/messages/${messageId}`);
        return response.data;
    },

    deleteConversation: async (otherUserId) => {
        const response = await axiosInstance.delete(`/messages/conversation/${otherUserId}`);
        return response.data;
    },

    // Key Exchange
    initiateKeyExchange: async (keyExchangeData) => {
        const response = await axiosInstance.post('/keyexchange/initiate', keyExchangeData);
        return response.data;
    },

    respondToKeyExchange: async (keyExchangeData) => {
        const response = await axiosInstance.post('/keyexchange/respond', keyExchangeData);
        return response.data;
    },

    confirmKeyExchange: async (keyExchangeId) => {
        try {
            const response = await axiosInstance.post('/keyexchange/confirm', {
                keyExchangeId
            });
            return response.data;
        } catch (error) {
            // Re-throw 404/400 errors as they're expected (key exchange not ready yet)
            // This allows the caller to handle them gracefully
            if (error.response && (error.response.status === 404 || error.response.status === 400)) {
                throw error;
            }
            // Re-throw other errors
            throw error;
        }
    },

    getPendingKeyExchanges: async () => {
        const response = await axiosInstance.get('/keyexchange/pending');
        return response.data;
    },

    // Files
    uploadFile: async (fileData) => {
        const response = await axiosInstance.post('/files/upload', fileData);
        return response.data;
    },

    downloadFile: async (fileId) => {
        const response = await axiosInstance.get(`/files/${fileId}`);
        return response.data;
    },

    getFilesList: async (otherUserId) => {
        const response = await axiosInstance.get(`/files/list/${otherUserId}`);
        return response.data;
    },

    // Security Logs
    getSecurityLogs: async (params = {}) => {
        const response = await axiosInstance.get('/logs', { params });
        return response.data;
    },

    getLogStats: async () => {
        const response = await axiosInstance.get('/logs/stats');
        return response.data;
    },

    // Two-Factor Authentication
    setup2FA: async () => {
        const response = await axiosInstance.post('/2fa/setup');
        return response.data;
    },

    verify2FA: async (token) => {
        const response = await axiosInstance.post('/2fa/verify', { token });
        return response.data;
    },

    validate2FA: async (username, token) => {
        const response = await axiosInstance.post('/2fa/validate', { username, token });
        return response.data;
    },

    disable2FA: async (password) => {
        const response = await axiosInstance.post('/2fa/disable', { password });
        return response.data;
    },

    get2FAStatus: async () => {
        const response = await axiosInstance.get('/2fa/status');
        return response.data;
    }
};

export default api;
