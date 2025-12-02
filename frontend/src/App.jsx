import { useState, useEffect } from 'react';
import Register from './components/Register';
import Login from './components/Login';
import ChatApp from './components/ChatApp';
import './App.css';

function App() {
  const [view, setView] = useState('login'); // 'login', 'register', 'chat'
  const [user, setUser] = useState(null);

  // Check if user is already logged in
  useEffect(() => {
    const checkSession = async () => {
      const token = localStorage.getItem('token');
      const userId = localStorage.getItem('userId');
      const username = localStorage.getItem('username');

      if (token && userId && username) {
        // Verify we still have the keys (they might have been cleared)
        const { hasStoredKeys } = await import('./crypto/keyManagement');
        const keysExist = await hasStoredKeys(userId);

        if (keysExist) {
          setUser({ token, userId, username });
          setView('chat');
        } else {
          // Keys missing, force logout
          console.warn('Session found but keys missing from storage. Logging out.');
          handleLogout();
        }
      }
    };

    checkSession();
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
    setView('chat');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    localStorage.removeItem('publicKey');
    setUser(null);
    setView('login');
  };

  const handleRegisterSuccess = () => {
    setView('login');
  };

  return (
    <div className="app">
      {view === 'login' && (
        <Login
          onLogin={handleLogin}
          onSwitchToRegister={() => setView('register')}
        />
      )}

      {view === 'register' && (
        <Register
          onSuccess={handleRegisterSuccess}
          onSwitchToLogin={() => setView('login')}
        />
      )}

      {view === 'chat' && user && (
        <ChatApp user={user} onLogout={handleLogout} />
      )}
    </div>
  );
}

export default App;
