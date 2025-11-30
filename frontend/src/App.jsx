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
    const token = localStorage.getItem('token');
    const userId = localStorage.getItem('userId');
    const username = localStorage.getItem('username');

    if (token && userId && username) {
      setUser({ token, userId, username });
      setView('chat');
    }
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
        <>
          <Login onLogin={handleLogin} />
          <div className="auth-switch">
            Don't have an account?{' '}
            <button onClick={() => setView('register')} className="switch-btn">
              Register
            </button>
          </div>
        </>
      )}

      {view === 'register' && (
        <>
          <Register onSuccess={handleRegisterSuccess} />
          <div className="auth-switch">
            Already have an account?{' '}
            <button onClick={() => setView('login')} className="switch-btn">
              Login
            </button>
          </div>
        </>
      )}

      {view === 'chat' && user && (
        <ChatApp user={user} onLogout={handleLogout} />
      )}
    </div>
  );
}

export default App;
