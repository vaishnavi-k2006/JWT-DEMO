const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());          // allow the React app (different port) to call this API
app.use(express.json());  // parse JSON request bodies

const SECRET = 'playground-secret'; // in real apps, put this in an env variable

// Fake user "database" for the demo
const users = {
  alice: { password: '1234' }
};

// LOGIN: check credentials, hand back a signed JWT (the "wristband")
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (users[username]?.password === password) {
    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
    return res.json({ token });
  }

  res.status(401).json({ message: 'Invalid username or password' });
});

// Middleware: checks the wristband before letting the request through
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization']; // expect "Bearer <token>"
  const token = authHeader?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = decoded; // attach decoded payload (e.g. { username })
    next();
  });
}

// PROTECTED ROUTE: only reachable with a valid token
app.get('/profile', requireAuth, (req, res) => {
  res.json({ message: `Welcome back, ${req.user.username}!` });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
import { useState } from 'react';
import './App.css';

const API_URL = 'http://localhost:5000';

function App() {
  const [username, setUsername] = useState('alice');
  const [password, setPassword] = useState('1234');
  const [token, setToken] = useState(null);
  const [profileMessage, setProfileMessage] = useState('');
  const [error, setError] = useState('');

  // Log in: send credentials, store the returned JWT
  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setProfileMessage('');

    try {
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.message);
        return;
      }

      setToken(data.token); // save the wristband
    } catch (err) {
      setError('Could not reach the server.');
    }
  };

  // Call the protected route, attaching the token in the Authorization header
  const handleFetchProfile = async () => {
    setError('');

    try {
      const res = await fetch(`${API_URL}/profile`, {
        headers: { Authorization: `Bearer ${token}` }
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.message);
        return;
      }

      setProfileMessage(data.message);
    } catch (err) {
      setError('Could not reach the server.');
    }
  };

  const handleLogout = () => {
    setToken(null);
    setProfileMessage('');
    setError('');
  };

  return (
    <div className="app">
      <h1>JWT Demo</h1>

      {!token ? (
        <form onSubmit={handleLogin} className="card">
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <button type="submit">Log In</button>
        </form>
      ) : (
        <div className="card">
          <p className="token-box">Token: {token.slice(0, 30)}...</p>
          <button onClick={handleFetchProfile}>Get Protected Profile</button>
          <button onClick={handleLogout} className="secondary">Log Out</button>
          {profileMessage && <p className="success">{profileMessage}</p>}
        </div>
      )}

      {error && <p className="error">{error}</p>}
    </div>
  );
}

export default App;
.app {
  max-width: 360px;
  margin: 60px auto;
  font-family: system-ui, sans-serif;
  text-align: center;
}

.card {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 24px;
  border: 1px solid #ddd;
  border-radius: 10px;
  background: #fafafa;
}

label {
  display: flex;
  flex-direction: column;
  gap: 4px;
  text-align: left;
  font-size: 14px;
}

input {
  padding: 8px 10px;
  border: 1px solid #ccc;
  border-radius: 6px;
  font-size: 14px;
}

button {
  padding: 10px;
  border: none;
  border-radius: 6px;
  background: #2563eb;
  color: white;
  font-size: 14px;
  cursor: pointer;
}

button.secondary {
  background: #6b7280;
}

button:hover {
  opacity: 0.9;
}

.token-box {
  font-size: 12px;
  word-break: break-all;
  background: #eee;
  padding: 8px;
  border-radius: 6px;
}

.success {
  color: #15803d;
  font-size: 14px;
}

.error {
  color: #b91c1c;
  font-size: 14px;
  margin-top: 10px;
}
