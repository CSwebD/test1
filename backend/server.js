const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Initialize SQLite database
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize database tables
function initializeDatabase() {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_active BOOLEAN DEFAULT 1
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token VARCHAR(255) UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
}

// Helper function to generate session token
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Helper function to create session
function createSession(userId, callback) {
    const token = generateSessionToken();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    db.run(
        'INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)',
        [userId, token, expiresAt.toISOString()],
        function(err) {
            if (err) {
                callback(err, null);
            } else {
                callback(null, { token, expiresAt });
            }
        }
    );
}

// Middleware to verify session
function authenticateSession(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ error: 'No session token provided' });
    }

    db.get(
        'SELECT s.*, u.id as user_id, u.username, u.email FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.session_token = ? AND s.expires_at > datetime("now")',
        [token],
        (err, session) => {
            if (err || !session) {
                return res.status(401).json({ error: 'Invalid or expired session' });
            }
            req.user = { id: session.user_id, username: session.username, email: session.email };
            next();
        }
    );
}

// POST /api/signup - Register new user
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    try {
        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Insert user
        db.run(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, passwordHash],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'Username or email already exists' });
                    }
                    return res.status(500).json({ error: 'Failed to create account' });
                }

                // Create session
                createSession(this.lastID, (err, session) => {
                    if (err) {
                        return res.status(500).json({ error: 'Account created but failed to login' });
                    }

                    res.status(201).json({
                        message: 'Account created successfully',
                        user: { id: this.lastID, username, email },
                        token: session.token
                    });
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/login - Login user
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        try {
            const match = await bcrypt.compare(password, user.password_hash);

            if (!match) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Update last login
            db.run('UPDATE users SET last_login = datetime("now") WHERE id = ?', [user.id]);

            // Create session
            createSession(user.id, (err, session) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create session' });
                }

                res.json({
                    message: 'Login successful',
                    user: { id: user.id, username: user.username, email: user.email },
                    token: session.token
                });
            });
        } catch (error) {
            res.status(500).json({ error: 'Server error' });
        }
    });
});

// POST /api/logout - Logout user
app.post('/api/logout', authenticateSession, (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');

    db.run('DELETE FROM sessions WHERE session_token = ?', [token], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to logout' });
        }
        res.json({ message: 'Logged out successfully' });
    });
});

// GET /api/me - Get current user
app.get('/api/me', authenticateSession, (req, res) => {
    res.json({ user: req.user });
});

// Start server
app.listen(PORT, () => {
    console.log(`Auth server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        }
        process.exit(0);
    });
});