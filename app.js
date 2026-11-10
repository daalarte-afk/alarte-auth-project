require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || '3306'),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: { rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: "Access token missing" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECRET || 'access_secret');
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: "Invalid or expired access token" });
    }
};

app.get('/', (req, res) => {
    res.json({ message: "Welcome to the Unified Aiven MySQL User Auth & CRUD API!" });
});

app.post('/auth/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password are required" });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (username, hashed_password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, 'user']
        );
        res.status(201).json({ message: "User registered successfully", userId: result.insertId });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ error: "Invalid username or password" });

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.hashed_password);
        if (!validPassword) return res.status(401).json({ error: "Invalid username or password" });

        const payload = { id: user.id, username: user.username, role: user.role };
        const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_TOKEN_SECRET || 'access_secret', { expiresIn: '15m' });
        const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_TOKEN_SECRET || 'refresh_secret', { expiresIn: '7d' });

        await pool.execute('UPDATE users SET refresh_token = ? WHERE id = ?', [refreshToken, user.id]);

        res.json({ message: "Login successful", accessToken, refreshToken });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/users', verifyToken, async (req, res) => {
    try {
        const [rows] = await pool.execute('SELECT id, username, role, created_at FROM users');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/users/:id', verifyToken, async (req, res) => {
    const { username, role } = req.body;
    try {
        const [result] = await pool.execute(
            'UPDATE users SET username = ?, role = ? WHERE id = ?',
            [username, role, req.params.id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: "User not found" });
        res.json({ message: "User updated successfully", updatedId: req.params.id });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.delete('/users/:id', verifyToken, async (req, res) => {
    try {
        const [result] = await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: "User not found" });
        res.json({ message: "User deleted successfully from database" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Unified Auth Server live on http://localhost:${PORT}`);
});
