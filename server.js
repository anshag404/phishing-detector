require('dotenv').config();
const express = require('express');
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'phishing-detector-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        httpOnly: true
    }
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// API Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/scan', require('./routes/scan'));

// Page routes — serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/report', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

// Initialize database
require('./database');

app.listen(PORT, async () => {
    console.log(`
  ╔══════════════════════════════════════════════╗
  ║   🛡️  Phishing Detection System             ║
  ║   Server running on http://localhost:${PORT}    ║
  ╚══════════════════════════════════════════════╝
  `);

    // Load PhishTank database in the background
    try {
        const { loadPhishTankDB, getPhishTankStats } = require('./utils/phishtank');
        await loadPhishTankDB();
        const stats = getPhishTankStats();
        console.log(`  📡 PhishTank DB: ${stats.entries} entries loaded`);
    } catch (err) {
        console.log(`  ⚠️ PhishTank DB failed to load: ${err.message}`);
    }
});
