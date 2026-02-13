const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const dns = require('dns');
const https = require('https');
const { findUserByEmail, createUser } = require('../database');

// ---- Helper: Validate email domain exists (MX → A/AAAA fallback → allow on error) ----
function validateEmailDomain(email) {
    return new Promise((resolve) => {
        const domain = email.split('@')[1];
        if (!domain) return resolve(false);

        // Set a timeout — if DNS takes too long, allow it through
        const timeout = setTimeout(() => resolve(true), 5000);

        // Try MX records first
        dns.resolveMx(domain, (err, mxAddresses) => {
            if (!err && mxAddresses && mxAddresses.length > 0) {
                clearTimeout(timeout);
                return resolve(true);
            }

            // Fallback: try A record (some domains don't have MX but accept email)
            dns.resolve4(domain, (err2, ipAddresses) => {
                if (!err2 && ipAddresses && ipAddresses.length > 0) {
                    clearTimeout(timeout);
                    return resolve(true);
                }

                // Fallback: try AAAA record (IPv6)
                dns.resolve6(domain, (err3, ipv6Addresses) => {
                    clearTimeout(timeout);
                    if (!err3 && ipv6Addresses && ipv6Addresses.length > 0) {
                        return resolve(true);
                    }
                    // Domain truly doesn't exist
                    resolve(false);
                });
            });
        });
    });
}


// ---- Helper: HTTPS GET request (for GitHub API) ----
function httpsGet(url, headers = {}) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const options = {
            hostname: parsed.hostname,
            path: parsed.pathname + parsed.search,
            method: 'GET',
            headers: { 'User-Agent': 'PhishGuard-App', ...headers }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { resolve(data); }
            });
        });
        req.on('error', reject);
        req.end();
    });
}

// ---- Helper: HTTPS POST request (for GitHub token exchange) ----
function httpsPost(url, body, headers = {}) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const postData = JSON.stringify(body);
        const options = {
            hostname: parsed.hostname,
            path: parsed.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'PhishGuard-App',
                'Content-Length': Buffer.byteLength(postData),
                ...headers
            }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { resolve(data); }
            });
        });
        req.on('error', reject);
        req.write(postData);
        req.end();
    });
}

// Known real email providers
const VALID_EMAIL_DOMAINS = [
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'yahoo.com', 'yahoo.co.in', 'yahoo.co.uk', 'yahoo.co.jp', 'ymail.com',
    'aol.com', 'protonmail.com', 'proton.me', 'icloud.com', 'me.com', 'mac.com',
    'mail.com', 'email.com', 'zoho.com', 'zohomail.com', 'yandex.com', 'yandex.ru',
    'gmx.com', 'gmx.net', 'gmx.de', 'tutanota.com', 'tuta.com', 'fastmail.com',
    'hey.com', 'pm.me', 'mailbox.org', 'posteo.de', 'runbox.com',
    'rediffmail.com', 'sify.com', 'in.com',
    'qq.com', '163.com', '126.com', 'sina.com', 'foxmail.com',
    'naver.com', 'hanmail.net', 'daum.net',
    'seznam.cz', 'wp.pl', 'o2.pl', 'interia.pl', 'libero.it', 'virgilio.it',
    'web.de', 't-online.de', 'freenet.de', 'mail.ru', 'rambler.ru', 'bk.ru',
    'outlook.in', 'live.in', 'hotmail.co.in', 'outlook.co.in',
    'comcast.net', 'verizon.net', 'att.net', 'sbcglobal.net', 'cox.net',
    'btinternet.com', 'sky.com', 'shaw.ca', 'rogers.com',
    'edu', 'ac.in', 'edu.in', 'ac.uk', 'edu.au'
];

// ============================================================
// SIGNUP with email/password (validates email domain)
// ============================================================
router.post('/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email, and password are required' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Please enter a valid email address' });
        }

        // Validate email domain is a known real provider
        const domain = email.split('@')[1].toLowerCase();
        const isValidDomain = VALID_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));
        if (!isValidDomain) {
            return res.status(400).json({ error: 'Please use a real email provider (e.g. Gmail, Outlook, Yahoo, etc.)' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const existing = findUserByEmail(email);
        if (existing) {
            return res.status(400).json({ error: 'An account with this email already exists' });
        }

        const id = uuidv4();
        const password_hash = await bcrypt.hash(password, 10);
        createUser({ id, name, email, password_hash, provider: 'local' });

        req.session.userId = id;
        req.session.userName = name;
        req.session.userEmail = email;

        res.json({ success: true, user: { id, name, email } });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Server error during signup' });
    }
});

// ============================================================
// LOGIN with email/password
// ============================================================
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = findUserByEmail(email);
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        if (!user.password_hash) {
            return res.status(401).json({ error: `This account uses ${user.provider} login. Please sign in with ${user.provider}.` });
        }

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        req.session.userId = user.id;
        req.session.userName = user.name;
        req.session.userEmail = user.email;

        res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// ============================================================
// GOOGLE OAuth — verify Google ID token from Sign In With Google
// ============================================================
router.post('/google', async (req, res) => {
    try {
        const { credential } = req.body;
        if (!credential) {
            return res.status(400).json({ error: 'Google credential is required' });
        }

        // Verify Google ID token
        const { OAuth2Client } = require('google-auth-library');
        const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

        const ticket = await client.verifyIdToken({
            idToken: credential,
            audience: process.env.GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const email = payload.email;
        const name = payload.name || payload.email;

        // Find or create user
        let user = findUserByEmail(email);
        if (!user) {
            const id = uuidv4();
            user = createUser({ id, name, email, provider: 'google' });
        }

        req.session.userId = user.id;
        req.session.userName = user.name;
        req.session.userEmail = user.email;

        res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
    } catch (err) {
        console.error('Google auth error:', err);
        res.status(401).json({ error: 'Google authentication failed. Please try again.' });
    }
});

// ============================================================
// GITHUB OAuth — Step 1: Redirect to GitHub authorization page
// ============================================================
router.get('/github', (req, res) => {
    const clientId = process.env.GITHUB_CLIENT_ID;
    if (!clientId || clientId === 'your-github-client-id') {
        return res.status(500).json({ error: 'GitHub OAuth is not configured. Set GITHUB_CLIENT_ID in .env file.' });
    }

    const redirectUri = `http://localhost:${process.env.PORT || 3000}/api/auth/github/callback`;
    const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=user:email`;
    res.redirect(githubAuthUrl);
});

// ============================================================
// GITHUB OAuth — Step 2: Handle callback, exchange code for token
// ============================================================
router.get('/github/callback', async (req, res) => {
    try {
        const { code } = req.query;
        if (!code) {
            return res.redirect('/?error=GitHub login failed: no authorization code');
        }

        // Exchange code for access token
        const tokenData = await httpsPost('https://github.com/login/oauth/access_token', {
            client_id: process.env.GITHUB_CLIENT_ID,
            client_secret: process.env.GITHUB_CLIENT_SECRET,
            code: code
        });

        if (!tokenData.access_token) {
            console.error('GitHub token error:', tokenData);
            return res.redirect('/?error=GitHub login failed: could not get access token');
        }

        // Get user info from GitHub
        const githubUser = await httpsGet('https://api.github.com/user', {
            Authorization: `Bearer ${tokenData.access_token}`
        });

        // Get the user's email (may need separate call if email is private)
        let email = githubUser.email;
        if (!email) {
            const emails = await httpsGet('https://api.github.com/user/emails', {
                Authorization: `Bearer ${tokenData.access_token}`
            });
            if (Array.isArray(emails)) {
                const primary = emails.find(e => e.primary) || emails[0];
                email = primary ? primary.email : null;
            }
        }

        if (!email) {
            return res.redirect('/?error=Could not get email from GitHub. Make sure your email is visible in GitHub settings.');
        }

        const name = githubUser.name || githubUser.login || email;

        // Find or create user
        let user = findUserByEmail(email);
        if (!user) {
            const id = uuidv4();
            user = createUser({ id, name, email, provider: 'github' });
        }

        req.session.userId = user.id;
        req.session.userName = user.name;
        req.session.userEmail = user.email;

        // Redirect to dashboard
        res.redirect('/dashboard');
    } catch (err) {
        console.error('GitHub callback error:', err);
        res.redirect('/?error=GitHub login failed');
    }
});

// ============================================================
// GET current user
// ============================================================
router.get('/me', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.json({
        user: {
            id: req.session.userId,
            name: req.session.userName,
            email: req.session.userEmail
        }
    });
});

// ============================================================
// LOGOUT
// ============================================================
router.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true });
    });
});

// ============================================================
// CONFIG — returns OAuth client IDs for frontend (public info)
// ============================================================
router.get('/config', (req, res) => {
    res.json({
        googleClientId: process.env.GOOGLE_CLIENT_ID || '',
        githubConfigured: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_ID !== 'your-github-client-id')
    });
});

module.exports = router;
