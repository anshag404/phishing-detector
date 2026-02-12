/**
 * Simple JSON File Database
 * Stores users and scans in a JSON file on disk
 */

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data.json');

// Initialize or load database
function loadDB() {
    try {
        if (fs.existsSync(DB_PATH)) {
            const raw = fs.readFileSync(DB_PATH, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error('DB load error, starting fresh:', e.message);
    }
    return { users: [], scans: [] };
}

function saveDB(data) {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
}

// Initialize
let db = loadDB();

// ---- User Operations ----

function findUserByEmail(email) {
    return db.users.find(u => u.email === email) || null;
}

function findUserById(id) {
    return db.users.find(u => u.id === id) || null;
}

function createUser({ id, name, email, password_hash, provider }) {
    const user = {
        id,
        name,
        email,
        password_hash: password_hash || null,
        provider: provider || 'local',
        created_at: new Date().toISOString()
    };
    db.users.push(user);
    saveDB(db);
    return user;
}

// ---- Scan Operations ----

function createScan({ id, user_id, type, target, score, risk_level, details, recommendations }) {
    const scan = {
        id,
        user_id,
        type,
        target,
        score,
        risk_level,
        details,
        recommendations,
        created_at: new Date().toISOString()
    };
    db.scans.push(scan);
    saveDB(db);
    return scan;
}

function getScansByUser(userId, limit = 50) {
    return db.scans
        .filter(s => s.user_id === userId)
        .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
        .slice(0, limit);
}

function getScanById(id, userId) {
    return db.scans.find(s => s.id === id && s.user_id === userId) || null;
}

module.exports = {
    findUserByEmail,
    findUserById,
    createUser,
    createScan,
    getScansByUser,
    getScanById
};
