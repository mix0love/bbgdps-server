const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cookieParser());

// CORS for local testing (file:// support)
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

// Serve the specific HTML file
app.get('/', (req, res) => {
    // Check if running locally with the specific file, otherwise serve standard index.html
    const localFile = 'd:\\index (12).html';
    if (fs.existsSync(localFile)) {
        res.sendFile(localFile);
    } else {
        res.sendFile(path.join(__dirname, 'index.html'));
    }
});

app.use(express.static(__dirname));

// --- DATABASE ---
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

function loadDB() {
    if (!fs.existsSync(DB_FILE)) return { levels: [], list: [], pending: [], team: [] };
    try {
        const data = fs.readFileSync(DB_FILE, 'utf8');
        return data ? JSON.parse(data) : { levels: [], list: [], pending: [], team: [] };
    } catch (e) {
        console.error("Error reading DB:", e);
        return { levels: [], list: [], pending: [], team: [] };
    }
}

function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return data ? JSON.parse(data) : [];
    } catch (e) {
        console.error("Error reading Users:", e);
        return [];
    }
}

function saveUsers(data) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

function loadLogs() {
    if (!fs.existsSync(LOGS_FILE)) return [];
    try {
        const data = fs.readFileSync(LOGS_FILE, 'utf8');
        return data ? JSON.parse(data) : [];
    } catch (e) {
        console.error("Error reading Logs:", e);
        return [];
    }
}

function saveLogs(data) {
    fs.writeFileSync(LOGS_FILE, JSON.stringify(data, null, 2));
}

function logAudit(action, actor) {
    const logs = loadLogs();
    const entry = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        actor: actor || 'System',
        action: action
    };
    logs.unshift(entry); // Newest first
    // Limit log size to 1000 entries
    if (logs.length > 1000) logs.pop();
    saveLogs(logs);
    console.log(`[AUDIT] ${entry.actor}: ${entry.action}`);
}

// --- AUTH MIDDLEWARE ---
const SESSIONS = {}; // token -> user object

function checkAuth(req, res, next) {
    const token = req.cookies['session_token'];
    if (!token || !SESSIONS[token]) return res.status(401).json({ error: 'Unauthorized' });

    // Reload user from DB to ensure fresh role info
    const users = loadUsers();
    const freshUser = users.find(u => u.username === SESSIONS[token].username);

    if (!freshUser) {
        delete SESSIONS[token];
        return res.status(401).json({ error: 'User not found' });
    }

    req.user = freshUser;
    // Update session cache
    SESSIONS[token] = freshUser;
    next();
}

function checkAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
}

// --- API ROUTES ---

// AUTH & USERS
app.post('/api/auth/register', (req, res) => {
    const { username, pass, country } = req.body;
    if (!username || !pass) return res.status(400).json({ error: 'Missing fields' });

    const users = loadUsers();

    // Check duplication
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
        return res.status(409).json({ error: 'Username taken' });
    }

    // First User Is Admin Logic
    const isFirstUser = users.length === 0;
    const role = isFirstUser ? 'admin' : 'user';

    const newUser = {
        username,
        pass, // Client sent hash, or we store hash depending on strategy. Assuming client sends SHA256 for now as per old logic.
        country: country || '',
        role: role,
        avatar: '',
        bio: '',
        joinedAt: new Date().toISOString()
    };

    users.push(newUser);
    saveUsers(users);

    logAudit(`User Registered: ${username} (Role: ${role})`, username);

    // Auto-login
    const sessionToken = crypto.randomBytes(32).toString('hex');
    SESSIONS[sessionToken] = newUser;
    res.cookie('session_token', sessionToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });

    // Return sanitised user
    const { pass: _, ...userSafe } = newUser;
    res.json({ success: true, user: userSafe });
});

app.post('/api/auth/login', (req, res) => {
    const { username, pass } = req.body;
    const users = loadUsers();

    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase() && u.pass === pass);

    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const sessionToken = crypto.randomBytes(32).toString('hex');
    SESSIONS[sessionToken] = user;
    res.cookie('session_token', sessionToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });

    logAudit(`User Logged In`, user.username);

    const { pass: _, ...userSafe } = user;
    res.json({ success: true, user: userSafe });
});

app.post('/api/auth/logout', (req, res) => {
    const token = req.cookies['session_token'];
    if (token) delete SESSIONS[token];
    res.clearCookie('session_token');
    res.json({ success: true });
});

app.get('/api/me', checkAuth, (req, res) => {
    const { pass: _, ...userSafe } = req.user;
    res.json(userSafe);
});

app.get('/api/users', (req, res) => {
    const users = loadUsers();
    // Return safe list
    const safeUsers = users.map(u => {
        const { pass, ...rest } = u;
        return rest;
    });
    res.json(safeUsers);
});

// CORE DATA
app.get('/api/levels', (req, res) => {
    const db = loadDB();
    res.json(db.levels || []);
});

app.get('/api/admin/logs', checkAuth, checkAdmin, (req, res) => {
    const logs = loadLogs();
    res.json(logs);
});
// ADMIN ACTIONS
// --- LEVEL MANAGEMENT ---
app.post('/api/admin/levels', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    const newLvl = req.body;
    // Basic validation
    if (!newLvl || !newLvl.name) return res.status(400).json({ error: "Invalid Data" });

    // Ensure ID uniqueness
    if (db.levels.find(x => x.id === newLvl.id)) newLvl.id = Date.now();

    db.levels.push(newLvl);
    saveDB(db);
    logAudit(`Added Level: ${newLvl.name} (${newLvl.id})`, req.user.username);
    res.json({ success: true, id: newLvl.id });
});

app.put('/api/admin/levels/:id', checkAuth, checkAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const db = loadDB();
    const idx = db.levels.findIndex(x => x.id === id);

    if (idx === -1) return res.status(404).json({ error: "Level not found" });

    // Merge updates
    const updatedLvl = { ...db.levels[idx], ...req.body };
    db.levels[idx] = updatedLvl;

    saveDB(db);
    logAudit(`Updated Level: ${updatedLvl.name} (${id})`, req.user.username);
    res.json({ success: true });
});

app.delete('/api/admin/levels/:id', checkAuth, checkAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const db = loadDB();
    const idx = db.levels.findIndex(x => x.id === id);

    if (idx === -1) return res.status(404).json({ error: "Level not found" });

    const name = db.levels[idx].name;
    db.levels.splice(idx, 1);

    saveDB(db);
    logAudit(`Deleted Level: ${name} (${id})`, req.user.username);
    res.json({ success: true });
});
app.post('/api/admin/promote', checkAuth, checkAdmin, (req, res) => {
    const { targetUser } = req.body;
    const users = loadUsers();
    const u = users.find(x => x.username === targetUser);

    if (!u) return res.status(404).json({ error: 'User not found' });

    u.role = 'admin';
    saveUsers(users);

    logAudit(`Promoted ${targetUser} to Admin`, req.user.username);
    res.json({ success: true });
});

app.post('/api/admin/demote', checkAuth, checkAdmin, (req, res) => {
    const { targetUser } = req.body;
    if (targetUser === req.user.username) return res.status(400).json({ error: 'Cannot demote self' });

    const users = loadUsers();
    const u = users.find(x => x.username === targetUser);

    if (!u) return res.status(404).json({ error: 'User not found' });

    u.role = 'user';
    saveUsers(users);

    logAudit(`Demoted ${targetUser} to User`, req.user.username);
    res.json({ success: true });
});

app.post('/api/admin/levels', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    if (!db.levels) db.levels = [];
    db.levels.push(req.body);
    saveDB(db);
    logAudit(`Added level ${req.body.name}`, req.user.username);
    res.json({ success: true });
});

app.put('/api/admin/levels/:id', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    const idx = db.levels.findIndex(l => l.id == req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });

    db.levels[idx] = { ...db.levels[idx], ...req.body };
    saveDB(db);
    logAudit(`Edited level ${db.levels[idx].name}`, req.user.username);
    res.json({ success: true });
});

app.delete('/api/admin/levels/:id', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    const lvlName = db.levels.find(l => l.id == req.params.id)?.name || req.params.id;
    db.levels = db.levels.filter(l => l.id != req.params.id);
    saveDB(db);
    logAudit(`Deleted level ${lvlName}`, req.user.username);
    res.json({ success: true });
});

// Admin: User Management
app.post('/api/admin/users/:username/password', checkAuth, checkAdmin, (req, res) => {
    const { pass } = req.body;
    const users = loadUsers();
    const u = users.find(x => x.username === req.params.username);
    if (!u) return res.status(404).json({ error: "User not found" });
    u.pass = pass; // Assuming hash is sent
    saveUsers(users);
    logAudit(`Changed password for ${req.params.username}`, req.user.username);
    res.json({ success: true });
});

app.post('/api/admin/users/:username/flag', checkAuth, checkAdmin, (req, res) => {
    const { country } = req.body;
    const users = loadUsers();
    const u = users.find(x => x.username === req.params.username);
    if (!u) return res.status(404).json({ error: "User not found" });
    u.country = country;
    saveUsers(users);
    logAudit(`Changed flag for ${req.params.username} to ${country}`, req.user.username);
    res.json({ success: true });
});

// Admin: Queue
app.post('/api/admin/queue/:id/decide', checkAuth, checkAdmin, (req, res) => {
    const { accept } = req.body;
    const db = loadDB();
    const qIdx = db.pending.findIndex(x => x.id == req.params.id);
    if (qIdx === -1) return res.status(404).json({ error: "Request not found" });

    const p = db.pending[qIdx];

    if (accept) {
        const l = db.levels.find(x => x.id == p.lvlId);
        if (l) {
            if (l.cat === 'platformer') {
                if (!l.victors.includes(p.player)) l.victors.push(p.player);
                if (!l.platformer_times) l.platformer_times = {};
                l.platformer_times[p.player] = p.perc;
            } else {
                if (p.perc >= 100) {
                    if (!l.victors.includes(p.player)) l.victors.push(p.player);
                } else {
                    if (!l.runs) l.runs = [];
                    l.runs.push({ name: p.player, percent: parseInt(p.perc) });
                    l.runs.sort((a, b) => b.percent - a.percent);
                }
            }
        }
    }

    db.pending.splice(qIdx, 1);
    saveDB(db);
    logAudit(`${accept ? 'Accepted' : 'Rejected'} submission for ${p.player}`, req.user.username);
    res.json({ success: true });
});

// Admin: Team
app.post('/api/admin/team', checkAuth, checkAdmin, (req, res) => {
    const { name, role } = req.body;
    const db = loadDB();
    if (!db.team) db.team = [];
    db.team.push({ name, role });
    saveDB(db);
    logAudit(`Added staff ${name}`, req.user.username);
    res.json({ success: true });
});

app.delete('/api/admin/team/:name', checkAuth, checkAdmin, (req, res) => {
    const db = loadDB();
    if (!db.team) db.team = [];
    db.team = db.team.filter(x => x.name !== req.params.name);
    saveDB(db);
    logAudit(`Removed staff ${req.params.name}`, req.user.username);
    res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Data Directory: ${DATA_DIR}`);
});
