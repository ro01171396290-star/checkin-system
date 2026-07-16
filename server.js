const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'checkin-secret-key-change-me';
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-token-change-me';
const DB_PATH = path.join(__dirname, 'data.db');

let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`CREATE TABLE IF NOT EXISTS invite_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'unused',
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    invite_code TEXT UNIQUE,
    total_days INTEGER DEFAULT 0,
    day7 INTEGER DEFAULT 0,
    day14 INTEGER DEFAULT 0,
    day21 INTEGER DEFAULT 0,
    day30 INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS checkins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    checkin_date TEXT NOT NULL,
    streak_day INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, checkin_date)
  )`);

  // Ensure milestone columns exist (for DBs created before these were added)
  ['day7','day14','day21','day30'].forEach(col => {
    try { db.run(`ALTER TABLE users ADD COLUMN ${col} INTEGER DEFAULT 0`); } catch(e) {}
  });

  const cnt = db.exec('SELECT COUNT(*) as cnt FROM invite_codes');
  const count = cnt.length > 0 ? cnt[0].values[0][0] : 0;

  if (count === 0) {
    console.log('Creating 99,999 invite codes...');
    db.run('BEGIN TRANSACTION');
    const stmt = db.prepare('INSERT INTO invite_codes (code) VALUES (?)');
    for (let i = 1; i <= 99999; i++) {
      stmt.run(['SR-' + String(i).padStart(5, '0')]);
      if (i % 10000 === 0) {
        db.run('COMMIT'); db.run('BEGIN TRANSACTION');
      }
    }
    db.run('COMMIT'); stmt.free(); saveDB();
    console.log('99,999 invite codes created.');
  } else {
    console.log(`Database loaded: ${count} invite codes.`);
  }
  return db;
}

function saveDB() {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function getRow(sql, params = []) {
  const stmt = db.prepare(sql); stmt.bind(params);
  if (stmt.step()) {
    const cols = stmt.getColumnNames(), vals = stmt.get();
    const row = {}; cols.forEach((c, i) => row[c] = vals[i]);
    stmt.free(); return row;
  }
  stmt.free(); return null;
}

function getAll(sql, params = []) {
  const stmt = db.prepare(sql); stmt.bind(params);
  const rows = [];
  while (stmt.step()) {
    const cols = stmt.getColumnNames(), vals = stmt.get();
    const row = {}; cols.forEach((c, i) => row[c] = vals[i]);
    rows.push(row);
  }
  stmt.free(); return rows;
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

initDB().then(() => {
  function authMiddleware(req, res, next) {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: '未登录' });
    try { req.userId = jwt.verify(h.split(' ')[1], JWT_SECRET).userId; next(); }
    catch (e) { return res.status(401).json({ error: '登录已过期' }); }
  }
  function adminMiddleware(req, res, next) {
    if (req.headers['x-admin-token'] !== ADMIN_TOKEN) return res.status(403).json({ error: '无权限' });
    next();
  }

  app.post('/api/register', (req, res) => {
    const { phone, password, inviteCode } = req.body;
    if (!phone || !password || !inviteCode) return res.status(400).json({ error: '手机号、密码和邀请码为必填项' });
    if (!/^\+60\d{9,10}$/.test(phone)) return res.status(400).json({ error: '手机号格式错误，请使用马来西亚格式 +60XXXXXXXXXX' });
    if (password.length < 6) return res.status(400).json({ error: '密码至少 6 位' });
    if (getRow('SELECT id FROM users WHERE phone = ?', [phone])) return res.status(400).json({ error: '该手机号已注册' });
    const invite = getRow('SELECT * FROM invite_codes WHERE code = ?', [inviteCode]);
    if (!invite) return res.status(400).json({ error: 'Invite Code Invalid' });
    if (invite.status === 'used') return res.status(400).json({ error: 'Invite Code Invalid' });
    db.run('INSERT INTO users (phone, password_hash, invite_code) VALUES (?, ?, ?)', [phone, bcrypt.hashSync(password, 10), inviteCode]);
    db.run("UPDATE invite_codes SET status = 'used' WHERE code = ?", [inviteCode]);
    saveDB();
    res.json({ success: true, message: '注册成功，请登录' });
  });

  app.post('/api/login', (req, res) => {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: '手机号和密码为必填项' });
    if (!/^\+60\d{9,10}$/.test(phone)) return res.status(400).json({ error: '手机号格式错误，请使用马来西亚格式 +60XXXXXXXXXX' });
    const user = getRow('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user) return res.status(400).json({ error: '手机号未注册' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(400).json({ error: '密码错误' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { phone: user.phone, inviteCode: user.invite_code, totalDays: user.total_days, day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30 } });
  });

  app.post('/api/change-password', authMiddleware, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ error: '旧密码和新密码为必填项' });
    if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少 6 位' });
    const user = getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    if (!bcrypt.compareSync(oldPassword, user.password_hash)) return res.status(400).json({ error: '旧密码错误' });
    db.run('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync(newPassword, 10), req.userId]);
    saveDB();
    res.json({ success: true, message: '密码修改成功' });
  });

  app.get('/api/checkin/status', authMiddleware, (req, res) => {
    const user = getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    const today = new Date().toISOString().slice(0, 10);
    const todayCheckin = getRow('SELECT * FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, today]);
    const allCheckins = getAll('SELECT checkin_date FROM checkins WHERE user_id = ? ORDER BY checkin_date ASC', [req.userId]);
    res.json({ success: true, totalDays: user.total_days, checkedToday: !!todayCheckin, streakDay: todayCheckin ? todayCheckin.streak_day : 0, milestonesClaimed: { day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30 }, history: allCheckins.map(c => c.checkin_date), lastDate: allCheckins.length > 0 ? allCheckins[allCheckins.length - 1].checkin_date : null });
  });

  app.post('/api/checkin', authMiddleware, (req, res) => {
    const today = new Date().toISOString().slice(0, 10);
    if (getRow('SELECT id FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, today])) return res.status(400).json({ error: '今天已签到' });
    const user = getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const yesterdayCheckin = getRow('SELECT * FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, yesterday]);
    const streakDay = yesterdayCheckin ? yesterdayCheckin.streak_day + 1 : 1;
    const milestones = [7, 14, 21, 30];
    let newMilestone = 0;
    db.run('INSERT INTO checkins (user_id, checkin_date, streak_day) VALUES (?, ?, ?)', [req.userId, today, streakDay]);
    const ms = milestones.filter(m => streakDay === m && !user['day' + m]);
    if (ms.length > 0) { db.run(`UPDATE users SET total_days = total_days + 1, day${ms[0]} = 1 WHERE id = ?`, [req.userId]); newMilestone = ms[0]; }
    else { db.run('UPDATE users SET total_days = total_days + 1 WHERE id = ?', [req.userId]); }
    saveDB();
    res.json({ success: true, streakDay, newMilestone, checkedToday: true });
  });

  // 测试端点：无每日限制，可无限签到
  app.post('/api/checkin-test', authMiddleware, (req, res) => {
    const today = new Date().toISOString().slice(0, 10);
    const user = getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const yesterdayCheckin = getRow('SELECT * FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, yesterday]);
    const streakDay = yesterdayCheckin ? (yesterdayCheckin.streak_day % 30) + 1 : 1;
    const milestones = [7, 14, 21, 30];
    let newMilestone = 0;
    db.run('INSERT OR REPLACE INTO checkins (user_id, checkin_date, streak_day) VALUES (?, ?, ?)', [req.userId, today, streakDay]);
    const displayDay = (user.total_days % 30) + 1;
    const ms = milestones.filter(m => displayDay === m && !user['day' + m]);
    if (ms.length > 0) { db.run(`UPDATE users SET total_days = total_days + 1, day${ms[0]} = 1 WHERE id = ?`, [req.userId]); newMilestone = ms[0]; }
    else { db.run('UPDATE users SET total_days = total_days + 1 WHERE id = ?', [req.userId]); }
    saveDB();
    const updatedUser = getRow('SELECT total_days FROM users WHERE id = ?', [req.userId]);
    res.json({ success: true, streakDay, totalDays: updatedUser.total_days, newMilestone, checkedToday: true });
  });

  app.post('/api/checkin-test/reset', authMiddleware, (req, res) => {
    db.run('DELETE FROM checkins WHERE user_id = ?', [req.userId]);
    db.run('UPDATE users SET total_days = 0, day7 = 0, day14 = 0, day21 = 0, day30 = 0 WHERE id = ?', [req.userId]);
    saveDB();
    res.json({ success: true, message: 'Reset complete' });
  });

  app.get('/api/admin/search', adminMiddleware, (req, res) => {
    const code = req.query.code;
    if (!code) return res.status(400).json({ error: '请输入代号' });
    const user = getRow('SELECT * FROM users WHERE invite_code = ?', [code]);
    if (!user) return res.json({ found: false, message: '该代号尚未注册' });
    res.json({ found: true, inviteCode: user.invite_code, phone: user.phone, totalDays: user.total_days, day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30, createdAt: user.created_at });
  });

  app.get('/api/admin/search-phone', adminMiddleware, (req, res) => {
    const phone = req.query.phone;
    if (!phone) return res.status(400).json({ error: '请输入手机号' });
    const user = getRow('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user) return res.json({ found: false, message: '该手机号尚未注册' });
    res.json({ found: true, inviteCode: user.invite_code, phone: user.phone, totalDays: user.total_days, day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30, createdAt: user.created_at });
  });

  app.post('/api/admin/reset-password', adminMiddleware, (req, res) => {
    const { code, newPassword } = req.body;
    if (!code || !newPassword) return res.status(400).json({ error: '代号和新密码为必填项' });
    if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少 6 位' });
    const fullCode = code.startsWith('SR-') ? code : 'SR-' + code.padStart(5, '0');
    if (!getRow('SELECT id FROM users WHERE invite_code = ?', [fullCode])) return res.status(400).json({ error: '该代号尚未注册' });
    db.run('UPDATE users SET password_hash = ? WHERE invite_code = ?', [bcrypt.hashSync(newPassword, 10), fullCode]);
    saveDB();
    res.json({ success: true, message: '密码重置成功' });
  });

  app.post('/api/admin/update-phone', adminMiddleware, (req, res) => {
    const { code, newPhone } = req.body;
    if (!code || !newPhone) return res.status(400).json({ error: '代号和新手机号为必填项' });
    if (!/^\+60\d{9,10}$/.test(newPhone)) return res.status(400).json({ error: '手机号格式错误，请使用马来西亚格式 +60XXXXXXXXXX' });
    const fullCode = code.startsWith('SR-') ? code : 'SR-' + code.padStart(5, '0');
    if (!getRow('SELECT id FROM users WHERE invite_code = ?', [fullCode])) return res.status(400).json({ error: '该代号尚未注册' });
    const existing = getRow('SELECT id FROM users WHERE phone = ? AND invite_code != ?', [newPhone, fullCode]);
    if (existing) return res.status(400).json({ error: '该手机号已被其他用户使用' });
    db.run('UPDATE users SET phone = ? WHERE invite_code = ?', [newPhone, fullCode]);
    saveDB();
    res.json({ success: true, message: '手机号更新成功', newPhone });
  });

  app.post('/api/admin/delete-user', adminMiddleware, (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: '代号为必填项' });
    const fullCode = code.startsWith('SR-') ? code : 'SR-' + code.padStart(5, '0');
    const user = getRow('SELECT id FROM users WHERE invite_code = ?', [fullCode]);
    if (!user) return res.status(400).json({ error: '该代号尚未注册' });
    db.run('DELETE FROM checkins WHERE user_id = ?', [user.id]);
    db.run('DELETE FROM users WHERE id = ?', [user.id]);
    db.run("UPDATE invite_codes SET status = 'unused' WHERE code = ?", [fullCode]);
    saveDB();
    res.json({ success: true, message: '用户已删除，号码和邀请码可重新注册' });
  });

  app.get('/api/admin/users', adminMiddleware, (req, res) => {
    const users = getAll('SELECT phone, invite_code, total_days, created_at FROM users ORDER BY created_at DESC');
    res.json({ success: true, users });
  });

  app.post('/api/admin/add-invite', adminMiddleware, (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: '邀请码为必填项' });
    if (getRow('SELECT id FROM invite_codes WHERE code = ?', [code])) return res.status(400).json({ error: '该邀请码已存在' });
    db.run('INSERT INTO invite_codes (code) VALUES (?)', [code]);
    saveDB();
    res.json({ success: true, message: '邀请码 ' + code + ' 已添加' });
  });

  app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`  Server: http://localhost:${PORT}`);
    console.log(`  Register: http://localhost:${PORT}/register.html`);
    console.log(`  Login:    http://localhost:${PORT}/login.html`);
    console.log(`  Checkin:  http://localhost:${PORT}/checkin.html`);
    console.log(`  Admin:    http://localhost:${PORT}/admin.html`);
    console.log(`========================================\n`);
  });
});
