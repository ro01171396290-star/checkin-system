const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@libsql/client');
const path = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'checkin-secret-key-change-me';
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'admin-token-change-me';
const TURSO_URL = process.env.TURSO_URL || 'libsql://checkin-db-ro01171396290-star.aws-ap-northeast-1.turso.io';
const TURSO_TOKEN = process.env.TURSO_TOKEN || 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODQxODI0NzksImlkIjoiMDE5ZjY5OGItMzMwMS03ZTAyLTkxM2ItNGFlMGU1Mjc2NmQyIiwia2lkIjoiM3lfbVhSTUlPdXljVzdGOWxaVURZbXBMMk9yaVdVUk1XN3pCSFNIUzdwdyIsInJpZCI6Ijk4NTllYjc2LTE3OWQtNDAyZi05YjViLTU0ZTQ3YWZiMzZhMiJ9.sDxnlQT7ofs3hDRUp74HJ0O4zZqvlcnRJ98OQ2v6Mvls2KMjKlmwbPzztrBqbVhRqw_bS5KEDjIYWzYrAlC5DA';

const client = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

async function getRow(sql, params = []) {
  const result = await client.execute({ sql, args: params });
  return result.rows.length > 0 ? result.rows[0] : null;
}

async function getAll(sql, params = []) {
  const result = await client.execute({ sql, args: params });
  return result.rows;
}

async function exec(sql, params = []) {
  await client.execute({ sql, args: params });
}

async function initDB() {
  await exec(`CREATE TABLE IF NOT EXISTS invite_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'unused',
    created_at TEXT DEFAULT (datetime('now'))
  )`);
  await exec(`CREATE TABLE IF NOT EXISTS users (
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
  await exec(`CREATE TABLE IF NOT EXISTS checkins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    checkin_date TEXT NOT NULL,
    streak_day INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, checkin_date)
  )`);

  for (const col of ['day7', 'day14', 'day21', 'day30']) {
    try { await exec(`ALTER TABLE users ADD COLUMN ${col} INTEGER DEFAULT 0`); } catch (e) {}
  }

  console.log('Turso database initialized.');
}

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

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

initDB().then(() => {

  app.post('/api/register', async (req, res) => {
    const { phone, password, inviteCode } = req.body;
    if (!phone || !password || !inviteCode) return res.status(400).json({ error: '手机号、密码和邀请码为必填项' });
    if (!/^\+60\d{9,10}$/.test(phone)) return res.status(400).json({ error: '手机号格式错误，请使用马来西亚格式 +60XXXXXXXXXX' });
    if (password.length < 6) return res.status(400).json({ error: '密码至少 6 位' });
    const existPhone = await getRow('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existPhone) return res.status(400).json({ error: '该手机号已注册' });
    const invite = await getRow('SELECT * FROM invite_codes WHERE code = ?', [inviteCode]);
    if (!invite) return res.status(400).json({ error: 'Invite Code Invalid' });
    if (invite.status === 'used') return res.status(400).json({ error: 'Invite Code Invalid' });
    await exec('INSERT INTO users (phone, password_hash, invite_code) VALUES (?, ?, ?)', [phone, bcrypt.hashSync(password, 10), inviteCode]);
    await exec("UPDATE invite_codes SET status = 'used' WHERE code = ?", [inviteCode]);
    res.json({ success: true, message: '注册成功，请登录' });
  });

  app.post('/api/login', async (req, res) => {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: '手机号和密码为必填项' });
    if (!/^\+60\d{9,10}$/.test(phone)) return res.status(400).json({ error: '手机号格式错误，请使用马来西亚格式 +60XXXXXXXXXX' });
    const user = await getRow('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user) return res.status(400).json({ error: '手机号未注册' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(400).json({ error: '密码错误' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user: { phone: user.phone, inviteCode: user.invite_code, totalDays: user.total_days, day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30 } });
  });

  app.post('/api/change-password', async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ error: '旧密码和新密码为必填项' });
    if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少 6 位' });
    const user = await getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    if (!bcrypt.compareSync(oldPassword, user.password_hash)) return res.status(400).json({ error: '旧密码错误' });
    await exec('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync(newPassword, 10), req.userId]);
    res.json({ success: true, message: '密码修改成功' });
  });

  app.get('/api/checkin/status', async (req, res) => {
    const user = await getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    const today = new Date().toISOString().slice(0, 10);
    const todayCheckin = await getRow('SELECT * FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, today]);
    const allCheckins = await getAll('SELECT checkin_date FROM checkins WHERE user_id = ? ORDER BY checkin_date ASC', [req.userId]);
    res.json({ success: true, totalDays: user.total_days, checkedToday: !!todayCheckin, streakDay: todayCheckin ? todayCheckin.streak_day : 0, milestonesClaimed: { day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30 }, history: allCheckins.map(c => c.checkin_date), lastDate: allCheckins.length > 0 ? allCheckins[allCheckins.length - 1].checkin_date : null });
  });

  app.post('/api/checkin', async (req, res) => {
    const today = new Date().toISOString().slice(0, 10);
    const already = await getRow('SELECT id FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, today]);
    if (already) return res.status(400).json({ error: '今天已签到' });
    const user = await getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const yesterdayCheckin = await getRow('SELECT * FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, yesterday]);
    const streakDay = yesterdayCheckin ? yesterdayCheckin.streak_day + 1 : 1;
    const milestones = [7, 14, 21, 30];
    let newMilestone = 0;
    await exec('INSERT INTO checkins (user_id, checkin_date, streak_day) VALUES (?, ?, ?)', [req.userId, today, streakDay]);
    const ms = milestones.filter(m => streakDay === m && !user['day' + m]);
    if (ms.length > 0) { await exec(`UPDATE users SET total_days = total_days + 1, day${ms[0]} = 1 WHERE id = ?`, [req.userId]); newMilestone = ms[0]; }
    else { await exec('UPDATE users SET total_days = total_days + 1 WHERE id = ?', [req.userId]); }
    res.json({ success: true, streakDay, newMilestone, checkedToday: true });
  });

  app.post('/api/checkin-test', async (req, res) => {
    const today = new Date().toISOString().slice(0, 10);
    const user = await getRow('SELECT * FROM users WHERE id = ?', [req.userId]);
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const yesterdayCheckin = await getRow('SELECT * FROM checkins WHERE user_id = ? AND checkin_date = ?', [req.userId, yesterday]);
    const streakDay = yesterdayCheckin ? (yesterdayCheckin.streak_day % 30) + 1 : 1;
    const milestones = [7, 14, 21, 30];
    let newMilestone = 0;
    await exec('INSERT OR REPLACE INTO checkins (user_id, checkin_date, streak_day) VALUES (?, ?, ?)', [req.userId, today, streakDay]);
    const displayDay = (user.total_days % 30) + 1;
    const ms = milestones.filter(m => displayDay === m && !user['day' + m]);
    if (ms.length > 0) { await exec(`UPDATE users SET total_days = total_days + 1, day${ms[0]} = 1 WHERE id = ?`, [req.userId]); newMilestone = ms[0]; }
    else { await exec('UPDATE users SET total_days = total_days + 1 WHERE id = ?', [req.userId]); }
    const updatedUser = await getRow('SELECT total_days FROM users WHERE id = ?', [req.userId]);
    res.json({ success: true, streakDay, totalDays: updatedUser.total_days, newMilestone, checkedToday: true });
  });

  app.post('/api/checkin-test/reset', async (req, res) => {
    await exec('DELETE FROM checkins WHERE user_id = ?', [req.userId]);
    await exec('UPDATE users SET total_days = 0, day7 = 0, day14 = 0, day21 = 0, day30 = 0 WHERE id = ?', [req.userId]);
    res.json({ success: true, message: 'Reset complete' });
  });

  app.get('/api/admin/search', async (req, res) => {
    const code = req.query.code;
    if (!code) return res.status(400).json({ error: '请输入代号' });
    const user = await getRow('SELECT * FROM users WHERE invite_code = ?', [code]);
    if (!user) return res.json({ found: false, message: '该代号尚未注册' });
    res.json({ found: true, inviteCode: user.invite_code, phone: user.phone, totalDays: user.total_days, day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30, createdAt: user.created_at });
  });

  app.get('/api/admin/search-phone', async (req, res) => {
    const phone = req.query.phone;
    if (!phone) return res.status(400).json({ error: '请输入手机号' });
    const user = await getRow('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user) return res.json({ found: false, message: '该手机号尚未注册' });
    res.json({ found: true, inviteCode: user.invite_code, phone: user.phone, totalDays: user.total_days, day7: user.day7, day14: user.day14, day21: user.day21, day30: user.day30, createdAt: user.created_at });
  });

  app.post('/api/admin/reset-password', async (req, res) => {
    const { code, newPassword } = req.body;
    if (!code || !newPassword) return res.status(400).json({ error: '代号和新密码为必填项' });
    if (newPassword.length < 6) return res.status(400).json({ error: '新密码至少 6 位' });
    const fullCode = code.startsWith('SR-') ? code : 'SR-' + code.padStart(5, '0');
    const exists = await getRow('SELECT id FROM users WHERE invite_code = ?', [fullCode]);
    if (!exists) return res.status(400).json({ error: '该代号尚未注册' });
    await exec('UPDATE users SET password_hash = ? WHERE invite_code = ?', [bcrypt.hashSync(newPassword, 10), fullCode]);
    res.json({ success: true, message: '密码重置成功' });
  });

  app.post('/api/admin/update-phone', async (req, res) => {
    const { code, newPhone } = req.body;
    if (!code || !newPhone) return res.status(400).json({ error: '代号和新手机号为必填项' });
    if (!/^\+60\d{9,10}$/.test(newPhone)) return res.status(400).json({ error: '手机号格式错误，请使用马来西亚格式 +60XXXXXXXXXX' });
    const fullCode = code.startsWith('SR-') ? code : 'SR-' + code.padStart(5, '0');
    const exists = await getRow('SELECT id FROM users WHERE invite_code = ?', [fullCode]);
    if (!exists) return res.status(400).json({ error: '该代号尚未注册' });
    const existing = await getRow('SELECT id FROM users WHERE phone = ? AND invite_code != ?', [newPhone, fullCode]);
    if (existing) return res.status(400).json({ error: '该手机号已被其他用户使用' });
    await exec('UPDATE users SET phone = ? WHERE invite_code = ?', [newPhone, fullCode]);
    res.json({ success: true, message: '手机号更新成功', newPhone });
  });

  app.post('/api/admin/delete-user', async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: '代号为必填项' });
    const fullCode = code.startsWith('SR-') ? code : 'SR-' + code.padStart(5, '0');
    const user = await getRow('SELECT id FROM users WHERE invite_code = ?', [fullCode]);
    if (!user) return res.status(400).json({ error: '该代号尚未注册' });
    await exec('DELETE FROM checkins WHERE user_id = ?', [user.id]);
    await exec('DELETE FROM users WHERE id = ?', [user.id]);
    await exec("UPDATE invite_codes SET status = 'unused' WHERE code = ?", [fullCode]);
    res.json({ success: true, message: '用户已删除，号码和邀请码可重新注册' });
  });

  app.get('/api/admin/users', async (req, res) => {
    const users = await getAll('SELECT phone, invite_code, total_days, created_at FROM users ORDER BY created_at DESC');
    res.json({ success: true, users });
  });

  app.post('/api/admin/add-invite', async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: '邀请码为必填项' });
    const exists = await getRow('SELECT id FROM invite_codes WHERE code = ?', [code]);
    if (exists) return res.status(400).json({ error: '该邀请码已存在' });
    await exec('INSERT INTO invite_codes (code) VALUES (?)', [code]);
    res.json({ success: true, message: '邀请码 ' + code + ' 已添加' });
  });

  app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`  Server: http://localhost:${PORT}`);
    console.log(`  Register: http://localhost:${PORT}/register.html`);
    console.log(`  Login:    http://localhost:${PORT}/login.html`);
    console.log(`  Checkin:  http://localhost:${PORT}/checkin.html`);
    console.log(`  Admin:    http://localhost:${PORT}/admin.html`);
    console.log(`  DB: Turso (${TURSO_URL})`);
    console.log(`========================================\n`);
  });
}).catch(err => {
  console.error('FATAL: Turso init failed:', err.message);
  process.exit(1);
});
