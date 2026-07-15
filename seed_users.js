const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data.db');

(async () => {
  const SQL = await initSqlJs();
  const buffer = fs.readFileSync(DB_PATH);
  const db = new SQL.Database(buffer);

  const passwordHash = bcrypt.hashSync('11223355', 10);

  for (let i = 1; i <= 10; i++) {
    const phone = '011' + String(i).padStart(8, '0');
    const code = 'SR-' + String(i).padStart(5, '0');

    db.run('INSERT OR IGNORE INTO users (phone, password_hash, invite_code) VALUES (?, ?, ?)', [phone, passwordHash, code]);
    db.run("UPDATE invite_codes SET status = 'used' WHERE code = ?", [code]);
    console.log(`Created: ${phone} / ${code}`);
  }

  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
  console.log('Done. 10 test accounts created.');
})();
