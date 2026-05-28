// Security: Database setup with SQLite
// This module initializes the database with secure schema including password hashing support

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
const initializeDatabase = () => {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Users table with encrypted sensitive fields
      db.run(
        `CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          student_id_encrypted TEXT NOT NULL,
          phone_encrypted TEXT NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT DEFAULT 'user',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,
        (err) => {
          if (err) reject(err);
        }
      );

      // Audit logs table for security tracking
      db.run(
        `CREATE TABLE IF NOT EXISTS audit_logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          action TEXT NOT NULL,
          user_email TEXT,
          ip_address TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  });
};

// Create default admin account if it doesn't exist
const createDefaultAdmin = async () => {
  try {
    const password = 'Admin@12345';
    // Security: Hash password with bcrypt before storing
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT OR IGNORE INTO users (name, email, student_id_encrypted, phone_encrypted, password_hash, role)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        'Admin User',
        'admin@portal.com',
        'ADMIN_ID_ENCRYPTED',
        'ADMIN_PHONE_ENCRYPTED',
        hashedPassword,
        'admin'
      ],
      (err) => {
        if (err) console.error('Error creating default admin:', err);
        else console.log('Default admin account created or already exists');
      }
    );
  } catch (error) {
    console.error('Error hashing admin password:', error);
  }
};

// Execute initialization on startup
initializeDatabase()
  .then(() => {
    console.log('Database initialized successfully');
    createDefaultAdmin();
  })
  .catch((err) => {
    console.error('Database initialization error:', err);
  });

module.exports = db;
