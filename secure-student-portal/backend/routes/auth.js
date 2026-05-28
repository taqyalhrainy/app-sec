// Security: Authentication Routes
// Handles user signup, login with security best practices

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const db = require('../database');

// Security: Rate limiting to prevent brute force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 attempts per 15 minutes
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max 10 signup attempts per hour
  message: 'Too many signup attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Security: Encryption function for sensitive fields
const encryptField = (plainText) => {
  // Use ENCRYPTION_KEY from environment for field encryption
  const key = process.env.ENCRYPTION_KEY || 'default-insecure-key-change-in-env';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

// Security: Decryption function
const decryptField = (encryptedData) => {
  const key = process.env.ENCRYPTION_KEY || 'default-insecure-key-change-in-env';
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
  let decrypted = decipher.update(parts[1], 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Sign up route
router.post('/signup', signupLimiter, async (req, res) => {
  const { name, email, studentId, phone, password } = req.body;

  try {
    // Security: Validate all inputs
    if (!name || !email || !studentId || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Security: Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Security: Sanitize inputs to prevent XSS
    const sanitizedName = validator.escape(name);
    const sanitizedEmail = validator.normalizeEmail(email);

    // Security: Validate password strength
    if (!validator.isLength(password, { min: 8 })) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Security: Validate phone format (basic)
    if (!validator.isMobilePhone(phone, 'any')) {
      return res.status(400).json({ error: 'Invalid phone format' });
    }

    // Security: Hash password with bcrypt (10 salt rounds)
    const passwordHash = await bcrypt.hash(password, 10);

    // Security: Encrypt sensitive fields before storage
    const encryptedStudentId = encryptField(validator.escape(studentId));
    const encryptedPhone = encryptField(validator.escape(phone));

    // Insert user into database
    db.run(
      `INSERT INTO users (name, email, student_id_encrypted, phone_encrypted, password_hash, role)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [sanitizedName, sanitizedEmail, encryptedStudentId, encryptedPhone, passwordHash, 'user'],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Email already registered' });
          }
          // Security: Don't expose database errors
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Signup failed. Please try again.' });
        }

        // Security: Log signup action
        const userIp = req.ip || req.connection.remoteAddress;
        db.run(
          `INSERT INTO audit_logs (action, user_email, ip_address)
           VALUES (?, ?, ?)`,
          ['signup', sanitizedEmail, userIp],
          (logErr) => {
            if (logErr) console.error('Audit log error:', logErr);
          }
        );

        res.status(201).json({ message: 'Signup successful. Please login.' });
      }
    );
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Signup failed. Please try again.' });
  }
});

// Login route
router.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    // Security: Validate inputs
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Security: Normalize email
    const sanitizedEmail = validator.normalizeEmail(email);

    // Query user by email
    db.get(`SELECT * FROM users WHERE email = ?`, [sanitizedEmail], async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        // Security: Generic error message
        return res.status(500).json({ error: 'Login failed. Please try again.' });
      }

      // Security: Check if user exists and password is correct
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        // Security: Generic error to prevent user enumeration
        const userIp = req.ip || req.connection.remoteAddress;
        db.run(
          `INSERT INTO audit_logs (action, user_email, ip_address)
           VALUES (?, ?, ?)`,
          ['failed_login', sanitizedEmail, userIp],
          (logErr) => {
            if (logErr) console.error('Audit log error:', logErr);
          }
        );
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Security: Generate JWT token with expiration
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          role: user.role
        },
        process.env.JWT_SECRET,
        { expiresIn: '24h' } // Token expires in 24 hours
      );

      // Security: Log successful login
      const userIp = req.ip || req.connection.remoteAddress;
      db.run(
        `INSERT INTO audit_logs (action, user_email, ip_address)
         VALUES (?, ?, ?)`,
        ['login', sanitizedEmail, userIp],
        (logErr) => {
          if (logErr) console.error('Audit log error:', logErr);
        }
      );

      res.json({
        message: 'Login successful',
        token: token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role
        }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

module.exports = router;
