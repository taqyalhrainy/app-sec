// Security: Authentication Routes with MongoDB

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const { User, AuditLog } = require('../database');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: 'Too many signup attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const encryptField = (plainText) => {
  const key = process.env.ENCRYPTION_KEY;

  if (!key || key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be exactly 32 characters');
  }

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return iv.toString('hex') + ':' + encrypted;
};

// Signup
router.post('/signup', signupLimiter, async (req, res) => {
  try {
    const { name, email, studentId, phone, password } = req.body;

    if (!name || !email || !studentId || !phone || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!validator.isLength(password, { min: 8 })) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    if (!validator.isMobilePhone(phone, 'any')) {
      return res.status(400).json({ error: 'Invalid phone format' });
    }

    const sanitizedName = validator.escape(name);
    const sanitizedEmail = validator.normalizeEmail(email);

    const existingUser = await User.findOne({ email: sanitizedEmail });

    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const encryptedStudentId = encryptField(validator.escape(studentId));
    const encryptedPhone = encryptField(validator.escape(phone));

    await User.create({
      name: sanitizedName,
      email: sanitizedEmail,
      student_id_encrypted: encryptedStudentId,
      phone_encrypted: encryptedPhone,
      password_hash: passwordHash,
      role: 'user'
    });

    await AuditLog.create({
      action: 'signup',
      user_email: sanitizedEmail,
      ip_address: req.ip
    });

    res.status(201).json({ message: 'Signup successful. Please login.' });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Signup failed. Please try again.' });
  }
});

// Login
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const sanitizedEmail = validator.normalizeEmail(email);

    const user = await User.findOne({ email: sanitizedEmail });

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      await AuditLog.create({
        action: 'failed_login',
        user_email: sanitizedEmail,
        ip_address: req.ip
      });

      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    await AuditLog.create({
      action: 'login',
      user_email: sanitizedEmail,
      ip_address: req.ip
    });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

module.exports = router;