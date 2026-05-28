// Security: User Routes
// Handles user profile operations with authentication

const express = require('express');
const router = express.Router();
const validator = require('validator');
const crypto = require('crypto');
const authMiddleware = require('../middleware/auth');
const db = require('../database');

// Security: Decryption function for sensitive fields
const decryptField = (encryptedData) => {
  const key = process.env.ENCRYPTION_KEY || 'default-insecure-key-change-in-env';
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
  let decrypted = decipher.update(parts[1], 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Security: Encryption function for sensitive fields
const encryptField = (plainText) => {
  const key = process.env.ENCRYPTION_KEY || 'default-insecure-key-change-in-env';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

// Get user profile - Protected route
router.get('/profile', authMiddleware, (req, res) => {
  try {
    // Security: User can only access their own profile
    const userId = req.user.id;

    db.get(
      `SELECT id, name, email, student_id_encrypted, phone_encrypted, role, created_at FROM users WHERE id = ?`,
      [userId],
      (err, user) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Failed to fetch profile' });
        }

        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }

        // Security: Decrypt sensitive fields before sending to frontend
        try {
          const decryptedStudentId = decryptField(user.student_id_encrypted);
          const decryptedPhone = decryptField(user.phone_encrypted);

          res.json({
            id: user.id,
            name: user.name,
            email: user.email,
            studentId: decryptedStudentId,
            phone: decryptedPhone,
            role: user.role,
            createdAt: user.created_at
          });
        } catch (decryptErr) {
          console.error('Decryption error:', decryptErr);
          res.status(500).json({ error: 'Failed to decrypt user data' });
        }
      }
    );
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile - Protected route
router.put('/profile', authMiddleware, (req, res) => {
  try {
    const userId = req.user.id;
    const { name, phone } = req.body;

    // Security: Validate inputs
    if (!name || !phone) {
      return res.status(400).json({ error: 'Name and phone are required' });
    }

    // Security: Sanitize inputs
    const sanitizedName = validator.escape(name);
    const sanitizedPhone = validator.escape(phone);

    // Security: Validate phone format
    if (!validator.isMobilePhone(sanitizedPhone, 'any')) {
      return res.status(400).json({ error: 'Invalid phone format' });
    }

    // Security: Encrypt phone before storage
    const encryptedPhone = encryptField(sanitizedPhone);

    db.run(
      `UPDATE users SET name = ?, phone_encrypted = ? WHERE id = ?`,
      [sanitizedName, encryptedPhone, userId],
      function (err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Failed to update profile' });
        }

        // Security: Log profile update
        db.run(
          `INSERT INTO audit_logs (action, user_email, ip_address)
           VALUES (?, ?, ?)`,
          ['profile_update', req.user.email, req.ip],
          (logErr) => {
            if (logErr) console.error('Audit log error:', logErr);
          }
        );

        res.json({ message: 'Profile updated successfully' });
      }
    );
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

module.exports = router;
