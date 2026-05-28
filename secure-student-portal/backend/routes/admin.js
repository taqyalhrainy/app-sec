// Security: Admin Routes
// Handles admin operations with role-based authorization

const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const roleMiddleware = require('../middleware/role');
const validator = require('validator');
const crypto = require('crypto');
const db = require('../database');

// Security: Decryption function for sensitive fields
const decryptField = (encryptedData) => {
  try {
    const key = process.env.ENCRYPTION_KEY || 'default-insecure-key-change-in-env';
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
    let decrypted = decipher.update(parts[1], 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    return '[Encrypted Data]'; // Don't expose decryption errors
  }
};

// Get all users - Admin only
router.get('/users', authMiddleware, roleMiddleware('admin'), (req, res) => {
  try {
    // Security: Only admins can access this endpoint
    db.all(
      `SELECT id, name, email, student_id_encrypted, phone_encrypted, role, created_at FROM users`,
      [],
      (err, users) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Failed to fetch users' });
        }

        // Security: Decrypt sensitive fields for admin view
        const decryptedUsers = users.map((user) => {
          try {
            return {
              id: user.id,
              name: user.name,
              email: user.email,
              studentId: decryptField(user.student_id_encrypted),
              phone: decryptField(user.phone_encrypted),
              role: user.role,
              createdAt: user.created_at
            };
          } catch (e) {
            return {
              id: user.id,
              name: user.name,
              email: user.email,
              studentId: '[Encrypted]',
              phone: '[Encrypted]',
              role: user.role,
              createdAt: user.created_at
            };
          }
        });

        // Security: Log admin access
        db.run(
          `INSERT INTO audit_logs (action, user_email, ip_address)
           VALUES (?, ?, ?)`,
          ['view_all_users', req.user.email, req.ip],
          (logErr) => {
            if (logErr) console.error('Audit log error:', logErr);
          }
        );

        res.json(decryptedUsers);
      }
    );
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Change user role - Admin only
router.put('/users/:id/role', authMiddleware, roleMiddleware('admin'), (req, res) => {
  try {
    const userId = req.params.id;
    const { role } = req.body;

    // Security: Validate role input
    if (!role || !['user', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role. Must be "user" or "admin"' });
    }

    // Security: Prevent self-role modification
    if (req.user.id == userId && role !== 'admin') {
      return res.status(400).json({ error: 'Cannot demote yourself from admin' });
    }

    db.run(
      `UPDATE users SET role = ? WHERE id = ?`,
      [role, userId],
      function (err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Failed to update user role' });
        }

        if (this.changes === 0) {
          return res.status(404).json({ error: 'User not found' });
        }

        // Security: Get user email for audit log
        db.get(`SELECT email FROM users WHERE id = ?`, [userId], (getErr, user) => {
          // Security: Log admin action
          db.run(
            `INSERT INTO audit_logs (action, user_email, ip_address)
             VALUES (?, ?, ?)`,
            [`change_role_for_${user?.email || 'unknown'}`, req.user.email, req.ip],
            (logErr) => {
              if (logErr) console.error('Audit log error:', logErr);
            }
          );
        });

        res.json({ message: 'User role updated successfully' });
      }
    );
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// Delete user - Admin only
router.delete('/users/:id', authMiddleware, roleMiddleware('admin'), (req, res) => {
  try {
    const userId = req.params.id;

    // Security: Prevent self-deletion
    if (req.user.id == userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    // Get user email before deletion
    db.get(`SELECT email FROM users WHERE id = ?`, [userId], (getErr, user) => {
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      db.run(`DELETE FROM users WHERE id = ?`, [userId], function (err) {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Failed to delete user' });
        }

        // Security: Log admin action
        db.run(
          `INSERT INTO audit_logs (action, user_email, ip_address)
           VALUES (?, ?, ?)`,
          [`delete_user_${user.email}`, req.user.email, req.ip],
          (logErr) => {
            if (logErr) console.error('Audit log error:', logErr);
          }
        );

        res.json({ message: 'User deleted successfully' });
      });
    });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Get audit logs - Admin only
router.get('/audit-logs', authMiddleware, roleMiddleware('admin'), (req, res) => {
  try {
    // Security: Only admins can access audit logs
    db.all(
      `SELECT id, action, user_email, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100`,
      [],
      (err, logs) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Failed to fetch audit logs' });
        }

        res.json(logs);
      }
    );
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

module.exports = router;
