// Security: JWT Authentication Middleware
// Verifies JWT tokens and protects private routes

const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  // Security: Extract token from Authorization header or localStorage (passed as header)
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;

  if (!token) {
    // Security: Don't expose sensitive information in error message
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  try {
    // Security: Verify token signature and expiration
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach user info to request
    next();
  } catch (error) {
    // Security: Generic error message to avoid information disclosure
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

module.exports = authMiddleware;
