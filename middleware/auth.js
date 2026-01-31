const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'saferoute_secret_key_change_in_production';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'saferoute_refresh_secret_key_change_in_production';

// Token blacklist for logged out tokens (in production, use Redis)
const tokenBlacklist = new Set();

/**
 * Middleware to verify JWT token
 */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. No token provided.',
      code: 'NO_TOKEN'
    });
  }
  
  const token = authHeader.split(' ')[1];
  
  // Check if token is blacklisted
  if (tokenBlacklist.has(token)) {
    return res.status(401).json({
      success: false,
      message: 'Token has been revoked. Please login again.',
      code: 'TOKEN_REVOKED'
    });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token has expired. Please login again.',
        code: 'TOKEN_EXPIRED'
      });
    }
    return res.status(401).json({
      success: false,
      message: 'Invalid token.',
      code: 'INVALID_TOKEN'
    });
  }
};

/**
 * Middleware to check user role
 * @param {string[]} allowedRoles - Array of roles allowed to access the route
 */
const checkRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      console.log('❌ checkRole: No user in request');
      return res.status(401).json({
        success: false,
        message: 'Authentication required.',
        code: 'AUTH_REQUIRED'
      });
    }
    
    console.log(`🔐 checkRole: User ${req.user.username} has role "${req.user.role}", allowed: [${allowedRoles.join(', ')}]`);
    
    if (!allowedRoles.includes(req.user.role)) {
      console.log(`❌ checkRole: Access denied for role "${req.user.role}"`);
      return res.status(403).json({
        success: false,
        message: `Access denied. Required role(s): ${allowedRoles.join(', ')}`,
        code: 'INSUFFICIENT_ROLE',
        requiredRoles: allowedRoles,
        currentRole: req.user.role
      });
    }
    
    console.log('✅ checkRole: Access granted');
    next();
  };
};

/**
 * Middleware to check if user owns a resource or has elevated role
 * @param {string[]} elevatedRoles - Roles that can access any resource
 */
const checkOwnerOrRole = (elevatedRoles = ['manager']) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.',
        code: 'AUTH_REQUIRED'
      });
    }
    
    // Allow if user has elevated role
    if (elevatedRoles.includes(req.user.role)) {
      return next();
    }
    
    // Check if userId in params or body matches authenticated user
    const resourceUserId = req.params.userId || req.body.userId;
    if (resourceUserId && resourceUserId.toString() === req.user.id.toString()) {
      return next();
    }
    
    return res.status(403).json({
      success: false,
      message: 'Access denied. You can only access your own resources.',
      code: 'FORBIDDEN'
    });
  };
};

/**
 * Middleware to check if manager is assigned to shelter
 */
const checkShelterAssignment = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required.',
      code: 'AUTH_REQUIRED'
    });
  }
  
  // Skip check for higher privilege roles
  if (req.user.role === 'admin') {
    return next();
  }
  
  const shelterId = req.params.id || req.params.shelterId || req.body.shelterId;
  
  // If manager, check if assigned to this shelter
  if (req.user.role === 'manager') {
    if (req.user.assignedShelterId && req.user.assignedShelterId.toString() === shelterId) {
      return next();
    }
    // Allow managers to view all shelters but restrict modifications
    if (req.method === 'GET') {
      return next();
    }
    return res.status(403).json({
      success: false,
      message: 'Access denied. You are not assigned to this shelter.',
      code: 'SHELTER_NOT_ASSIGNED'
    });
  }
  
  // Rescue team can view all, modify SOS related
  if (req.user.role === 'rescue_team') {
    return next();
  }
  
  // Users can only view
  if (req.user.role === 'user' && req.method === 'GET') {
    return next();
  }
  
  return res.status(403).json({
    success: false,
    message: 'Access denied.',
    code: 'FORBIDDEN'
  });
};

/**
 * Generate JWT access token
 */
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      role: user.role,
      assignedShelterId: user.assignedShelterId
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
};

/**
 * Generate JWT refresh token
 */
const generateRefreshToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      tokenType: 'refresh'
    },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );
};

/**
 * Verify refresh token
 */
const verifyRefreshToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET);
    if (decoded.tokenType !== 'refresh') {
      throw new Error('Invalid token type');
    }
    return decoded;
  } catch (error) {
    return null;
  }
};

/**
 * Blacklist a token (for logout)
 */
const blacklistToken = (token) => {
  tokenBlacklist.add(token);
  
  // Auto-remove expired tokens from blacklist (cleanup)
  try {
    const decoded = jwt.decode(token);
    if (decoded && decoded.exp) {
      const expiresIn = (decoded.exp * 1000) - Date.now();
      if (expiresIn > 0) {
        setTimeout(() => {
          tokenBlacklist.delete(token);
        }, expiresIn);
      }
    }
  } catch (e) {
    // Token is invalid, will expire from blacklist after 24h
    setTimeout(() => {
      tokenBlacklist.delete(token);
    }, 24 * 60 * 60 * 1000);
  }
};

/**
 * Socket.io authentication middleware
 */
const socketAuthMiddleware = (socket, next) => {
  const token = socket.handshake.auth.token || socket.handshake.query.token;
  
  if (!token) {
    return next(new Error('Authentication required'));
  }
  
  if (tokenBlacklist.has(token)) {
    return next(new Error('Token has been revoked'));
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded;
    socket.token = token;
    next();
  } catch (error) {
    return next(new Error('Invalid or expired token'));
  }
};

/**
 * Socket.io role check helper
 */
const socketCheckRole = (socket, allowedRoles) => {
  if (!socket.user) {
    return { allowed: false, error: 'Authentication required' };
  }
  
  if (!allowedRoles.includes(socket.user.role)) {
    return { 
      allowed: false, 
      error: `Access denied. Required role(s): ${allowedRoles.join(', ')}`
    };
  }
  
  return { allowed: true };
};

/**
 * Rate limiting helper (simple in-memory implementation)
 */
const rateLimitMap = new Map();

const rateLimit = (options = {}) => {
  const {
    windowMs = 60 * 1000, // 1 minute
    max = 100, // max requests per window
    message = 'Too many requests, please try again later.'
  } = options;
  
  return (req, res, next) => {
    const key = req.user?.id || req.ip;
    const now = Date.now();
    
    if (!rateLimitMap.has(key)) {
      rateLimitMap.set(key, { count: 1, startTime: now });
      return next();
    }
    
    const record = rateLimitMap.get(key);
    
    // Reset if window has passed
    if (now - record.startTime > windowMs) {
      rateLimitMap.set(key, { count: 1, startTime: now });
      return next();
    }
    
    // Check if limit exceeded
    if (record.count >= max) {
      return res.status(429).json({
        success: false,
        message,
        code: 'RATE_LIMITED',
        retryAfter: Math.ceil((record.startTime + windowMs - now) / 1000)
      });
    }
    
    record.count++;
    next();
  };
};

/**
 * Permission definitions for fine-grained access control
 */
const PERMISSIONS = {
  // Shelter permissions
  SHELTER_CREATE: ['manager', 'admin'],
  SHELTER_UPDATE: ['manager', 'admin'],
  SHELTER_DELETE: ['manager', 'admin'],
  SHELTER_VIEW: ['user', 'manager', 'rescue_team', 'admin'],
  
  // Food inventory permissions
  FOOD_ADD: ['manager', 'admin'],
  FOOD_UPDATE: ['manager', 'admin'],
  FOOD_DELETE: ['manager', 'admin'],
  FOOD_VIEW: ['manager', 'rescue_team', 'admin'],
  
  // Bed management permissions
  BED_ADD: ['manager', 'admin'],
  BED_UPDATE: ['manager', 'admin'],
  BED_DELETE: ['manager', 'admin'],
  BED_CHECKIN: ['manager', 'admin'],
  BED_CHECKOUT: ['manager', 'admin'],
  BED_VIEW: ['manager', 'rescue_team', 'admin'],
  
  // SOS permissions
  SOS_CREATE: ['user', 'manager', 'rescue_team', 'admin'],
  SOS_ACKNOWLEDGE: ['rescue_team', 'manager', 'admin'],
  SOS_DISPATCH: ['rescue_team', 'manager', 'admin'],
  SOS_RESOLVE: ['rescue_team', 'manager', 'admin'],
  SOS_VIEW_ALL: ['rescue_team', 'manager', 'admin'],
  
  // User management permissions
  USER_CREATE: ['manager', 'admin'],
  USER_UPDATE: ['manager', 'admin'],
  USER_DELETE: ['admin'],
  USER_VIEW_ALL: ['manager', 'admin'],
  
  // Statistics permissions
  STATS_VIEW: ['manager', 'rescue_team', 'admin']
};

/**
 * Check specific permission
 */
const checkPermission = (permission) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.',
        code: 'AUTH_REQUIRED'
      });
    }
    
    const allowedRoles = PERMISSIONS[permission];
    if (!allowedRoles) {
      console.error(`Unknown permission: ${permission}`);
      return res.status(500).json({
        success: false,
        message: 'Internal server error',
        code: 'UNKNOWN_PERMISSION'
      });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Permission required: ${permission}`,
        code: 'PERMISSION_DENIED',
        permission,
        currentRole: req.user.role
      });
    }
    
    next();
  };
};

module.exports = {
  verifyToken,
  checkRole,
  checkOwnerOrRole,
  checkShelterAssignment,
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
  blacklistToken,
  socketAuthMiddleware,
  socketCheckRole,
  rateLimit,
  checkPermission,
  PERMISSIONS,
  JWT_SECRET,
  JWT_REFRESH_SECRET
};
