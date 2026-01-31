const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    unique: true,
    sparse: true, // Allows null/undefined to not conflict
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['user', 'manager', 'rescue_team', 'admin'],
    default: 'user'
  },
  // Profile information
  profile: {
    firstName: {
      type: String,
      trim: true,
      default: ''
    },
    lastName: {
      type: String,
      trim: true,
      default: ''
    },
    phone: {
      type: String,
      trim: true,
      default: ''
    },
    alternatePhone: {
      type: String,
      trim: true,
      default: ''
    },
    emergencyContact: {
      name: {
        type: String,
        default: ''
      },
      phone: {
        type: String,
        default: ''
      },
      relationship: {
        type: String,
        default: ''
      }
    },
    address: {
      type: String,
      default: ''
    },
    bloodGroup: {
      type: String,
      enum: ['', 'A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'],
      default: ''
    },
    medicalConditions: {
      type: String,
      default: ''
    }
  },
  // For manager role - assigned shelter
  assignedShelterId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Shelter',
    default: null
  },
  // For rescue_team role - assigned area/zone
  assignedZone: {
    type: String,
    default: ''
  },
  // Last known location (for rescue team tracking)
  lastLocation: {
    type: {
      type: String,
      enum: ['Point'],
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      default: [0, 0]
    },
    updatedAt: {
      type: Date,
      default: null
    }
  },
  // Account status
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'pending_verification'],
    default: 'active'
  },
  // For tracking online status
  isOnline: {
    type: Boolean,
    default: false
  },
  lastSeen: {
    type: Date,
    default: null
  },
  // Current socket ID for real-time communication
  socketId: {
    type: String,
    default: null
  },
  // Device tokens for push notifications
  deviceTokens: [{
    token: String,
    platform: {
      type: String,
      enum: ['ios', 'android', 'web'],
      default: 'web'
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  // Password reset
  passwordResetToken: {
    type: String,
    default: null
  },
  passwordResetExpires: {
    type: Date,
    default: null
  },
  // Login history
  loginHistory: [{
    ip: String,
    userAgent: String,
    timestamp: {
      type: Date,
      default: Date.now
    },
    success: {
      type: Boolean,
      default: true
    }
  }],
  // Refresh token for session management
  refreshToken: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

// Index for geospatial queries on last location
userSchema.index({ 'lastLocation': '2dsphere' });
userSchema.index({ role: 1 });
userSchema.index({ status: 1 });
userSchema.index({ assignedShelterId: 1 });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Update last seen
userSchema.methods.updateLastSeen = function() {
  this.lastSeen = new Date();
  this.isOnline = true;
};

// Mark offline
userSchema.methods.markOffline = function() {
  this.isOnline = false;
  this.lastSeen = new Date();
  this.socketId = null;
};

// Add login history
userSchema.methods.addLoginHistory = function(ip, userAgent, success = true) {
  this.loginHistory.push({
    ip,
    userAgent,
    timestamp: new Date(),
    success
  });
  
  // Keep only last 10 login records
  if (this.loginHistory.length > 10) {
    this.loginHistory = this.loginHistory.slice(-10);
  }
};

// Update location
userSchema.methods.updateLocation = function(longitude, latitude) {
  this.lastLocation = {
    type: 'Point',
    coordinates: [longitude, latitude],
    updatedAt: new Date()
  };
};

// Static method to find online rescue team members
userSchema.statics.getOnlineRescueTeam = async function() {
  return this.find({
    role: 'rescue_team',
    isOnline: true,
    status: 'active'
  }).select('-password -refreshToken -loginHistory');
};

// Static method to find available managers
userSchema.statics.getAvailableManagers = async function() {
  return this.find({
    role: 'manager',
    status: 'active'
  }).populate('assignedShelterId', 'name status').select('-password -refreshToken -loginHistory');
};

// Static method to get users by shelter
userSchema.statics.getUsersByShelter = async function(shelterId) {
  return this.find({
    assignedShelterId: shelterId,
    status: 'active'
  }).select('-password -refreshToken -loginHistory');
};

// Remove password and sensitive fields from JSON output
userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  delete obj.refreshToken;
  delete obj.passwordResetToken;
  delete obj.passwordResetExpires;
  delete obj.loginHistory;
  delete obj.deviceTokens;
  return obj;
};

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  if (this.profile.firstName || this.profile.lastName) {
    return `${this.profile.firstName || ''} ${this.profile.lastName || ''}`.trim();
  }
  return this.username;
});

// Include virtuals in JSON
userSchema.set('toJSON', { virtuals: true });
userSchema.set('toObject', { virtuals: true });

const User = mongoose.model('User', userSchema);

module.exports = User;
