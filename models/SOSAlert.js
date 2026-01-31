const mongoose = require('mongoose');

// Response log for tracking rescue operations
const responseLogSchema = new mongoose.Schema({
  action: {
    type: String,
    enum: ['created', 'acknowledged', 'dispatched', 'en_route', 'arrived', 'assisting', 'resolved', 'cancelled', 'escalated', 'transferred'],
    required: true
  },
  performedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  notes: {
    type: String,
    default: ''
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const sosAlertSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  // Contact information (in case user profile is incomplete)
  contactInfo: {
    name: {
      type: String,
      default: ''
    },
    phone: {
      type: String,
      default: ''
    },
    alternatePhone: {
      type: String,
      default: ''
    }
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      required: true,
      default: 'Point'
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: true
    },
    accuracy: {
      type: Number, // in meters
      default: null
    },
    address: {
      type: String, // Reverse geocoded address
      default: ''
    },
    landmark: {
      type: String, // User-provided landmark
      default: ''
    }
  },
  // Emergency type classification
  emergencyType: {
    type: String,
    enum: ['medical', 'fire', 'flood', 'trapped', 'injury', 'evacuation', 'supplies', 'other'],
    default: 'other'
  },
  // Priority level
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'high'
  },
  // Number of people needing help
  peopleCount: {
    adults: {
      type: Number,
      default: 1,
      min: 0
    },
    children: {
      type: Number,
      default: 0,
      min: 0
    },
    elderly: {
      type: Number,
      default: 0,
      min: 0
    },
    injured: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  // Special needs
  specialNeeds: {
    wheelchairAccess: {
      type: Boolean,
      default: false
    },
    medicalEquipment: {
      type: Boolean,
      default: false
    },
    pets: {
      type: Boolean,
      default: false
    },
    infantCare: {
      type: Boolean,
      default: false
    }
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  status: {
    type: String,
    enum: ['PENDING', 'ACKNOWLEDGED', 'DISPATCHED', 'EN_ROUTE', 'ARRIVED', 'ASSISTING', 'RESOLVED', 'CANCELLED', 'ESCALATED'],
    default: 'PENDING'
  },
  // Assigned rescue team member
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  // Assigned shelter for evacuation
  assignedShelter: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Shelter',
    default: null
  },
  details: {
    type: String,
    default: ''
  },
  // Media attachments (URLs)
  attachments: [{
    type: {
      type: String,
      enum: ['image', 'audio', 'video'],
      required: true
    },
    url: {
      type: String,
      required: true
    },
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],
  // Timeline tracking
  acknowledgedAt: {
    type: Date,
    default: null
  },
  acknowledgedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  dispatchedAt: {
    type: Date,
    default: null
  },
  arrivedAt: {
    type: Date,
    default: null
  },
  resolvedAt: {
    type: Date,
    default: null
  },
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  // Resolution details
  resolution: {
    type: {
      type: String,
      enum: ['rescued', 'evacuated', 'medical_provided', 'supplies_delivered', 'false_alarm', 'self_resolved', 'transferred', 'other'],
      default: null
    },
    notes: {
      type: String,
      default: ''
    },
    shelterAssigned: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Shelter',
      default: null
    }
  },
  // Response logs for audit trail
  responseLogs: [responseLogSchema],
  // Estimated response time (in minutes)
  estimatedResponseTime: {
    type: Number,
    default: null
  },
  // Actual response time (in minutes)
  actualResponseTime: {
    type: Number,
    default: null
  }
}, {
  timestamps: true
});

// Create 2dsphere index for geospatial queries on SOS locations
sosAlertSchema.index({ location: '2dsphere' });
sosAlertSchema.index({ status: 1 });
sosAlertSchema.index({ priority: 1 });
sosAlertSchema.index({ assignedTo: 1 });
sosAlertSchema.index({ timestamp: -1 });

// Pre-save middleware
sosAlertSchema.pre('save', function(next) {
  // Calculate actual response time when resolved
  if (this.status === 'RESOLVED' && this.resolvedAt && this.timestamp) {
    this.actualResponseTime = Math.round((this.resolvedAt - this.timestamp) / (1000 * 60));
  }
  
  // Auto-escalate old pending alerts
  if (this.status === 'PENDING') {
    const timeSinceCreation = Date.now() - this.timestamp;
    const thirtyMinutes = 30 * 60 * 1000;
    if (timeSinceCreation > thirtyMinutes && this.priority !== 'critical') {
      this.priority = 'critical';
    }
  }
  
  next();
});

// Method to add response log
sosAlertSchema.methods.addResponseLog = function(action, userId, notes = '') {
  this.responseLogs.push({
    action,
    performedBy: userId,
    notes,
    timestamp: new Date()
  });
};

// Method to update status with logging
sosAlertSchema.methods.updateStatus = function(newStatus, userId, notes = '') {
  const oldStatus = this.status;
  this.status = newStatus;
  
  // Update timestamps based on status
  switch (newStatus) {
    case 'ACKNOWLEDGED':
      if (!this.acknowledgedAt) {
        this.acknowledgedAt = new Date();
        this.acknowledgedBy = userId;
      }
      break;
    case 'DISPATCHED':
      if (!this.dispatchedAt) {
        this.dispatchedAt = new Date();
      }
      break;
    case 'ARRIVED':
      if (!this.arrivedAt) {
        this.arrivedAt = new Date();
      }
      break;
    case 'RESOLVED':
      if (!this.resolvedAt) {
        this.resolvedAt = new Date();
        this.resolvedBy = userId;
      }
      break;
  }
  
  this.addResponseLog(newStatus.toLowerCase(), userId, notes || `Status changed from ${oldStatus} to ${newStatus}`);
};

// Static method to get pending alerts with high priority
sosAlertSchema.statics.getCriticalAlerts = async function() {
  return this.find({
    status: { $in: ['PENDING', 'ACKNOWLEDGED'] },
    priority: { $in: ['high', 'critical'] }
  })
  .populate('userId', 'username')
  .populate('assignedTo', 'username')
  .sort({ priority: -1, timestamp: 1 });
};

// Static method to get alerts assigned to a specific user
sosAlertSchema.statics.getAssignedAlerts = async function(userId) {
  return this.find({
    assignedTo: userId,
    status: { $nin: ['RESOLVED', 'CANCELLED'] }
  })
  .populate('userId', 'username')
  .sort({ priority: -1, timestamp: 1 });
};

// Static method to get response statistics
sosAlertSchema.statics.getResponseStats = async function(startDate, endDate) {
  const match = {
    status: 'RESOLVED',
    resolvedAt: { $exists: true }
  };
  
  if (startDate) match.timestamp = { $gte: startDate };
  if (endDate) match.timestamp = { ...match.timestamp, $lte: endDate };
  
  return this.aggregate([
    { $match: match },
    {
      $group: {
        _id: null,
        totalResolved: { $sum: 1 },
        avgResponseTime: { $avg: '$actualResponseTime' },
        minResponseTime: { $min: '$actualResponseTime' },
        maxResponseTime: { $max: '$actualResponseTime' }
      }
    }
  ]);
};

// Virtual for total people count
sosAlertSchema.virtual('totalPeopleCount').get(function() {
  return (this.peopleCount.adults || 0) + 
         (this.peopleCount.children || 0) + 
         (this.peopleCount.elderly || 0);
});

// Include virtuals in JSON
sosAlertSchema.set('toJSON', { virtuals: true });
sosAlertSchema.set('toObject', { virtuals: true });

const SOSAlert = mongoose.model('SOSAlert', sosAlertSchema);

module.exports = SOSAlert;
