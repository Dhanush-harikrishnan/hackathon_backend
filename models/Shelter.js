const mongoose = require('mongoose');

// Food item schema for inventory tracking
const foodItemSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    enum: ['grains', 'canned', 'fresh', 'water', 'snacks', 'baby_food', 'medical_nutrition', 'other'],
    default: 'other'
  },
  quantity: {
    type: Number,
    required: true,
    min: 0,
    default: 0
  },
  unit: {
    type: String,
    enum: ['kg', 'liters', 'packets', 'boxes', 'units', 'bottles', 'cans'],
    default: 'units'
  },
  expiryDate: {
    type: Date,
    default: null
  },
  minimumStock: {
    type: Number,
    default: 10,
    min: 0
  },
  lastRestocked: {
    type: Date,
    default: Date.now
  },
  addedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
}, { _id: true, timestamps: true });

// Bed/occupancy tracking schema
const bedSchema = new mongoose.Schema({
  bedNumber: {
    type: String,
    required: true
  },
  section: {
    type: String,
    enum: ['general', 'women', 'children', 'elderly', 'medical', 'isolation'],
    default: 'general'
  },
  status: {
    type: String,
    enum: ['available', 'occupied', 'reserved', 'maintenance', 'out_of_service'],
    default: 'available'
  },
  occupantId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  occupantName: {
    type: String,
    default: null
  },
  checkinTime: {
    type: Date,
    default: null
  },
  checkoutTime: {
    type: Date,
    default: null
  },
  notes: {
    type: String,
    default: ''
  }
}, { _id: true, timestamps: true });

// Activity log for audit trail
const activityLogSchema = new mongoose.Schema({
  action: {
    type: String,
    enum: ['created', 'updated', 'deleted', 'checkin', 'checkout', 'food_added', 'food_removed', 'food_updated', 'status_changed', 'capacity_changed', 'resource_toggled'],
    required: true
  },
  performedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const shelterSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  address: {
    type: String,
    trim: true,
    default: ''
  },
  phone: {
    type: String,
    trim: true,
    default: ''
  },
  email: {
    type: String,
    trim: true,
    default: ''
  },
  status: {
    type: String,
    enum: ['OPEN', 'CLOSED', 'FULL', 'EMERGENCY', 'MAINTENANCE'],
    default: 'OPEN'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium'
  },
  capacity: {
    total: {
      type: Number,
      required: true,
      min: 0
    },
    current: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  // Enhanced bed management
  beds: {
    total: {
      type: Number,
      default: 0,
      min: 0
    },
    available: {
      type: Number,
      default: 0,
      min: 0
    },
    occupied: {
      type: Number,
      default: 0,
      min: 0
    },
    reserved: {
      type: Number,
      default: 0,
      min: 0
    },
    maintenance: {
      type: Number,
      default: 0,
      min: 0
    },
    // Detailed bed list
    bedList: [bedSchema]
  },
  // Enhanced food inventory
  foodInventory: [foodItemSchema],
  // Resource availability flags
  resources: {
    food: {
      type: Boolean,
      default: false
    },
    water: {
      type: Boolean,
      default: false
    },
    medical: {
      type: Boolean,
      default: false
    },
    electricity: {
      type: Boolean,
      default: false
    },
    wifi: {
      type: Boolean,
      default: false
    },
    sanitation: {
      type: Boolean,
      default: false
    },
    childcare: {
      type: Boolean,
      default: false
    },
    petFriendly: {
      type: Boolean,
      default: false
    }
  },
  // Manager assignment
  managedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  // Assigned staff
  assignedStaff: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
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
    }
  },
  // Activity logs for audit
  activityLogs: [activityLogSchema],
  // Statistics
  statistics: {
    totalCheckins: {
      type: Number,
      default: 0
    },
    totalCheckouts: {
      type: Number,
      default: 0
    },
    averageStayDuration: {
      type: Number, // in hours
      default: 0
    },
    peakOccupancy: {
      type: Number,
      default: 0
    },
    lastPeakTime: {
      type: Date,
      default: null
    }
  },
  // Alerts for low stock or capacity
  alerts: [{
    type: {
      type: String,
      enum: ['low_food', 'low_water', 'capacity_warning', 'capacity_critical', 'medical_shortage', 'maintenance_required'],
      required: true
    },
    message: String,
    severity: {
      type: String,
      enum: ['info', 'warning', 'critical'],
      default: 'warning'
    },
    isActive: {
      type: Boolean,
      default: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  lastUpdated: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Create 2dsphere index for geospatial queries
shelterSchema.index({ location: '2dsphere' });
shelterSchema.index({ status: 1 });
shelterSchema.index({ 'beds.available': 1 });
shelterSchema.index({ managedBy: 1 });

// Update lastUpdated on every save
shelterSchema.pre('save', function(next) {
  this.lastUpdated = new Date();
  
  // Auto-calculate bed counts from bedList
  if (this.beds.bedList && this.beds.bedList.length > 0) {
    this.beds.total = this.beds.bedList.length;
    this.beds.available = this.beds.bedList.filter(b => b.status === 'available').length;
    this.beds.occupied = this.beds.bedList.filter(b => b.status === 'occupied').length;
    this.beds.reserved = this.beds.bedList.filter(b => b.status === 'reserved').length;
    this.beds.maintenance = this.beds.bedList.filter(b => b.status === 'maintenance' || b.status === 'out_of_service').length;
  }
  
  // Auto-update status based on capacity
  if (this.capacity.current >= this.capacity.total) {
    this.status = 'FULL';
  }
  
  // Update peak occupancy statistics
  if (this.capacity.current > this.statistics.peakOccupancy) {
    this.statistics.peakOccupancy = this.capacity.current;
    this.statistics.lastPeakTime = new Date();
  }
  
  // Auto-generate alerts
  this.checkAndGenerateAlerts();
  
  next();
});

// Method to check and generate alerts
shelterSchema.methods.checkAndGenerateAlerts = function() {
  const capacityPercentage = (this.capacity.current / this.capacity.total) * 100;
  
  // Clear old auto-generated alerts
  this.alerts = this.alerts.filter(a => !a.isActive || 
    !['capacity_warning', 'capacity_critical', 'low_food'].includes(a.type));
  
  // Capacity alerts
  if (capacityPercentage >= 90) {
    this.alerts.push({
      type: 'capacity_critical',
      message: `Shelter at ${capacityPercentage.toFixed(0)}% capacity`,
      severity: 'critical',
      isActive: true
    });
  } else if (capacityPercentage >= 75) {
    this.alerts.push({
      type: 'capacity_warning',
      message: `Shelter at ${capacityPercentage.toFixed(0)}% capacity`,
      severity: 'warning',
      isActive: true
    });
  }
  
  // Food inventory alerts
  const lowStockItems = this.foodInventory.filter(item => item.quantity <= item.minimumStock);
  if (lowStockItems.length > 0) {
    this.alerts.push({
      type: 'low_food',
      message: `${lowStockItems.length} food item(s) running low`,
      severity: lowStockItems.length > 3 ? 'critical' : 'warning',
      isActive: true
    });
  }
};

// Method to add activity log
shelterSchema.methods.addActivityLog = function(action, userId, details = {}) {
  this.activityLogs.push({
    action,
    performedBy: userId,
    details,
    timestamp: new Date()
  });
  
  // Keep only last 100 logs
  if (this.activityLogs.length > 100) {
    this.activityLogs = this.activityLogs.slice(-100);
  }
};

// Static method to get shelters with low resources
shelterSchema.statics.getSheltersNeedingResupply = async function() {
  return this.find({
    $or: [
      { 'resources.food': false },
      { 'resources.water': false },
      { 'alerts.isActive': true, 'alerts.severity': { $in: ['warning', 'critical'] } }
    ],
    status: { $ne: 'CLOSED' }
  });
};

// Virtual for occupancy percentage
shelterSchema.virtual('occupancyPercentage').get(function() {
  if (this.capacity.total === 0) return 0;
  return Math.round((this.capacity.current / this.capacity.total) * 100);
});

// Virtual for bed availability percentage
shelterSchema.virtual('bedAvailabilityPercentage').get(function() {
  if (this.beds.total === 0) return 100;
  return Math.round((this.beds.available / this.beds.total) * 100);
});

// Include virtuals in JSON
shelterSchema.set('toJSON', { virtuals: true });
shelterSchema.set('toObject', { virtuals: true });

const Shelter = mongoose.model('Shelter', shelterSchema);

module.exports = Shelter;
