const mongoose = require('mongoose');

const shelterSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  status: {
    type: String,
    enum: ['OPEN', 'FULL', 'CLOSED'],
    default: 'OPEN'
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
    }
  },
  location: {
    type: {
      type: String,
      enum: ['Point'],
      required: true
    },
    coordinates: {
      type: [Number],
      required: true
    }
  },
  address: {
    type: String,
    required: true
  },
  phone: {
    type: String
  },
  lastUpdated: {
    type: Date,
    default: Date.now
  },
  managedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
});

// Create geospatial index
shelterSchema.index({ location: '2dsphere' });

// Virtual for occupancy percentage
shelterSchema.virtual('occupancyPercentage').get(function() {
  return (this.capacity.current / this.capacity.total) * 100;
});

// Update lastUpdated on save
shelterSchema.pre('save', function(next) {
  this.lastUpdated = Date.now();
  
  // Auto-update status based on capacity
  if (this.capacity.current >= this.capacity.total) {
    this.status = 'FULL';
  } else if (this.status === 'FULL' && this.capacity.current < this.capacity.total) {
    this.status = 'OPEN';
  }
  
  next();
});

module.exports = mongoose.model('Shelter', shelterSchema);
