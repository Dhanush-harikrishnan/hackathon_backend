// Seed script for Chennai shelter data
require('dotenv').config();
const mongoose = require('mongoose');
const Shelter = require('./models/Shelter');
const User = require('./models/User');
const SOSAlert = require('./models/SOSAlert');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/saferoute';

// Chennai Shelter Data
const chennaiShelters = [
  {
    name: 'Marina Beach Community Center',
    address: '123 Kamarajar Salai, Marina Beach, Chennai - 600005',
    phone: '+91 44 2536 1234',
    status: 'OPEN',
    capacity: { total: 500, current: 185 },
    resources: { food: true, water: true, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.2824, 13.0499] // Marina Beach
    }
  },
  {
    name: 'T. Nagar Corporation School',
    address: '45 Pondy Bazaar, T. Nagar, Chennai - 600017',
    phone: '+91 44 2434 5678',
    status: 'OPEN',
    capacity: { total: 350, current: 280 },
    resources: { food: true, water: true, medical: false },
    location: {
      type: 'Point',
      coordinates: [80.2339, 13.0418] // T. Nagar
    }
  },
  {
    name: 'Anna Nagar Tower Relief Camp',
    address: '2nd Avenue, Anna Nagar, Chennai - 600040',
    phone: '+91 44 2628 9012',
    status: 'OPEN',
    capacity: { total: 600, current: 125 },
    resources: { food: true, water: true, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.2096, 13.0850] // Anna Nagar
    }
  },
  {
    name: 'Adyar Corporation Higher Secondary School',
    address: '78 Gandhi Nagar, Adyar, Chennai - 600020',
    phone: '+91 44 2442 3456',
    status: 'OPEN',
    capacity: { total: 400, current: 390 },
    resources: { food: true, water: false, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.2565, 13.0012] // Adyar
    }
  },
  {
    name: 'Velachery YMCA Shelter',
    address: '156 100 Feet Road, Velachery, Chennai - 600042',
    phone: '+91 44 2243 7890',
    status: 'FULL',
    capacity: { total: 250, current: 250 },
    resources: { food: true, water: true, medical: false },
    location: {
      type: 'Point',
      coordinates: [80.2207, 12.9815] // Velachery
    }
  },
  {
    name: 'Tambaram Railway Station Camp',
    address: 'Station Road, Tambaram, Chennai - 600045',
    phone: '+91 44 2239 1234',
    status: 'OPEN',
    capacity: { total: 450, current: 210 },
    resources: { food: false, water: true, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.1270, 12.9249] // Tambaram
    }
  },
  {
    name: 'Guindy Industrial Estate Relief Center',
    address: 'SIDCO Industrial Estate, Guindy, Chennai - 600032',
    phone: '+91 44 2234 5678',
    status: 'OPEN',
    capacity: { total: 800, current: 445 },
    resources: { food: true, water: true, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.2129, 13.0067] // Guindy
    }
  },
  {
    name: 'Egmore Museum Grounds',
    address: 'Pantheon Road, Egmore, Chennai - 600008',
    phone: '+91 44 2819 0123',
    status: 'OPEN',
    capacity: { total: 300, current: 75 },
    resources: { food: true, water: true, medical: false },
    location: {
      type: 'Point',
      coordinates: [80.2601, 13.0732] // Egmore
    }
  },
  {
    name: 'Mylapore Sri Kapaleeshwarar Temple Hall',
    address: 'Sannidhi Street, Mylapore, Chennai - 600004',
    phone: '+91 44 2464 7890',
    status: 'OPEN',
    capacity: { total: 200, current: 165 },
    resources: { food: true, water: true, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.2693, 13.0337] // Mylapore
    }
  },
  {
    name: 'Kodambakkam Film City Shelter',
    address: 'Film City Road, Kodambakkam, Chennai - 600024',
    phone: '+91 44 2371 2345',
    status: 'CLOSED',
    capacity: { total: 350, current: 0 },
    resources: { food: false, water: false, medical: false },
    location: {
      type: 'Point',
      coordinates: [80.2245, 13.0524] // Kodambakkam
    }
  },
  {
    name: 'Perambur Railway Workshop Hall',
    address: 'Perambur High Road, Perambur, Chennai - 600011',
    phone: '+91 44 2551 6789',
    status: 'OPEN',
    capacity: { total: 550, current: 320 },
    resources: { food: true, water: true, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.2422, 13.1165] // Perambur
    }
  },
  {
    name: 'Porur Lake Community Center',
    address: 'Mount Poonamallee Road, Porur, Chennai - 600116',
    phone: '+91 44 2476 0123',
    status: 'OPEN',
    capacity: { total: 400, current: 88 },
    resources: { food: true, water: false, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.1569, 13.0382] // Porur
    }
  },
  {
    name: 'Sholinganallur IT Park Relief Camp',
    address: 'OMR Road, Sholinganallur, Chennai - 600119',
    phone: '+91 44 2450 4567',
    status: 'OPEN',
    capacity: { total: 700, current: 235 },
    resources: { food: true, water: true, medical: false },
    location: {
      type: 'Point',
      coordinates: [80.2279, 12.9010] // Sholinganallur
    }
  },
  {
    name: 'Royapettah Government Hospital Annex',
    address: 'Royapettah High Road, Chennai - 600014',
    phone: '+91 44 2811 8901',
    status: 'OPEN',
    capacity: { total: 250, current: 198 },
    resources: { food: false, water: true, medical: true },
    location: {
      type: 'Point',
      coordinates: [80.2614, 13.0540] // Royapettah
    }
  },
  {
    name: 'Besant Nagar Elliot Beach Hall',
    address: 'Elliot Beach Road, Besant Nagar, Chennai - 600090',
    phone: '+91 44 2491 2345',
    status: 'OPEN',
    capacity: { total: 180, current: 45 },
    resources: { food: true, water: true, medical: false },
    location: {
      type: 'Point',
      coordinates: [80.2715, 12.9988] // Besant Nagar
    }
  }
];

// Demo Users
const demoUsers = [
  {
    username: 'admin',
    password: 'admin123',
    role: 'manager'
  },
  {
    username: 'rescue1',
    password: 'rescue123',
    role: 'rescue_team'
  },
  {
    username: 'user1',
    password: 'user123',
    role: 'user'
  },
  {
    username: 'manager_marina',
    password: 'marina123',
    role: 'manager'
  },
  {
    username: 'rescue_chennai',
    password: 'chennai123',
    role: 'rescue_team'
  }
];

// Sample SOS Alerts (pending emergencies)
const sampleSOSAlerts = [
  {
    location: {
      type: 'Point',
      coordinates: [80.2500, 13.0600] // Near Egmore
    },
    status: 'PENDING',
    details: 'Family of 4 stranded on rooftop, water rising',
    timestamp: new Date(Date.now() - 15 * 60000) // 15 mins ago
  },
  {
    location: {
      type: 'Point',
      coordinates: [80.2150, 12.9750] // Near Velachery
    },
    status: 'PENDING',
    details: 'Elderly person needs medical assistance, diabetic',
    timestamp: new Date(Date.now() - 8 * 60000) // 8 mins ago
  },
  {
    location: {
      type: 'Point',
      coordinates: [80.2700, 13.0200] // Near Mylapore
    },
    status: 'PENDING',
    details: 'Pregnant woman needs evacuation',
    timestamp: new Date(Date.now() - 25 * 60000) // 25 mins ago
  },
  {
    location: {
      type: 'Point',
      coordinates: [80.2350, 13.0450] // Near T. Nagar
    },
    status: 'PENDING',
    details: 'Group of 10 stuck in basement parking',
    timestamp: new Date(Date.now() - 3 * 60000) // 3 mins ago
  },
  {
    location: {
      type: 'Point',
      coordinates: [80.2050, 13.0900] // Near Anna Nagar
    },
    status: 'RESOLVED',
    details: 'Children stuck in school building - RESCUED',
    timestamp: new Date(Date.now() - 45 * 60000) // 45 mins ago
  }
];

async function seedDatabase() {
  try {
    console.log('🔗 Connecting to MongoDB...');
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Clear existing data
    console.log('🧹 Clearing existing data...');
    await Shelter.deleteMany({});
    await User.deleteMany({});
    await SOSAlert.deleteMany({});
    console.log('✅ Existing data cleared');

    // Insert shelters
    console.log('🏠 Inserting Chennai shelters...');
    const shelters = await Shelter.insertMany(chennaiShelters);
    console.log(`✅ Inserted ${shelters.length} shelters`);

    // Insert users
    console.log('👤 Creating demo users...');
    for (const userData of demoUsers) {
      const user = new User(userData);
      await user.save();
      console.log(`   ✅ Created user: ${userData.username} (${userData.role})`);
    }

    // Get a user for SOS alerts
    const testUser = await User.findOne({ role: 'user' });
    
    // Insert SOS alerts
    console.log('🚨 Creating sample SOS alerts...');
    for (const alertData of sampleSOSAlerts) {
      const alert = new SOSAlert({
        ...alertData,
        userId: testUser._id
      });
      await alert.save();
    }
    console.log(`✅ Inserted ${sampleSOSAlerts.length} SOS alerts`);

    console.log('\n========================================');
    console.log('🎉 Database seeded successfully!');
    console.log('========================================');
    console.log('\n📋 Demo Credentials:');
    console.log('   Manager:     admin / admin123');
    console.log('   Rescue Team: rescue1 / rescue123');
    console.log('   Public User: user1 / user123');
    console.log('\n🗺️  Location: Chennai, Tamil Nadu, India');
    console.log(`📍 ${shelters.length} Shelters across Chennai`);
    console.log(`🚨 ${sampleSOSAlerts.length} Sample SOS Alerts`);
    console.log('========================================\n');

    process.exit(0);
  } catch (error) {
    console.error('❌ Error seeding database:', error);
    process.exit(1);
  }
}

seedDatabase();
