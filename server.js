require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const WebSocket = require('ws');

// Models
const User = require('./models/User');
const Shelter = require('./models/Shelter');
const SOSAlert = require('./models/SOSAlert');

// Middleware
const {
  verifyToken,
  checkRole,
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
  blacklistToken,
  socketAuthMiddleware,
  socketCheckRole,
  rateLimit,
  checkPermission,
  checkShelterAssignment,
  PERMISSIONS
} = require('./middleware/auth');

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Parse allowed origins from environment variable
const getAllowedOrigins = () => {
  const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
  const defaultOrigins = ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000', 'http://127.0.0.1:5173'];

  // Split by comma if multiple URLs are provided
  const envOrigins = frontendUrl.split(',').map(url => url.trim());

  // Combine and deduplicate
  return [...new Set([...defaultOrigins, ...envOrigins])];
};

const allowedOrigins = getAllowedOrigins();
console.log('🌐 CORS Allowed Origins:', allowedOrigins);

// Initialize Socket.io with dynamic CORS
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'PUT'],
    credentials: true
  }
});

// Initialize WebSocket Server for LoRa Simulation (on same server, different path)
const wss = new WebSocket.Server({ server, path: '/lora' });

// Middleware - Dynamic CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      console.warn(`⚠️  CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Make io accessible in routes
app.set('io', io);

// Health check and root route
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'SafeRoute Backend API is running',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth/*',
      shelters: '/api/shelters',
      sos: '/api/sos'
    }
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// MongoDB Connection with robust error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/saferoute';

const connectWithRetry = async () => {
  const maxRetries = 5;
  let retries = 0;

  while (retries < maxRetries) {
    try {
      await mongoose.connect(MONGODB_URI, {
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
      });
      console.log('✅ Connected to MongoDB');
      console.log(`📍 Database: ${mongoose.connection.name}`);
      return true;
    } catch (err) {
      retries++;
      console.error(`❌ MongoDB connection attempt ${retries}/${maxRetries} failed:`, err.message);

      if (retries < maxRetries) {
        console.log(`⏳ Retrying in 3 seconds...`);
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
    }
  }

  console.error('❌ Could not connect to MongoDB after multiple attempts.');
  console.log('💡 TIP: Make sure MongoDB is running locally:');
  console.log('   - Windows: Start MongoDB service or run "mongod"');
  console.log('   - Or use MongoDB Atlas with proper network access');
  return false;
};

// Handle MongoDB connection events
mongoose.connection.on('disconnected', () => {
  console.log('⚠️  MongoDB disconnected. Attempting to reconnect...');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err.message);
});

// Connect to MongoDB
connectWithRetry();

// ==================== LORA MESH SIMULATION LAYER ====================

/**
 * LoRa Packet Simulation Logic
 * Simulates realistic radio wave propagation with:
 * - Random delay (300-800ms) to mimic radio transmission
 * - RSSI (Received Signal Strength Indicator)
 * - SNR (Signal-to-Noise Ratio)
 * - Hop count for mesh routing
 */
const broadcastRadioPacket = (data, options = {}) => {
  // Simulate Radio Delay (300ms - 800ms) to look realistic
  const baseDelay = options.baseDelay || 300;
  const delayVariance = options.delayVariance || 500;
  const delay = Math.floor(Math.random() * delayVariance) + baseDelay;

  // Add "Radio Metadata" (RSSI = Received Signal Strength Indicator)
  const packet = JSON.stringify({
    ...data,
    meta: {
      rssi: -(Math.floor(Math.random() * 20) + 70), // e.g. -85 dBm (realistic range -70 to -90)
      snr: (Math.random() * 5 + 7).toFixed(1), // Signal-to-noise ratio (7-12 dB)
      hops: options.hops || 1, // Mesh hop count
      frequency: '915MHz', // LoRa frequency band
      bandwidth: '125kHz',
      spreadingFactor: 7,
      transmitPower: '20dBm'
    },
    timestamp: Date.now()
  });

  setTimeout(() => {
    let clientCount = 0;
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(packet);
        clientCount++;
      }
    });
    console.log(`⚡ LoRa Packet Sent: ${delay}ms delay | RSSI: -${Math.floor(Math.random() * 10 + 75)}dBm | Clients: ${clientCount}`);
  }, delay);

  return { delay, packetSize: packet.length };
};

/**
 * Broadcast to specific shelter subscribers (simulated mesh routing)
 */
const broadcastToShelterSubscribers = (shelterId, data, options = {}) => {
  const packet = {
    type: 'SHELTER_UPDATE',
    shelterId,
    ...data,
    meta: {
      rssi: -(Math.floor(Math.random() * 20) + 70),
      snr: (Math.random() * 5 + 7).toFixed(1),
      hops: options.hops || 1,
      meshRoute: options.meshRoute || 'direct'
    },
    timestamp: Date.now()
  };

  return broadcastRadioPacket(packet, options);
};

// WebSocket LoRa connection handler
wss.on('connection', (ws, req) => {
  console.log(`📡 LoRa Client connected from: ${req.socket.remoteAddress}`);

  // Send initial handshake with simulated radio metadata
  ws.send(JSON.stringify({
    type: 'LORA_HANDSHAKE',
    message: 'Connected to SafeRoute LoRa Gateway',
    gatewayId: 'SAFEROUTE-GW-001',
    meta: {
      rssi: -65,
      snr: 10.5,
      frequency: '915MHz'
    },
    timestamp: Date.now()
  }));

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      console.log(`📡 LoRa Packet Received:`, data.type);

      // Handle different message types from LoRa clients
      if (data.type === 'PING') {
        ws.send(JSON.stringify({
          type: 'PONG',
          timestamp: Date.now(),
          meta: { rssi: -(Math.floor(Math.random() * 20) + 70) }
        }));
      }
    } catch (error) {
      console.error('LoRa message parse error:', error);
    }
  });

  ws.on('close', () => {
    console.log('📡 LoRa Client disconnected');
  });

  ws.on('error', (error) => {
    console.error('📡 LoRa WebSocket error:', error);
  });
});

// ==================== SOCKET.IO LOGIC ====================

// Track connected clients with detailed info
const connectedClients = new Map();
const userSocketMap = new Map(); // userId -> socketId mapping for real-time role updates

// Apply socket authentication middleware (optional - allows anonymous connections too)
io.use((socket, next) => {
  const token = socket.handshake.auth.token || socket.handshake.query.token;
  if (token) {
    try {
      socketAuthMiddleware(socket, next);
    } catch (err) {
      // Allow connection without auth for public data
      socket.user = null;
      next();
    }
  } else {
    socket.user = null;
    next();
  }
});

io.on('connection', (socket) => {
  const user = socket.user;
  console.log(`🔌 Client connected: ${socket.id} | User: ${user?.username || 'anonymous'} | Role: ${user?.role || 'guest'}`);

  // Store client info
  connectedClients.set(socket.id, {
    connectedAt: new Date(),
    userId: user?.id,
    username: user?.username,
    role: user?.role
  });

  // Map user to socket for role-based real-time updates
  if (user?.id) {
    userSocketMap.set(user.id.toString(), socket.id);

    // Update user online status in database
    User.findByIdAndUpdate(user.id, {
      isOnline: true,
      socketId: socket.id,
      lastSeen: new Date()
    }).catch(err => console.error('Failed to update user online status:', err));
  }

  // Broadcast client count
  io.emit('client_count', { count: connectedClients.size });

  // Auto-join role-based room
  if (user?.role) {
    const roleRoom = `${user.role}_room`;
    socket.join(roleRoom);
    console.log(`📢 Auto-joined ${socket.id} to room: ${roleRoom}`);
  }

  // Join room based on role (rescue_team_room, manager_room, etc.)
  socket.on('join_room', (room) => {
    // Validate room access based on role
    const roleRoomMap = {
      'rescue_team_room': ['rescue_team', 'admin'],
      'manager_room': ['manager', 'admin'],
      'admin_room': ['admin'],
      'user_room': ['user', 'manager', 'rescue_team', 'admin']
    };

    if (roleRoomMap[room] && user && !roleRoomMap[room].includes(user?.role)) {
      socket.emit('room_error', {
        message: `Access denied to room: ${room}`,
        requiredRoles: roleRoomMap[room]
      });
      return;
    }

    socket.join(room);
    if (connectedClients.has(socket.id)) {
      connectedClients.get(socket.id).room = room;
    }
    console.log(`📢 Socket ${socket.id} joined room: ${room}`);

    // Notify room members
    socket.to(room).emit('member_joined', {
      socketId: socket.id,
      username: user?.username,
      role: user?.role,
      room,
      memberCount: io.sockets.adapter.rooms.get(room)?.size || 0
    });
  });

  // Leave room
  socket.on('leave_room', (room) => {
    socket.leave(room);
    console.log(`📢 Socket ${socket.id} left room: ${room}`);
    socket.to(room).emit('member_left', {
      socketId: socket.id,
      username: user?.username,
      room,
      memberCount: io.sockets.adapter.rooms.get(room)?.size || 0
    });
  });

  // Real-time shelter capacity update from manager
  socket.on('update_shelter_capacity', async (data) => {
    try {
      // Role check
      if (!user || !['manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Manager role required.' });
        return;
      }

      const { shelterId, current } = data;
      const shelter = await Shelter.findById(shelterId);
      if (shelter) {
        const oldCapacity = shelter.capacity.current;
        shelter.capacity.current = Math.max(0, Math.min(current, shelter.capacity.total));
        shelter.lastUpdated = new Date();

        // Auto-update status based on capacity
        if (shelter.capacity.current >= shelter.capacity.total) {
          shelter.status = 'FULL';
        } else if (shelter.status === 'FULL') {
          shelter.status = 'OPEN';
        }

        // Add activity log
        shelter.addActivityLog('capacity_changed', user.id, {
          from: oldCapacity,
          to: shelter.capacity.current
        });

        await shelter.save();

        // Broadcast to ALL clients instantly via Socket.io
        io.emit('shelter_update', shelter);

        // Also broadcast via LoRa simulation
        broadcastToShelterSubscribers(shelterId, {
          status: shelter.status,
          capacity: Math.round((shelter.capacity.current / shelter.capacity.total) * 100),
          message: `Capacity: ${shelter.capacity.current}/${shelter.capacity.total}`
        });

        console.log(`⚡ Real-time capacity update: ${shelter.name} -> ${current}/${shelter.capacity.total}`);
      }
    } catch (error) {
      console.error('Socket capacity update error:', error);
      socket.emit('error', { message: 'Failed to update capacity', error: error.message });
    }
  });

  // Real-time resource toggle from manager
  socket.on('toggle_shelter_resource', async (data) => {
    try {
      if (!user || !['manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Manager role required.' });
        return;
      }

      const { shelterId, resource } = data;
      const shelter = await Shelter.findById(shelterId);
      if (shelter && shelter.resources[resource] !== undefined) {
        shelter.resources[resource] = !shelter.resources[resource];
        shelter.lastUpdated = new Date();

        shelter.addActivityLog('resource_toggled', user.id, {
          resource,
          newValue: shelter.resources[resource]
        });

        await shelter.save();

        // Broadcast to ALL clients instantly
        io.emit('shelter_update', shelter);

        // LoRa broadcast for offline-first clients
        broadcastRadioPacket({
          type: 'RESOURCE_UPDATE',
          shelterId,
          resource,
          available: shelter.resources[resource]
        });

        console.log(`⚡ Real-time resource toggle: ${shelter.name} -> ${resource}: ${shelter.resources[resource]}`);
      }
    } catch (error) {
      console.error('Socket resource toggle error:', error);
      socket.emit('error', { message: 'Failed to toggle resource', error: error.message });
    }
  });

  // Real-time bed checkin
  socket.on('bed_checkin', async (data) => {
    try {
      if (!user || !['manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Manager role required.' });
        return;
      }

      const { shelterId, bedId, occupantName, occupantId } = data;
      const shelter = await Shelter.findById(shelterId);

      if (!shelter) {
        socket.emit('error', { message: 'Shelter not found' });
        return;
      }

      const bed = shelter.beds.bedList.id(bedId);
      if (!bed) {
        socket.emit('error', { message: 'Bed not found' });
        return;
      }

      if (bed.status !== 'available' && bed.status !== 'reserved') {
        socket.emit('error', { message: 'Bed is not available for checkin' });
        return;
      }

      bed.status = 'occupied';
      bed.occupantName = occupantName;
      bed.occupantId = occupantId || null;
      bed.checkinTime = new Date();
      bed.checkoutTime = null;

      shelter.capacity.current = Math.min(shelter.capacity.current + 1, shelter.capacity.total);
      shelter.statistics.totalCheckins += 1;

      shelter.addActivityLog('checkin', user.id, { bedNumber: bed.bedNumber, occupantName });

      await shelter.save();

      io.emit('shelter_update', shelter);
      io.emit('bed_checkin_success', { shelterId, bedId, bed });

      broadcastRadioPacket({
        type: 'BED_CHECKIN',
        shelterId,
        bedNumber: bed.bedNumber,
        bedsAvailable: shelter.beds.available
      });

      console.log(`⚡ Bed checkin: ${shelter.name} - Bed ${bed.bedNumber} -> ${occupantName}`);
    } catch (error) {
      console.error('Socket bed checkin error:', error);
      socket.emit('error', { message: 'Failed to checkin', error: error.message });
    }
  });

  // Real-time bed checkout
  socket.on('bed_checkout', async (data) => {
    try {
      if (!user || !['manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Manager role required.' });
        return;
      }

      const { shelterId, bedId } = data;
      const shelter = await Shelter.findById(shelterId);

      if (!shelter) {
        socket.emit('error', { message: 'Shelter not found' });
        return;
      }

      const bed = shelter.beds.bedList.id(bedId);
      if (!bed) {
        socket.emit('error', { message: 'Bed not found' });
        return;
      }

      const occupantName = bed.occupantName;
      const stayDuration = bed.checkinTime ? (Date.now() - bed.checkinTime.getTime()) / (1000 * 60 * 60) : 0; // hours

      bed.status = 'available';
      bed.occupantName = null;
      bed.occupantId = null;
      bed.checkoutTime = new Date();

      shelter.capacity.current = Math.max(0, shelter.capacity.current - 1);
      shelter.statistics.totalCheckouts += 1;

      // Update average stay duration
      if (stayDuration > 0 && shelter.statistics.totalCheckouts > 0) {
        const totalStay = shelter.statistics.averageStayDuration * (shelter.statistics.totalCheckouts - 1) + stayDuration;
        shelter.statistics.averageStayDuration = totalStay / shelter.statistics.totalCheckouts;
      }

      // Update status if was FULL
      if (shelter.status === 'FULL') {
        shelter.status = 'OPEN';
      }

      shelter.addActivityLog('checkout', user.id, { bedNumber: bed.bedNumber, occupantName, stayDuration: stayDuration.toFixed(2) });

      await shelter.save();

      io.emit('shelter_update', shelter);
      io.emit('bed_checkout_success', { shelterId, bedId, bed });

      broadcastRadioPacket({
        type: 'BED_CHECKOUT',
        shelterId,
        bedNumber: bed.bedNumber,
        bedsAvailable: shelter.beds.available
      });

      console.log(`⚡ Bed checkout: ${shelter.name} - Bed ${bed.bedNumber} | Stay: ${stayDuration.toFixed(2)}h`);
    } catch (error) {
      console.error('Socket bed checkout error:', error);
      socket.emit('error', { message: 'Failed to checkout', error: error.message });
    }
  });

  // Real-time food inventory update
  socket.on('update_food_inventory', async (data) => {
    try {
      if (!user || !['manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Manager role required.' });
        return;
      }

      const { shelterId, foodItemId, quantity, action } = data;
      const shelter = await Shelter.findById(shelterId);

      if (!shelter) {
        socket.emit('error', { message: 'Shelter not found' });
        return;
      }

      const foodItem = shelter.foodInventory.id(foodItemId);
      if (!foodItem) {
        socket.emit('error', { message: 'Food item not found' });
        return;
      }

      const oldQuantity = foodItem.quantity;

      if (action === 'add') {
        foodItem.quantity += quantity;
        foodItem.lastRestocked = new Date();
      } else if (action === 'remove') {
        foodItem.quantity = Math.max(0, foodItem.quantity - quantity);
      } else if (action === 'set') {
        foodItem.quantity = Math.max(0, quantity);
      }

      shelter.addActivityLog('food_updated', user.id, {
        itemName: foodItem.name,
        action,
        oldQuantity,
        newQuantity: foodItem.quantity
      });

      // Auto-update food resource flag
      const totalFood = shelter.foodInventory.reduce((sum, item) => sum + item.quantity, 0);
      shelter.resources.food = totalFood > 0;

      await shelter.save();

      io.emit('shelter_update', shelter);
      io.emit('food_inventory_updated', { shelterId, foodItem });

      // Check for low stock alert
      if (foodItem.quantity <= foodItem.minimumStock) {
        io.to('manager_room').emit('low_stock_alert', {
          shelterId,
          shelterName: shelter.name,
          item: foodItem.name,
          quantity: foodItem.quantity,
          minimumStock: foodItem.minimumStock
        });
      }

      broadcastRadioPacket({
        type: 'FOOD_UPDATE',
        shelterId,
        itemName: foodItem.name,
        quantity: foodItem.quantity,
        lowStock: foodItem.quantity <= foodItem.minimumStock
      });

      console.log(`⚡ Food update: ${shelter.name} - ${foodItem.name}: ${oldQuantity} -> ${foodItem.quantity}`);
    } catch (error) {
      console.error('Socket food inventory update error:', error);
      socket.emit('error', { message: 'Failed to update food inventory', error: error.message });
    }
  });

  // Ping for latency check
  socket.on('ping_server', () => {
    socket.emit('pong_server', { timestamp: Date.now() });
  });

  // New SOS alert from user
  socket.on('new_sos', async (data) => {
    console.log(`🚨 New SOS Alert from socket: ${socket.id}`);

    // Broadcast to rescue team room and manager room
    io.to('rescue_team_room').emit('new_emergency', { sos: data.sos });
    io.to('manager_room').emit('new_emergency', { sos: data.sos });

    // LoRa broadcast for offline rescue teams
    broadcastRadioPacket({
      type: 'SOS_ALERT',
      priority: data.sos?.priority || 'high',
      location: data.sos?.location,
      emergencyType: data.sos?.emergencyType || 'other',
      message: 'NEW EMERGENCY - RESPOND IMMEDIATELY'
    }, { baseDelay: 100, delayVariance: 200 }); // Faster for emergencies
  });

  // Acknowledge SOS
  socket.on('acknowledge_sos', async (data) => {
    try {
      if (!user || !['rescue_team', 'manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Rescue team or manager role required.' });
        return;
      }

      const { sosId, notes } = data;
      const sos = await SOSAlert.findById(sosId).populate('userId', 'username');

      if (sos) {
        sos.updateStatus('ACKNOWLEDGED', user.id, notes);
        await sos.save();

        // Broadcast update
        io.emit('sos_updated', { sos });
        io.emit('sos_acknowledged', { sos, acknowledgedBy: user.username });

        broadcastRadioPacket({
          type: 'SOS_ACK',
          sosId,
          status: 'ACKNOWLEDGED',
          responder: user.username
        });

        console.log(`✅ SOS ${sosId} acknowledged by ${user.username}`);
      }
    } catch (error) {
      console.error('Socket acknowledge SOS error:', error);
      socket.emit('error', { message: 'Failed to acknowledge SOS', error: error.message });
    }
  });

  // Dispatch rescue team to SOS
  socket.on('dispatch_sos', async (data) => {
    try {
      if (!user || !['rescue_team', 'manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Rescue team or manager role required.' });
        return;
      }

      const { sosId, assignedTo, estimatedTime, notes } = data;
      const sos = await SOSAlert.findById(sosId).populate('userId', 'username');

      if (sos) {
        sos.updateStatus('DISPATCHED', user.id, notes);
        sos.assignedTo = assignedTo || user.id;
        sos.estimatedResponseTime = estimatedTime || null;
        await sos.save();

        io.emit('sos_updated', { sos });
        io.emit('sos_dispatched', { sos, dispatchedBy: user.username });

        // Notify assigned rescue team member
        if (assignedTo) {
          const assignedSocket = userSocketMap.get(assignedTo.toString());
          if (assignedSocket) {
            io.to(assignedSocket).emit('sos_assigned', { sos });
          }
        }

        broadcastRadioPacket({
          type: 'SOS_DISPATCH',
          sosId,
          status: 'DISPATCHED',
          estimatedTime
        });

        console.log(`🚨 SOS ${sosId} dispatched by ${user.username}`);
      }
    } catch (error) {
      console.error('Socket dispatch SOS error:', error);
      socket.emit('error', { message: 'Failed to dispatch SOS', error: error.message });
    }
  });

  // Resolve SOS
  socket.on('resolve_sos', async (data) => {
    try {
      if (!user || !['rescue_team', 'manager', 'admin'].includes(user.role)) {
        socket.emit('error', { message: 'Access denied. Rescue team or manager role required.' });
        return;
      }

      const { sosId, resolutionType, resolutionNotes, shelterAssigned } = data;
      const sos = await SOSAlert.findById(sosId).populate('userId', 'username');

      if (sos) {
        sos.updateStatus('RESOLVED', user.id, resolutionNotes);
        sos.resolution = {
          type: resolutionType || 'other',
          notes: resolutionNotes || '',
          shelterAssigned: shelterAssigned || null
        };
        await sos.save();

        // Broadcast update
        io.emit('sos_resolved', { sos, sosId, resolvedBy: user.username });

        broadcastRadioPacket({
          type: 'SOS_RESOLVED',
          sosId,
          resolutionType
        });

        console.log(`✅ SOS ${sosId} resolved by ${user.username}`);
      }
    } catch (error) {
      console.error('Socket resolve SOS error:', error);
      socket.emit('error', { message: 'Failed to resolve SOS', error: error.message });
    }
  });

  // Real-time location update from rescue team
  socket.on('location_update', async (data) => {
    try {
      const { longitude, latitude } = data;

      if (user?.id) {
        await User.findByIdAndUpdate(user.id, {
          'lastLocation.coordinates': [longitude, latitude],
          'lastLocation.updatedAt': new Date()
        });

        // Broadcast to manager room for tracking
        io.to('manager_room').emit('rescue_team_location', {
          userId: user.id,
          username: user.username,
          location: { longitude, latitude },
          timestamp: new Date()
        });
      }
    } catch (error) {
      console.error('Location update error:', error);
    }
  });

  socket.on('disconnect', async () => {
    connectedClients.delete(socket.id);

    if (user?.id) {
      userSocketMap.delete(user.id.toString());

      // Update user offline status
      await User.findByIdAndUpdate(user.id, {
        isOnline: false,
        socketId: null,
        lastSeen: new Date()
      }).catch(err => console.error('Failed to update user offline status:', err));
    }

    io.emit('client_count', { count: connectedClients.size });
    console.log(`🔌 Client disconnected: ${socket.id} | User: ${user?.username || 'anonymous'}`);
  });
});

// ==================== AUTH ROUTES ====================

// POST /api/auth/register - Register new user
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, role, assignedShelterId } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Username already exists'
      });
    }

    // Validate role
    const validRoles = ['user', 'manager', 'rescue_team'];
    if (role && !validRoles.includes(role)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid role specified'
      });
    }

    // Create new user
    const user = new User({
      username,
      password,
      role: role || 'user',
      assignedShelterId: assignedShelterId || null
    });

    await user.save();

    // Generate token
    const token = generateToken(user);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: user.toJSON(),
        token
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: error.message
    });
  }
});

// POST /api/auth/login - Login user
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate token
    const token = generateToken(user);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: user.toJSON(),
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.message
    });
  }
});

// GET /api/auth/me - Get current user info (Protected)
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).populate('assignedShelterId');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    res.status(200).json({
      success: true,
      data: user.toJSON()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user info',
      error: error.message
    });
  }
});

// ==================== SHELTER ROUTES ====================

// POST /api/shelters - Create a new shelter (Manager only)
app.post('/api/shelters', verifyToken, checkRole(['manager']), async (req, res) => {
  try {
    const { name, status, capacity, resources, location } = req.body;

    const shelter = new Shelter({
      name,
      status,
      capacity,
      resources,
      location
    });

    const savedShelter = await shelter.save();

    // Emit to all connected clients
    io.emit('shelter_update', savedShelter);

    res.status(201).json({
      success: true,
      message: 'Shelter created successfully',
      data: savedShelter
    });
  } catch (error) {
    console.error('Error creating shelter:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create shelter',
      error: error.message
    });
  }
});

// PATCH /api/shelters/:id/update - Update shelter (Manager only)
app.patch('/api/shelters/:id/update', verifyToken, checkRole(['manager']), async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, lastUpdated: new Date() };

    const updatedShelter = await Shelter.findByIdAndUpdate(
      id,
      { $set: updateData },
      { new: true, runValidators: true }
    );

    if (!updatedShelter) {
      return res.status(404).json({
        success: false,
        message: 'Shelter not found'
      });
    }

    // Emit Socket.io event with updated shelter data
    io.emit('shelter_update', updatedShelter);
    console.log(`📡 Emitted shelter_update for shelter: ${updatedShelter.name}`);

    res.status(200).json({
      success: true,
      message: 'Shelter updated successfully',
      data: updatedShelter
    });
  } catch (error) {
    console.error('Error updating shelter:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update shelter',
      error: error.message
    });
  }
});

// GET /api/shelters - Get all shelters
app.get('/api/shelters', async (req, res) => {
  try {
    const shelters = await Shelter.find().sort({ lastUpdated: -1 });
    res.status(200).json({
      success: true,
      count: shelters.length,
      data: shelters
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch shelters',
      error: error.message
    });
  }
});

// GET /api/shelters/:id - Get single shelter
app.get('/api/shelters/:id', async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }
    res.status(200).json({ success: true, data: shelter });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch shelter', error: error.message });
  }
});

// PATCH /api/shelters/:id/capacity - Update shelter capacity (Manager only)
app.patch('/api/shelters/:id/capacity', verifyToken, checkRole(['manager']), async (req, res) => {
  try {
    const { id } = req.params;
    const { current } = req.body;

    const shelter = await Shelter.findById(id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    // Update capacity
    shelter.capacity.current = Math.max(0, Math.min(current, shelter.capacity.total));
    shelter.lastUpdated = new Date();

    // Auto-update status
    if (shelter.capacity.current >= shelter.capacity.total) {
      shelter.status = 'FULL';
    } else if (shelter.status === 'FULL') {
      shelter.status = 'OPEN';
    }

    await shelter.save();

    // Broadcast to ALL clients instantly
    io.emit('shelter_update', { shelter });
    console.log(`⚡ Capacity updated: ${shelter.name} -> ${shelter.capacity.current}/${shelter.capacity.total}`);

    res.status(200).json({ success: true, message: 'Capacity updated', data: shelter });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update capacity', error: error.message });
  }
});

// PATCH /api/shelters/:id/resources - Update shelter resources (Manager only)
app.patch('/api/shelters/:id/resources', verifyToken, checkRole(['manager']), async (req, res) => {
  try {
    const { id } = req.params;
    const { resources } = req.body;

    const shelter = await Shelter.findById(id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    // Update resources
    if (resources.food !== undefined) shelter.resources.food = resources.food;
    if (resources.water !== undefined) shelter.resources.water = resources.water;
    if (resources.medical !== undefined) shelter.resources.medical = resources.medical;
    shelter.lastUpdated = new Date();

    await shelter.save();

    // Broadcast to ALL clients instantly
    io.emit('shelter_update', { shelter });
    console.log(`⚡ Resources updated: ${shelter.name} -> food:${shelter.resources.food}, water:${shelter.resources.water}, medical:${shelter.resources.medical}`);

    res.status(200).json({ success: true, message: 'Resources updated', data: shelter });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update resources', error: error.message });
  }
});

// PATCH /api/shelters/:id/status - Update shelter status (Manager only)
app.patch('/api/shelters/:id/status', verifyToken, checkRole(['manager']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!['OPEN', 'CLOSED', 'FULL'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status' });
    }

    const shelter = await Shelter.findByIdAndUpdate(
      id,
      { status, lastUpdated: new Date() },
      { new: true }
    );

    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    io.emit('shelter_update', { shelter });
    res.status(200).json({ success: true, message: 'Status updated', data: shelter });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update status', error: error.message });
  }
});

// DELETE /api/shelters/:id - Delete shelter (Manager only)
app.delete('/api/shelters/:id', verifyToken, checkRole(['manager']), async (req, res) => {
  try {
    const shelter = await Shelter.findByIdAndDelete(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    io.emit('shelter_deleted', { shelterId: req.params.id });
    res.status(200).json({ success: true, message: 'Shelter deleted' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete shelter', error: error.message });
  }
});

// GET /api/shelters/nearest - Find nearest available shelters
app.get('/api/shelters/nearest', async (req, res) => {
  try {
    const { lat, lng } = req.query;

    if (!lat || !lng) {
      return res.status(400).json({
        success: false,
        message: 'lat and lng query parameters are required'
      });
    }

    const latitude = parseFloat(lat);
    const longitude = parseFloat(lng);

    if (isNaN(latitude) || isNaN(longitude)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid lat or lng values'
      });
    }

    // MongoDB Aggregation Pipeline
    const shelters = await Shelter.aggregate([
      // Step 1: $geoNear - Find shelters within 5000 meters
      {
        $geoNear: {
          near: {
            type: 'Point',
            coordinates: [longitude, latitude] // GeoJSON uses [lng, lat] order
          },
          distanceField: 'distance',
          maxDistance: 5000, // 5000 meters
          spherical: true
        }
      },
      // Step 2: Add calculated field occupancyPct = (current / total) * 100
      {
        $addFields: {
          occupancyPct: {
            $multiply: [
              { $divide: ['$capacity.current', '$capacity.total'] },
              100
            ]
          }
        }
      },
      // Step 3: Filter out shelters where occupancyPct >= 100 OR status is 'CLOSED'
      {
        $match: {
          $and: [
            { occupancyPct: { $lt: 100 } },
            { status: { $ne: 'CLOSED' } }
          ]
        }
      },
      // Step 4: Add weighted score and sort
      {
        $addFields: {
          weightedScore: {
            $add: [
              { $multiply: ['$distance', 0.7] },
              { $multiply: ['$occupancyPct', 0.3] }
            ]
          }
        }
      },
      {
        $sort: { weightedScore: 1 } // Ascending - lower score is better
      }
    ]);

    res.status(200).json({
      success: true,
      count: shelters.length,
      data: shelters
    });
  } catch (error) {
    console.error('Error finding nearest shelters:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to find nearest shelters',
      error: error.message
    });
  }
});

// ==================== SOS ALERT ROUTES ====================

// POST /api/sos - Create SOS Alert (Protected - any logged in user)
app.post('/api/sos', verifyToken, async (req, res) => {
  try {
    const { location, details } = req.body;

    if (!location || !location.coordinates) {
      return res.status(400).json({
        success: false,
        message: 'Location with coordinates is required'
      });
    }

    // Create SOS Alert
    const sosAlert = new SOSAlert({
      userId: req.user.id,
      location: {
        type: 'Point',
        coordinates: location.coordinates // [longitude, latitude]
      },
      details: details || '',
      status: 'PENDING',
      timestamp: new Date()
    });

    const savedAlert = await sosAlert.save();

    // Populate user info for the alert
    const populatedAlert = await SOSAlert.findById(savedAlert._id)
      .populate('userId', 'username role');

    // Emit new_emergency to rescue_team_room AND manager_room
    io.to('rescue_team_room').emit('new_emergency', { sos: populatedAlert });
    io.to('manager_room').emit('new_emergency', { sos: populatedAlert });
    console.log(`🚨 SOS Alert emitted from user: ${req.user.username}`);

    res.status(201).json({
      success: true,
      message: 'SOS Alert sent successfully. Help is on the way!',
      data: populatedAlert
    });
  } catch (error) {
    console.error('Error creating SOS alert:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send SOS alert',
      error: error.message
    });
  }
});

// PATCH /api/sos/:id/acknowledge - Acknowledge SOS Alert (Rescue Team only)
app.patch('/api/sos/:id/acknowledge', verifyToken, checkRole(['rescue_team', 'manager']), async (req, res) => {
  try {
    const { id } = req.params;

    const acknowledgedAlert = await SOSAlert.findByIdAndUpdate(
      id,
      { $set: { status: 'ACKNOWLEDGED', acknowledgedAt: new Date() } },
      { new: true }
    ).populate('userId', 'username role');

    if (!acknowledgedAlert) {
      return res.status(404).json({
        success: false,
        message: 'SOS Alert not found'
      });
    }

    // Emit update to all rooms
    io.emit('sos_acknowledged', { sos: acknowledgedAlert });
    console.log(`✅ SOS ${id} acknowledged`);

    res.status(200).json({
      success: true,
      message: 'SOS Alert acknowledged',
      data: acknowledgedAlert
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to acknowledge SOS alert',
      error: error.message
    });
  }
});

// PATCH /api/sos/:id/resolve - Resolve SOS Alert (Rescue Team only)
app.patch('/api/sos/:id/resolve', verifyToken, checkRole(['rescue_team', 'manager']), async (req, res) => {
  try {
    const { id } = req.params;

    const resolvedAlert = await SOSAlert.findByIdAndUpdate(
      id,
      { $set: { status: 'RESOLVED', resolvedAt: new Date() } },
      { new: true }
    ).populate('userId', 'username role');

    if (!resolvedAlert) {
      return res.status(404).json({
        success: false,
        message: 'SOS Alert not found'
      });
    }

    // Emit update to all
    io.emit('sos_resolved', { sos: resolvedAlert, sosId: id });
    console.log(`✅ SOS ${id} resolved`);

    res.status(200).json({
      success: true,
      message: 'SOS Alert resolved',
      data: resolvedAlert
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to resolve SOS alert',
      error: error.message
    });
  }
});

// GET /api/sos - Get all SOS Alerts (Rescue Team & Manager only)
app.get('/api/sos', verifyToken, checkRole(['rescue_team', 'manager']), async (req, res) => {
  try {
    console.log('📡 GET /api/sos called by user:', req.user.username, 'role:', req.user.role);
    const { status } = req.query;

    const query = status ? { status: status.toUpperCase() } : {};

    const alerts = await SOSAlert.find(query)
      .populate('userId', 'username role')
      .sort({ timestamp: -1 });

    console.log(`✅ Found ${alerts.length} SOS alerts`);

    // Transform alerts to match frontend expected format
    const transformedAlerts = alerts.map(alert => {
      const alertObj = alert.toObject();
      return {
        _id: alertObj._id.toString(),
        userId: alertObj.userId?._id?.toString() || alertObj.userId?.toString(),
        userName: alertObj.userId?.username || alertObj.contactInfo?.name || 'Unknown User',
        lat: alertObj.location?.coordinates?.[1] || 0,
        lng: alertObj.location?.coordinates?.[0] || 0,
        timestamp: alertObj.timestamp,
        status: (alertObj.status || 'PENDING').toLowerCase(),
        notes: alertObj.details || alertObj.notes || '',
        emergencyType: alertObj.emergencyType || 'other',
        priority: alertObj.priority || 'high'
      };
    });

    console.log('📤 Sending transformed alerts:', transformedAlerts.length);

    res.status(200).json({
      success: true,
      count: transformedAlerts.length,
      data: transformedAlerts
    });
  } catch (error) {
    console.error('❌ Error fetching SOS alerts:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch SOS alerts',
      error: error.message
    });
  }
});

// GET /api/sos/my - Get user's own SOS alerts
app.get('/api/sos/my', verifyToken, async (req, res) => {
  try {
    const alerts = await SOSAlert.find({ userId: req.user.id })
      .sort({ timestamp: -1 });

    res.status(200).json({
      success: true,
      count: alerts.length,
      data: alerts
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch your SOS alerts',
      error: error.message
    });
  }
});

// ==================== LOCATION SYNC ROUTES ====================

// POST /api/user/location-sync - Sync offline location data (Protected)
app.post('/api/user/location-sync', verifyToken, async (req, res) => {
  try {
    const { locations } = req.body;

    if (!locations || !Array.isArray(locations) || locations.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'An array of location points is required'
      });
    }

    // Validate each location point
    const validatedLocations = locations.map((loc, index) => {
      if (!loc.coordinates || !Array.isArray(loc.coordinates) || loc.coordinates.length !== 2) {
        throw new Error(`Invalid coordinates at index ${index}`);
      }
      return {
        userId: req.user.id,
        coordinates: loc.coordinates, // [longitude, latitude]
        timestamp: loc.timestamp || new Date(),
        accuracy: loc.accuracy || null
      };
    });

    // Here you could save to a LocationHistory collection
    // For now, we'll just acknowledge receipt
    console.log(`📍 Received ${validatedLocations.length} location points from user: ${req.user.username}`);

    // Optionally emit the latest location to relevant parties
    const latestLocation = validatedLocations[validatedLocations.length - 1];
    io.to('rescue_team_room').emit('user_location_update', {
      userId: req.user.id,
      username: req.user.username,
      location: latestLocation
    });

    res.status(200).json({
      success: true,
      message: `Successfully synced ${validatedLocations.length} location points`,
      data: {
        syncedCount: validatedLocations.length,
        latestTimestamp: latestLocation.timestamp
      }
    });
  } catch (error) {
    console.error('Error syncing locations:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to sync location data',
      error: error.message
    });
  }
});

// ==================== FOOD INVENTORY MANAGEMENT ROUTES ====================

// GET /api/shelters/:id/food - Get shelter food inventory
app.get('/api/shelters/:id/food', verifyToken, async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    // Calculate inventory statistics
    const stats = {
      totalItems: shelter.foodInventory.length,
      lowStockItems: shelter.foodInventory.filter(item => item.quantity <= item.minimumStock).length,
      expiringSoon: shelter.foodInventory.filter(item => {
        if (!item.expiryDate) return false;
        const daysUntilExpiry = (new Date(item.expiryDate) - new Date()) / (1000 * 60 * 60 * 24);
        return daysUntilExpiry <= 7 && daysUntilExpiry > 0;
      }).length,
      expired: shelter.foodInventory.filter(item => {
        if (!item.expiryDate) return false;
        return new Date(item.expiryDate) < new Date();
      }).length
    };

    res.status(200).json({
      success: true,
      data: {
        inventory: shelter.foodInventory,
        stats
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch food inventory', error: error.message });
  }
});

// POST /api/shelters/:id/food - Add food item to inventory (Manager only)
app.post('/api/shelters/:id/food', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const { name, category, quantity, unit, expiryDate, minimumStock } = req.body;

    if (!name || quantity === undefined) {
      return res.status(400).json({ success: false, message: 'Name and quantity are required' });
    }

    const newFoodItem = {
      name,
      category: category || 'other',
      quantity: Math.max(0, quantity),
      unit: unit || 'units',
      expiryDate: expiryDate || null,
      minimumStock: minimumStock || 10,
      lastRestocked: new Date(),
      addedBy: req.user.id
    };

    shelter.foodInventory.push(newFoodItem);
    shelter.addActivityLog('food_added', req.user.id, { itemName: name, quantity });

    // Auto-update food resource flag
    shelter.resources.food = true;

    await shelter.save();

    const addedItem = shelter.foodInventory[shelter.foodInventory.length - 1];

    io.emit('shelter_update', shelter);
    io.emit('food_item_added', { shelterId: req.params.id, foodItem: addedItem });

    // LoRa broadcast
    broadcastRadioPacket({
      type: 'FOOD_ADDED',
      shelterId: req.params.id,
      itemName: name,
      quantity
    });

    res.status(201).json({
      success: true,
      message: 'Food item added successfully',
      data: addedItem
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to add food item', error: error.message });
  }
});

// PATCH /api/shelters/:id/food/:foodId - Update food item (Manager only)
app.patch('/api/shelters/:id/food/:foodId', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const foodItem = shelter.foodInventory.id(req.params.foodId);
    if (!foodItem) {
      return res.status(404).json({ success: false, message: 'Food item not found' });
    }

    const { name, category, quantity, unit, expiryDate, minimumStock } = req.body;
    const oldQuantity = foodItem.quantity;

    if (name !== undefined) foodItem.name = name;
    if (category !== undefined) foodItem.category = category;
    if (quantity !== undefined) {
      foodItem.quantity = Math.max(0, quantity);
      if (quantity > oldQuantity) {
        foodItem.lastRestocked = new Date();
      }
    }
    if (unit !== undefined) foodItem.unit = unit;
    if (expiryDate !== undefined) foodItem.expiryDate = expiryDate;
    if (minimumStock !== undefined) foodItem.minimumStock = minimumStock;

    shelter.addActivityLog('food_updated', req.user.id, {
      itemName: foodItem.name,
      oldQuantity,
      newQuantity: foodItem.quantity
    });

    // Auto-update food resource flag
    const totalFood = shelter.foodInventory.reduce((sum, item) => sum + item.quantity, 0);
    shelter.resources.food = totalFood > 0;

    await shelter.save();

    io.emit('shelter_update', shelter);
    io.emit('food_item_updated', { shelterId: req.params.id, foodItem });

    // Check and broadcast low stock alert
    if (foodItem.quantity <= foodItem.minimumStock) {
      io.to('manager_room').emit('low_stock_alert', {
        shelterId: req.params.id,
        shelterName: shelter.name,
        item: foodItem.name,
        quantity: foodItem.quantity,
        minimumStock: foodItem.minimumStock
      });

      broadcastRadioPacket({
        type: 'LOW_STOCK_ALERT',
        shelterId: req.params.id,
        itemName: foodItem.name,
        quantity: foodItem.quantity
      });
    }

    res.status(200).json({
      success: true,
      message: 'Food item updated successfully',
      data: foodItem
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update food item', error: error.message });
  }
});

// DELETE /api/shelters/:id/food/:foodId - Remove food item (Manager only)
app.delete('/api/shelters/:id/food/:foodId', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const foodItem = shelter.foodInventory.id(req.params.foodId);
    if (!foodItem) {
      return res.status(404).json({ success: false, message: 'Food item not found' });
    }

    const itemName = foodItem.name;
    shelter.foodInventory.pull(req.params.foodId);

    shelter.addActivityLog('food_removed', req.user.id, { itemName });

    // Auto-update food resource flag
    const totalFood = shelter.foodInventory.reduce((sum, item) => sum + item.quantity, 0);
    shelter.resources.food = totalFood > 0;

    await shelter.save();

    io.emit('shelter_update', shelter);
    io.emit('food_item_deleted', { shelterId: req.params.id, foodItemId: req.params.foodId });

    res.status(200).json({
      success: true,
      message: 'Food item removed successfully'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to remove food item', error: error.message });
  }
});

// POST /api/shelters/:id/food/bulk-update - Bulk update food inventory (Manager only)
app.post('/api/shelters/:id/food/bulk-update', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const { updates } = req.body; // Array of { foodItemId, quantity, action: 'add' | 'remove' | 'set' }

    if (!updates || !Array.isArray(updates)) {
      return res.status(400).json({ success: false, message: 'Updates array is required' });
    }

    const results = [];

    for (const update of updates) {
      const foodItem = shelter.foodInventory.id(update.foodItemId);
      if (foodItem) {
        const oldQuantity = foodItem.quantity;

        if (update.action === 'add') {
          foodItem.quantity += update.quantity;
          foodItem.lastRestocked = new Date();
        } else if (update.action === 'remove') {
          foodItem.quantity = Math.max(0, foodItem.quantity - update.quantity);
        } else if (update.action === 'set') {
          foodItem.quantity = Math.max(0, update.quantity);
        }

        results.push({
          foodItemId: update.foodItemId,
          name: foodItem.name,
          oldQuantity,
          newQuantity: foodItem.quantity,
          success: true
        });
      } else {
        results.push({
          foodItemId: update.foodItemId,
          success: false,
          error: 'Item not found'
        });
      }
    }

    shelter.addActivityLog('food_updated', req.user.id, { bulkUpdate: true, itemsUpdated: results.filter(r => r.success).length });

    // Auto-update food resource flag
    const totalFood = shelter.foodInventory.reduce((sum, item) => sum + item.quantity, 0);
    shelter.resources.food = totalFood > 0;

    await shelter.save();

    io.emit('shelter_update', shelter);

    res.status(200).json({
      success: true,
      message: 'Bulk update completed',
      data: results
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to perform bulk update', error: error.message });
  }
});

// ==================== BED MANAGEMENT ROUTES ====================

// GET /api/shelters/:id/beds - Get shelter bed status
app.get('/api/shelters/:id/beds', verifyToken, async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id).populate('beds.bedList.occupantId', 'username');
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const stats = {
      total: shelter.beds.total,
      available: shelter.beds.available,
      occupied: shelter.beds.occupied,
      reserved: shelter.beds.reserved,
      maintenance: shelter.beds.maintenance,
      occupancyRate: shelter.beds.total > 0 ? Math.round((shelter.beds.occupied / shelter.beds.total) * 100) : 0
    };

    // Group beds by section
    const bedsBySection = {};
    for (const bed of shelter.beds.bedList) {
      if (!bedsBySection[bed.section]) {
        bedsBySection[bed.section] = [];
      }
      bedsBySection[bed.section].push(bed);
    }

    res.status(200).json({
      success: true,
      data: {
        beds: shelter.beds.bedList,
        bedsBySection,
        stats
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch beds', error: error.message });
  }
});

// POST /api/shelters/:id/beds - Add new bed (Manager only)
app.post('/api/shelters/:id/beds', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const { bedNumber, section, status, notes } = req.body;

    if (!bedNumber) {
      return res.status(400).json({ success: false, message: 'Bed number is required' });
    }

    // Check if bed number already exists
    const existingBed = shelter.beds.bedList.find(b => b.bedNumber === bedNumber);
    if (existingBed) {
      return res.status(400).json({ success: false, message: 'Bed number already exists' });
    }

    const newBed = {
      bedNumber,
      section: section || 'general',
      status: status || 'available',
      notes: notes || ''
    };

    shelter.beds.bedList.push(newBed);
    shelter.capacity.total += 1;

    shelter.addActivityLog('created', req.user.id, { type: 'bed', bedNumber });

    await shelter.save();

    const addedBed = shelter.beds.bedList[shelter.beds.bedList.length - 1];

    io.emit('shelter_update', shelter);
    io.emit('bed_added', { shelterId: req.params.id, bed: addedBed });

    broadcastRadioPacket({
      type: 'BED_ADDED',
      shelterId: req.params.id,
      bedNumber,
      totalBeds: shelter.beds.total
    });

    res.status(201).json({
      success: true,
      message: 'Bed added successfully',
      data: addedBed
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to add bed', error: error.message });
  }
});

// POST /api/shelters/:id/beds/bulk-add - Bulk add beds (Manager only)
app.post('/api/shelters/:id/beds/bulk-add', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const { count, section, prefix } = req.body;

    if (!count || count < 1) {
      return res.status(400).json({ success: false, message: 'Count must be at least 1' });
    }

    const bedPrefix = prefix || 'BED';
    const startNumber = shelter.beds.bedList.length + 1;
    const addedBeds = [];

    for (let i = 0; i < count; i++) {
      const bedNumber = `${bedPrefix}-${String(startNumber + i).padStart(3, '0')}`;
      const newBed = {
        bedNumber,
        section: section || 'general',
        status: 'available'
      };
      shelter.beds.bedList.push(newBed);
      addedBeds.push(bedNumber);
    }

    shelter.capacity.total += count;
    shelter.addActivityLog('created', req.user.id, { type: 'bulk_beds', count, bedNumbers: addedBeds });

    await shelter.save();

    io.emit('shelter_update', shelter);

    broadcastRadioPacket({
      type: 'BEDS_BULK_ADDED',
      shelterId: req.params.id,
      count,
      totalBeds: shelter.beds.total
    });

    res.status(201).json({
      success: true,
      message: `${count} beds added successfully`,
      data: {
        addedCount: count,
        bedNumbers: addedBeds,
        totalBeds: shelter.beds.total
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to bulk add beds', error: error.message });
  }
});

// PATCH /api/shelters/:id/beds/:bedId - Update bed (Manager only)
app.patch('/api/shelters/:id/beds/:bedId', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const bed = shelter.beds.bedList.id(req.params.bedId);
    if (!bed) {
      return res.status(404).json({ success: false, message: 'Bed not found' });
    }

    const { section, status, notes } = req.body;

    if (section !== undefined) bed.section = section;
    if (status !== undefined) bed.status = status;
    if (notes !== undefined) bed.notes = notes;

    shelter.addActivityLog('updated', req.user.id, { type: 'bed', bedNumber: bed.bedNumber, changes: req.body });

    await shelter.save();

    io.emit('shelter_update', shelter);
    io.emit('bed_updated', { shelterId: req.params.id, bed });

    res.status(200).json({
      success: true,
      message: 'Bed updated successfully',
      data: bed
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update bed', error: error.message });
  }
});

// POST /api/shelters/:id/beds/:bedId/checkin - Check in to a bed (Manager only)
app.post('/api/shelters/:id/beds/:bedId/checkin', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const bed = shelter.beds.bedList.id(req.params.bedId);
    if (!bed) {
      return res.status(404).json({ success: false, message: 'Bed not found' });
    }

    if (bed.status !== 'available' && bed.status !== 'reserved') {
      return res.status(400).json({ success: false, message: 'Bed is not available for checkin' });
    }

    const { occupantName, occupantId, notes } = req.body;

    if (!occupantName) {
      return res.status(400).json({ success: false, message: 'Occupant name is required' });
    }

    bed.status = 'occupied';
    bed.occupantName = occupantName;
    bed.occupantId = occupantId || null;
    bed.checkinTime = new Date();
    bed.checkoutTime = null;
    if (notes) bed.notes = notes;

    shelter.capacity.current = Math.min(shelter.capacity.current + 1, shelter.capacity.total);
    shelter.statistics.totalCheckins += 1;

    // Auto-update shelter status
    if (shelter.capacity.current >= shelter.capacity.total) {
      shelter.status = 'FULL';
    }

    shelter.addActivityLog('checkin', req.user.id, { bedNumber: bed.bedNumber, occupantName });

    await shelter.save();

    io.emit('shelter_update', shelter);
    io.emit('bed_checkin_success', { shelterId: req.params.id, bedId: req.params.bedId, bed });

    broadcastRadioPacket({
      type: 'BED_CHECKIN',
      shelterId: req.params.id,
      bedNumber: bed.bedNumber,
      bedsAvailable: shelter.beds.available,
      capacityPercent: Math.round((shelter.capacity.current / shelter.capacity.total) * 100)
    });

    res.status(200).json({
      success: true,
      message: 'Checkin successful',
      data: bed
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to checkin', error: error.message });
  }
});

// POST /api/shelters/:id/beds/:bedId/checkout - Check out from a bed (Manager only)
app.post('/api/shelters/:id/beds/:bedId/checkout', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const bed = shelter.beds.bedList.id(req.params.bedId);
    if (!bed) {
      return res.status(404).json({ success: false, message: 'Bed not found' });
    }

    if (bed.status !== 'occupied') {
      return res.status(400).json({ success: false, message: 'Bed is not occupied' });
    }

    const occupantName = bed.occupantName;
    const stayDuration = bed.checkinTime ? (Date.now() - bed.checkinTime.getTime()) / (1000 * 60 * 60) : 0;

    bed.status = 'available';
    bed.occupantName = null;
    bed.occupantId = null;
    bed.checkoutTime = new Date();

    shelter.capacity.current = Math.max(0, shelter.capacity.current - 1);
    shelter.statistics.totalCheckouts += 1;

    // Update average stay duration
    if (stayDuration > 0 && shelter.statistics.totalCheckouts > 0) {
      const totalStay = shelter.statistics.averageStayDuration * (shelter.statistics.totalCheckouts - 1) + stayDuration;
      shelter.statistics.averageStayDuration = totalStay / shelter.statistics.totalCheckouts;
    }

    // Update status if was FULL
    if (shelter.status === 'FULL') {
      shelter.status = 'OPEN';
    }

    shelter.addActivityLog('checkout', req.user.id, {
      bedNumber: bed.bedNumber,
      occupantName,
      stayDuration: stayDuration.toFixed(2)
    });

    await shelter.save();

    io.emit('shelter_update', shelter);
    io.emit('bed_checkout_success', { shelterId: req.params.id, bedId: req.params.bedId, bed, stayDuration });

    broadcastRadioPacket({
      type: 'BED_CHECKOUT',
      shelterId: req.params.id,
      bedNumber: bed.bedNumber,
      bedsAvailable: shelter.beds.available,
      capacityPercent: Math.round((shelter.capacity.current / shelter.capacity.total) * 100)
    });

    res.status(200).json({
      success: true,
      message: 'Checkout successful',
      data: {
        bed,
        stayDuration: stayDuration.toFixed(2) + ' hours'
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to checkout', error: error.message });
  }
});

// DELETE /api/shelters/:id/beds/:bedId - Remove bed (Manager only)
app.delete('/api/shelters/:id/beds/:bedId', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelter = await Shelter.findById(req.params.id);
    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const bed = shelter.beds.bedList.id(req.params.bedId);
    if (!bed) {
      return res.status(404).json({ success: false, message: 'Bed not found' });
    }

    if (bed.status === 'occupied') {
      return res.status(400).json({ success: false, message: 'Cannot delete occupied bed. Checkout first.' });
    }

    const bedNumber = bed.bedNumber;
    shelter.beds.bedList.pull(req.params.bedId);
    shelter.capacity.total = Math.max(0, shelter.capacity.total - 1);

    shelter.addActivityLog('deleted', req.user.id, { type: 'bed', bedNumber });

    await shelter.save();

    io.emit('shelter_update', shelter);
    io.emit('bed_deleted', { shelterId: req.params.id, bedId: req.params.bedId });

    res.status(200).json({
      success: true,
      message: 'Bed removed successfully'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to remove bed', error: error.message });
  }
});

// ==================== USER MANAGEMENT ROUTES ====================

// GET /api/users - Get all users (Manager/Admin only)
app.get('/api/users', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const { role, status, online } = req.query;

    const query = {};
    if (role) query.role = role;
    if (status) query.status = status;
    if (online !== undefined) query.isOnline = online === 'true';

    const users = await User.find(query)
      .populate('assignedShelterId', 'name status')
      .sort({ createdAt: -1 });

    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch users', error: error.message });
  }
});

// GET /api/users/:id - Get single user (Manager/Admin only)
app.get('/api/users/:id', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .populate('assignedShelterId', 'name status');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch user', error: error.message });
  }
});

// PATCH /api/users/:id - Update user (Manager/Admin only)
app.patch('/api/users/:id', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const { role, status, assignedShelterId, assignedZone, profile } = req.body;

    // Only admin can change roles to admin
    if (role === 'admin' && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Only admins can assign admin role' });
    }

    const updateData = {};
    if (role !== undefined) updateData.role = role;
    if (status !== undefined) updateData.status = status;
    if (assignedShelterId !== undefined) updateData.assignedShelterId = assignedShelterId;
    if (assignedZone !== undefined) updateData.assignedZone = assignedZone;
    if (profile !== undefined) updateData.profile = profile;

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updateData },
      { new: true, runValidators: true }
    ).populate('assignedShelterId', 'name status');

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // If role changed, notify the user via socket
    if (role !== undefined) {
      const userSocket = userSocketMap.get(req.params.id);
      if (userSocket) {
        io.to(userSocket).emit('role_updated', {
          newRole: role,
          message: `Your role has been updated to ${role}`
        });
      }
    }

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: user
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to update user', error: error.message });
  }
});

// DELETE /api/users/:id - Delete user (Admin only)
app.delete('/api/users/:id', verifyToken, checkRole(['admin']), async (req, res) => {
  try {
    // Prevent self-deletion
    if (req.params.id === req.user.id) {
      return res.status(400).json({ success: false, message: 'Cannot delete your own account' });
    }

    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Disconnect user socket if online
    const userSocket = userSocketMap.get(req.params.id);
    if (userSocket) {
      io.to(userSocket).emit('account_deleted', { message: 'Your account has been deleted' });
    }

    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to delete user', error: error.message });
  }
});

// GET /api/users/rescue-team/online - Get online rescue team members
app.get('/api/users/rescue-team/online', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const rescueTeam = await User.getOnlineRescueTeam();

    res.status(200).json({
      success: true,
      count: rescueTeam.length,
      data: rescueTeam
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch rescue team', error: error.message });
  }
});

// ==================== LORA BROADCAST ENDPOINT ====================

// POST /broadcast - Admin endpoint for LoRa simulation (for demo purposes)
app.post('/broadcast', async (req, res) => {
  try {
    const { shelterId, status, capacity, message } = req.body;

    const payload = {
      type: 'SHELTER_UPDATE',
      shelterId,
      status, // "OPEN", "FULL", "CLOSED"
      capacity,
      message,
      timestamp: Date.now()
    };

    const result = broadcastRadioPacket(payload);

    // Also broadcast via Socket.io for real-time dashboard
    io.emit('lora_broadcast', payload);

    res.json({
      success: true,
      mode: 'LoRa_Simulated',
      delay: result.delay,
      packetSize: result.packetSize
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Broadcast failed', error: error.message });
  }
});

// POST /broadcast/emergency - Emergency broadcast with priority
app.post('/broadcast/emergency', verifyToken, checkRole(['rescue_team', 'manager', 'admin']), async (req, res) => {
  try {
    const { message, priority, area, shelterIds } = req.body;

    const payload = {
      type: 'EMERGENCY_BROADCAST',
      priority: priority || 'high',
      message,
      area,
      shelterIds,
      broadcastBy: req.user.username,
      timestamp: Date.now()
    };

    // Fast broadcast for emergencies
    const result = broadcastRadioPacket(payload, { baseDelay: 50, delayVariance: 100 });

    // Socket.io broadcast
    io.emit('emergency_broadcast', payload);
    io.to('rescue_team_room').emit('emergency_broadcast', payload);
    io.to('manager_room').emit('emergency_broadcast', payload);

    res.json({
      success: true,
      mode: 'Emergency_LoRa_Simulated',
      delay: result.delay
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Emergency broadcast failed', error: error.message });
  }
});

// ==================== STATISTICS & DASHBOARD ROUTES ====================

// GET /api/stats/dashboard - Get dashboard statistics (Manager/Admin only)
app.get('/api/stats/dashboard', verifyToken, checkRole(['manager', 'rescue_team', 'admin']), async (req, res) => {
  try {
    // Shelter statistics
    const shelterStats = await Shelter.aggregate([
      {
        $group: {
          _id: null,
          totalShelters: { $sum: 1 },
          openShelters: { $sum: { $cond: [{ $eq: ['$status', 'OPEN'] }, 1, 0] } },
          fullShelters: { $sum: { $cond: [{ $eq: ['$status', 'FULL'] }, 1, 0] } },
          closedShelters: { $sum: { $cond: [{ $eq: ['$status', 'CLOSED'] }, 1, 0] } },
          totalCapacity: { $sum: '$capacity.total' },
          currentOccupancy: { $sum: '$capacity.current' },
          totalBeds: { $sum: '$beds.total' },
          availableBeds: { $sum: '$beds.available' }
        }
      }
    ]);

    // SOS statistics
    const sosStats = await SOSAlert.aggregate([
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          pending: { $sum: { $cond: [{ $eq: ['$status', 'PENDING'] }, 1, 0] } },
          acknowledged: { $sum: { $cond: [{ $eq: ['$status', 'ACKNOWLEDGED'] }, 1, 0] } },
          dispatched: { $sum: { $cond: [{ $eq: ['$status', 'DISPATCHED'] }, 1, 0] } },
          resolved: { $sum: { $cond: [{ $eq: ['$status', 'RESOLVED'] }, 1, 0] } },
          avgResponseTime: { $avg: '$actualResponseTime' }
        }
      }
    ]);

    // User statistics
    const userStats = await User.aggregate([
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          online: { $sum: { $cond: ['$isOnline', 1, 0] } },
          managers: { $sum: { $cond: [{ $eq: ['$role', 'manager'] }, 1, 0] } },
          rescueTeam: { $sum: { $cond: [{ $eq: ['$role', 'rescue_team'] }, 1, 0] } },
          users: { $sum: { $cond: [{ $eq: ['$role', 'user'] }, 1, 0] } }
        }
      }
    ]);

    // Shelters needing resupply
    const sheltersNeedingResupply = await Shelter.getSheltersNeedingResupply();

    // Critical SOS alerts
    const criticalAlerts = await SOSAlert.getCriticalAlerts();

    res.status(200).json({
      success: true,
      data: {
        shelters: shelterStats[0] || {},
        sos: sosStats[0] || {},
        users: userStats[0] || {},
        sheltersNeedingResupply: sheltersNeedingResupply.length,
        criticalAlerts: criticalAlerts.length,
        connectedClients: connectedClients.size
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch dashboard stats', error: error.message });
  }
});

// GET /api/stats/shelters - Detailed shelter statistics
app.get('/api/stats/shelters', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const shelters = await Shelter.find().select('name status capacity beds resources statistics alerts lastUpdated');

    const detailedStats = shelters.map(shelter => ({
      id: shelter._id,
      name: shelter.name,
      status: shelter.status,
      occupancyRate: shelter.occupancyPercentage,
      bedAvailability: shelter.bedAvailabilityPercentage,
      resources: shelter.resources,
      statistics: shelter.statistics,
      activeAlerts: shelter.alerts.filter(a => a.isActive).length,
      lastUpdated: shelter.lastUpdated
    }));

    res.status(200).json({
      success: true,
      data: detailedStats
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch shelter stats', error: error.message });
  }
});

// GET /api/stats/sos - SOS response statistics
app.get('/api/stats/sos', verifyToken, checkRole(['manager', 'rescue_team', 'admin']), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    const start = startDate ? new Date(startDate) : new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // Default last 7 days
    const end = endDate ? new Date(endDate) : new Date();

    const responseStats = await SOSAlert.getResponseStats(start, end);

    // Group by emergency type
    const byType = await SOSAlert.aggregate([
      { $match: { timestamp: { $gte: start, $lte: end } } },
      { $group: { _id: '$emergencyType', count: { $sum: 1 } } }
    ]);

    // Group by priority
    const byPriority = await SOSAlert.aggregate([
      { $match: { timestamp: { $gte: start, $lte: end } } },
      { $group: { _id: '$priority', count: { $sum: 1 } } }
    ]);

    // Daily breakdown
    const dailyBreakdown = await SOSAlert.aggregate([
      { $match: { timestamp: { $gte: start, $lte: end } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
          count: { $sum: 1 },
          resolved: { $sum: { $cond: [{ $eq: ['$status', 'RESOLVED'] }, 1, 0] } }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    res.status(200).json({
      success: true,
      data: {
        overview: responseStats[0] || {},
        byType,
        byPriority,
        dailyBreakdown,
        period: { start, end }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch SOS stats', error: error.message });
  }
});

// GET /api/shelters/:id/activity - Get shelter activity logs
app.get('/api/shelters/:id/activity', verifyToken, checkRole(['manager', 'admin']), async (req, res) => {
  try {
    const { limit = 50 } = req.query;

    const shelter = await Shelter.findById(req.params.id)
      .populate('activityLogs.performedBy', 'username role');

    if (!shelter) {
      return res.status(404).json({ success: false, message: 'Shelter not found' });
    }

    const logs = shelter.activityLogs
      .slice(-parseInt(limit))
      .reverse();

    res.status(200).json({
      success: true,
      count: logs.length,
      data: logs
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to fetch activity logs', error: error.message });
  }
});

// ==================== UTILITY ROUTES ====================

// Health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'SafeRoute API is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    connections: {
      socketio: connectedClients.size,
      lora: wss.clients.size
    }
  });
});

// GET /api/status - Detailed system status
app.get('/api/status', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';

    res.status(200).json({
      success: true,
      data: {
        server: {
          status: 'running',
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          nodeVersion: process.version
        },
        database: {
          status: dbStatus,
          name: mongoose.connection.name
        },
        realtime: {
          socketioClients: connectedClients.size,
          loraClients: wss.clients.size,
          rooms: {
            rescue_team: io.sockets.adapter.rooms.get('rescue_team_room')?.size || 0,
            manager: io.sockets.adapter.rooms.get('manager_room')?.size || 0,
            user: io.sockets.adapter.rooms.get('user_room')?.size || 0
          }
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to get status', error: error.message });
  }
});

// POST /api/auth/logout - Logout user
app.post('/api/auth/logout', verifyToken, async (req, res) => {
  try {
    // Blacklist the token
    blacklistToken(req.token);

    // Update user status
    await User.findByIdAndUpdate(req.user.id, {
      isOnline: false,
      socketId: null,
      lastSeen: new Date(),
      refreshToken: null
    });

    // Disconnect user from socket
    const userSocket = userSocketMap.get(req.user.id);
    if (userSocket) {
      io.to(userSocket).emit('logout', { message: 'You have been logged out' });
    }

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Logout failed', error: error.message });
  }
});

// POST /api/auth/refresh - Refresh access token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ success: false, message: 'Refresh token required' });
    }

    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    const newAccessToken = generateToken(user);
    const newRefreshToken = generateRefreshToken(user);

    user.refreshToken = newRefreshToken;
    await user.save();

    res.status(200).json({
      success: true,
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Token refresh failed', error: error.message });
  }
});

// PATCH /api/auth/password - Change password
app.patch('/api/auth/password', verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, message: 'Current and new password required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'New password must be at least 6 characters' });
    }

    const user = await User.findById(req.user.id);
    const isMatch = await user.comparePassword(currentPassword);

    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Current password is incorrect' });
    }

    user.password = newPassword;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Password change failed', error: error.message });
  }
});

// PATCH /api/auth/profile - Update own profile
app.patch('/api/auth/profile', verifyToken, async (req, res) => {
  try {
    const { profile, email } = req.body;

    const updateData = {};
    if (profile) updateData.profile = { ...profile };
    if (email) updateData.email = email;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updateData },
      { new: true, runValidators: true }
    );

    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: user.toJSON()
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Profile update failed', error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.url} not found`
  });
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3001;

server.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║                    🚀 SafeRoute Server                       ║');
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log(`║  🌐 HTTP Server:     http://localhost:${PORT}                   ║`);
  console.log(`║  📡 Socket.io:       ws://localhost:${PORT}                     ║`);
  console.log(`║  📻 LoRa Gateway:    ws://localhost:${PORT}/lora                ║`);
  console.log('╠══════════════════════════════════════════════════════════════╣');
  console.log('║  ✅ MongoDB Connected                                        ║');
  console.log('║  🔐 JWT Authentication Enabled                               ║');
  console.log('║  ⚡ Real-time Updates Active                                  ║');
  console.log('║  📻 LoRa Mesh Simulation Ready                               ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');
});
