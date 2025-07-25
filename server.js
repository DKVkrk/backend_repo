import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import helmet from 'helmet';
import http from 'http';
import { Server } from 'socket.io'; // Correct import with curly braces

import connectDB from './config/db.js';
import userRouter from './routes/user.route.js';
import { calculateDistance } from './utils/geoUtils.js'; // Assuming this path

dotenv.config();

const app = express();

// Enhanced CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(morgan('dev'));
app.use(helmet({
  crossOriginResourcePolicy: false
}));

const server = http.createServer(app);

// --- CRITICAL RE-FIX START ---
// Define activeUsers and driverLocations BEFORE `io` initialization but AFTER `app`
// This ensures they are in a scope accessible by everything that needs them.
const activeUsers = new Map(); // userId -> socket.id
const driverLocations = new Map(); // driverId -> { lat, lng }

// Initialize Socket.IO server immediately after http server
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL,
    methods: ["GET", "POST", "PUT"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingInterval: 10000,
  pingTimeout: 5000,
  cookie: false
});

// Attach io and activeUsers directly to the Express app.locals object
// This is the most reliable way to make them available to ALL middleware and controllers
app.locals.io = io;
app.locals.activeUsers = activeUsers;
app.locals.driverLocations = driverLocations; // Also make driverLocations accessible

// Now, define your Express routes and other middleware
// Make sure this is AFTER `app.locals` assignment
app.use('/api/user', userRouter);

// --- CRITICAL RE-FIX END ---


// Socket.IO authentication middleware
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error'));
  }
  // No need to verify JWT here, it's done by auth middleware in routes.
  // This just ensures a token exists for socket connection.
  next();
});

io.on('connection', (socket) => {
  console.log(`✅ WebSocket Connected: ${socket.id}`);

  // Register user/driver and store their socket ID in activeUsers map
  socket.on('registerUser', (userId) => {
    app.locals.activeUsers.set(userId, socket.id);
    console.log(`User ${userId} registered with socket ${socket.id}`);
  });

  socket.on('driverOnline', (driverId) => {
    app.locals.activeUsers.set(driverId, socket.id);
    socket.join('drivers'); // Drivers join a 'drivers' room
    console.log(`Driver ${driverId} is online`);
  });

  socket.on('updateDriverLocation', ({ driverId, location }) => {
    app.locals.driverLocations.set(driverId, location);
    console.log(`Driver ${driverId} location updated to: ${location.lat}, ${location.lng}`);
  });

  socket.on('driverOffline', (driverId) => {
    socket.leave('drivers');
    app.locals.activeUsers.delete(driverId);
    app.locals.driverLocations.delete(driverId);
    console.log(`Driver ${driverId} is offline`);
  });

  socket.on('newRideRequest', (rideData) => {
    console.log(`New ride request from ${rideData.userId}`);

    // Find nearby drivers (within 5km) and notify them
    for (const [driverId, location] of app.locals.driverLocations.entries()) {
      const distance = calculateDistance(
        rideData.pickup_location.lat,
        rideData.pickup_location.lng,
        location.lat,
        location.lng
      );

      if (distance <= 5) { // Notify drivers within 5km
        const driverSocketId = app.locals.activeUsers.get(driverId);
        if (driverSocketId) {
          app.locals.io.to(driverSocketId).emit('newRideAvailable', rideData);
        }
      }
    }
  });

  socket.on('driverAcceptsRide', ({ rideId, driverId, userId, driverName, vehicleType, driverProfilePhoto }) => {
    const riderSocketId = app.locals.activeUsers.get(userId);
    if (riderSocketId) {
      app.locals.io.to(riderSocketId).emit('rideAccepted', {
        rideId,
        driverId,
        driverName,
        vehicleType,
        driverProfilePhoto,
        message: "Your ride has been accepted!"
      });
    }
    app.locals.io.to('drivers').emit('rideAcceptedByOther', { rideId });
  });

  socket.on('driverRejectsRide', ({ rideId, userId }) => {
    const riderSocketId = app.locals.activeUsers.get(userId);
    if (riderSocketId) {
      app.locals.io.to(riderSocketId).emit('rideRejected', {
        rideId,
        message: "Driver couldn't accept your ride. Searching for another driver..."
      });
    }
  });

  socket.on('driverReachedRider', ({ riderId, rideId }) => {
    const riderSocketId = app.locals.activeUsers.get(riderId);
    if (riderSocketId) {
      app.locals.io.to(riderSocketId).emit('driverReachedRider', { riderId, rideId });
      console.log(`Driver reached rider for ride ${rideId}`);
    }
  });

  // This is handled by usercontroller.js now.
  // socket.on('verifyOtp', ...)

  socket.on('rideCompleted', ({ userId, rideId }) => {
    const riderSocketId = app.locals.activeUsers.get(userId);
    if (riderSocketId) {
      app.locals.io.to(riderSocketId).emit('rideCompleted', { rideId, userId });
      console.log(`Ride ${rideId} completed for user ${userId}`);
    }
  });

  socket.on('riderCancelledRide', ({ rideId, driverId }) => {
    const driverSocketId = app.locals.activeUsers.get(driverId);
    if (driverSocketId) {
      app.locals.io.to(driverSocketId).emit('rideCancelled', { rideId });
      console.log(`Rider cancelled ride ${rideId}, notifying driver ${driverId}`);
    }
  });

  // Image message event handler, triggered by usercontroller.js
  // The usercontroller.js now directly uses app.locals.io to emit these messages.
  // This listener here is redundant if the controller emits directly,
  // but harmless if kept. For clarity, the primary emission happens in controller.
  socket.on('imageMessage', ({ rideId, imageUrl, senderId, senderRole, recipientId }) => {
    console.log(`[Socket.IO Server] Received imageMessage to relay:`, { rideId, imageUrl, senderId, senderRole, recipientId });
    // This part should technically be handled by the controller's logic
    // via `req.app.locals.io.to(...)`
    // If you see this log, it means a client tried to emit 'imageMessage' directly,
    // which is not the intended flow anymore (it should be an HTTP POST then socket emit from server)
  });


  socket.on('disconnect', () => {
    console.log(`❌ WebSocket Disconnected: ${socket.id}`);
    for (const [userId, sockId] of app.locals.activeUsers.entries()) {
      if (sockId === socket.id) {
        app.locals.activeUsers.delete(userId);
        if (app.locals.driverLocations.has(userId)) {
          app.locals.driverLocations.delete(userId);
          socket.leave('drivers');
        }
        break;
      }
    }
  });
});

// Error handling middleware (kept at the end)
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    message: err.message || 'Internal Server Error',
    error: true
  });
});

const PORT = process.env.PORT || 8000;

connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`CORS enabled for: ${process.env.FRONTEND_URL}`);
  });
});