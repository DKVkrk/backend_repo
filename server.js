// import express from 'express';
// import cors from 'cors';
// import dotenv from 'dotenv';
// import cookieParser from 'cookie-parser';
// import morgan from 'morgan';
// import helmet from 'helmet';
// import http from 'http';
// import { Server } from 'socket.io';

// import connectDB from './config/db.js';
// import userRouter from './routes/user.route.js';
// import { calculateDistance } from './utils/geoUtils.js';

// dotenv.config();

// const app = express();
// const server = http.createServer(app);

// let io;
// const activeUsers = new Map();
// const driverLocations = new Map();

// app.use(cors({
//   origin: process.env.FRONTEND_URL,
//   credentials: true,
//   methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
//   allowedHeaders: ['Content-Type', 'Authorization']
// }));
// app.use(express.json({ limit: '10mb' }));
// app.use(cookieParser());
// app.use(morgan('dev'));
// app.use(helmet({
//   crossOriginResourcePolicy: false
// }));

// io = new Server(server, {
//   cors: {
//     origin: process.env.FRONTEND_URL,
//     methods: ["GET", "POST", "PUT"],
//     credentials: true
//   },
//   transports: ['websocket', 'polling'],
//   pingInterval: 10000,
//   pingTimeout: 5000,
//   cookie: false
// });

// app.locals.io = io;
// app.locals.activeUsers = activeUsers;
// app.locals.driverLocations = driverLocations;

// app.use('/api/user', userRouter);
// app.post('/api/user/payment/webhook', express.raw({ type: 'application/json' }), userRouter);

// io.use((socket, next) => {
//   const token = socket.handshake.auth.token;
//   if (!token) {
//     return next(new Error('Authentication error: Missing token'));
//   }
//   next();
// });

// io.on('connection', (socket) => {
//   console.log(`✅ WebSocket Connected: ${socket.id}`);

//   socket.on('registerUser', (userId) => {
//     app.locals.activeUsers.set(userId, socket.id);
//     console.log(`User ${userId} registered with socket ${socket.id}`);
//   });

//   socket.on('driverOnline', (driverId) => {
//     app.locals.activeUsers.set(driverId, socket.id);
//     socket.join('drivers');
//     console.log(`Driver ${driverId} is online`);
//   });

//   socket.on('updateDriverLocation', ({ driverId, location }) => {
//     app.locals.driverLocations.set(driverId, location);
//     console.log(`Driver ${driverId} location updated to: ${location.lat}, ${location.lng}`);
//   });

//   socket.on('driverOffline', (driverId) => {
//     socket.leave('drivers');
//     app.locals.activeUsers.delete(driverId);
//     app.locals.driverLocations.delete(driverId);
//     console.log(`Driver ${driverId} is offline`);
//   });

//   socket.on('newRideRequest', (rideData) => {
//     console.log(`New ride request from ${rideData.userId}`);

//     for (const [driverId, location] of app.locals.driverLocations.entries()) {
//       const distance = calculateDistance(
//         rideData.pickup_location.lat,
//         rideData.pickup_location.lng,
//         location.lat,
//         location.lng
//       );

//       if (distance <= 5) {
//         const driverSocketId = app.locals.activeUsers.get(driverId);
//         if (driverSocketId) {
//           app.locals.io.to(driverSocketId).emit('newRideAvailable', rideData);
//         }
//       }
//     }
//   });

//   socket.on('driverAcceptsRide', ({ rideId, driverId, userId, driverName, vehicleType, driverProfilePhoto }) => {
//     const riderSocketId = app.locals.activeUsers.get(userId);
//     if (riderSocketId) {
//       app.locals.io.to(riderSocketId).emit('rideAccepted', {
//         rideId,
//         driverId,
//         driverName,
//         vehicleType,
//         driverProfilePhoto,
//         message: "Your ride has been accepted!"
//       });
//     }
//     app.locals.io.to('drivers').emit('rideAcceptedByOther', { rideId });
//   });

//   socket.on('driverRejectsRide', ({ rideId, userId }) => {
//     const riderSocketId = app.locals.activeUsers.get(userId);
//     if (riderSocketId) {
//       app.locals.io.to(riderSocketId).emit('rideRejected', {
//         rideId,
//         message: "Driver couldn't accept your ride. Searching for another driver..."
//       });
//     }
//   });

//   socket.on('driverReachedRider', ({ riderId, rideId }) => {
//     const riderSocketId = app.locals.activeUsers.get(riderId);
//     if (riderSocketId) {
//       app.locals.io.to(riderSocketId).emit('driverReachedRider', { riderId, rideId });
//     }
//   });

//   socket.on('rideCompleted', ({ userId, rideId }) => {
//     const riderSocketId = app.locals.activeUsers.get(userId);
//     if (riderSocketId) {
//       app.locals.io.to(riderSocketId).emit('rideCompleted', { rideId, userId });
//     }
//   });

//   socket.on('riderCancelledRide', ({ rideId, driverId }) => {
//     const driverSocketId = app.locals.activeUsers.get(driverId);
//     if (driverSocketId) {
//       app.locals.io.to(driverSocketId).emit('rideCancelled', { rideId });
//     }
//   });

//   socket.on('disconnect', () => {
//     console.log(`❌ WebSocket Disconnected: ${socket.id}`);
//     for (const [userId, sockId] of app.locals.activeUsers.entries()) {
//       if (sockId === socket.id) {
//         app.locals.activeUsers.delete(userId);
//         if (app.locals.driverLocations.has(userId)) {
//           app.locals.driverLocations.delete(userId);
//           socket.leave('drivers');
//         }
//         break;
//       }
//     }
//   });
// });

// app.use((err, req, res, next) => {
//   console.error('Server error:', err);
//   res.status(500).json({
//     message: err.message || 'Internal Server Error',
//     error: true
//   });
// });

// const PORT = process.env.PORT || 8000;

// connectDB().then(() => {
//   server.listen(PORT, () => {
//     console.log(`Server running on port ${PORT}`);
//     console.log(`CORS enabled for: ${process.env.FRONTEND_URL}`);
//   });
// });
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import helmet from 'helmet';
import http from 'http';
import { Server } from 'socket.io';

import connectDB from './config/db.js';
import userRouter from './routes/user.route.js';
import { calculateDistance } from './utils/geoUtils.js';

dotenv.config();

const app = express();
const server = http.createServer(app);

// ✅ Allow multiple origins for CORS
const allowedOrigins = [
  "http://localhost:3000",
  "https://fron-repo-nbkujw78h-devesh-kumar-singhs-projects.vercel.app" // Your Vercel frontend
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl)
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("CORS not allowed for this origin"));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(morgan('dev'));
app.use(helmet({
  crossOriginResourcePolicy: false
}));

// ✅ Socket.IO CORS setup to match Express
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST", "PUT"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingInterval: 10000,
  pingTimeout: 5000,
  cookie: false
});

app.locals.io = io;
app.locals.activeUsers = new Map();
app.locals.driverLocations = new Map();

app.use('/api/user', userRouter);
app.post('/api/user/payment/webhook', express.raw({ type: 'application/json' }), userRouter);

// Socket.IO events...
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error: Missing token'));
  }
  next();
});

// Your socket events remain the same...

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
    console.log(`✅ CORS allowed for:`, allowedOrigins);
  });
});
