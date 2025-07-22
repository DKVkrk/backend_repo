const { Server } = require('socket.io');
const crypto = require('crypto');

// In-memory store for demo (replace with DB in production)
const rides = {};
const userSockets = {};
const driverSockets = {};

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function setupSocket(server) {
  const io = new Server(server, {
    cors: {
      origin: '*',
      methods: ['GET', 'POST']
    }
  });

  io.on('connection', (socket) => {
    // Register user or driver
    socket.on('registerUser', (userId) => {
      userSockets[userId] = socket;
      socket.userId = userId;
    });
    socket.on('driverOnline', (driverId) => {
      driverSockets[driverId] = socket;
      socket.driverId = driverId;
    });
    socket.on('driverOffline', (driverId) => {
      delete driverSockets[driverId];
    });

    // Rider requests a ride
    socket.on('newRideRequest', (data) => {
      const { userId, rideId, pickup_location, dropoff_location, fare, vehicleType } = data;
      const otp = generateOtp();
      rides[rideId] = {
        userId,
        rideId,
        pickup_location,
        dropoff_location,
        fare,
        vehicleType,
        otp,
        status: 'requested',
        driverId: null,
        driverLocation: null
      };
      // Notify all online drivers
      Object.values(driverSockets).forEach(driverSocket => {
        driverSocket.emit('newRideAvailable', {
          userId,
          rideId,
          pickup_location,
          dropoff_location,
          fare,
          vehicleType,
          otp // For demo, do not send to driver in real app
        });
      });
      // Send OTP to rider
      if (userSockets[userId]) {
        userSockets[userId].emit('otpGenerated', { otp });
      }
    });

    // Driver accepts ride
    socket.on('driverAcceptsRide', (data) => {
      const { rideId, driverId, userId } = data;
      if (rides[rideId]) {
        rides[rideId].status = 'accepted';
        rides[rideId].driverId = driverId;
        // Notify rider
        if (userSockets[userId]) {
          userSockets[userId].emit('rideAccepted', {
            driverId,
            driverName: 'Driver', // Replace with real name
            vehicleType: rides[rideId].vehicleType,
            driverProfilePhoto: 'https://cdn-icons-png.flaticon.com/512/3135/3135715.png',
            message: 'Your ride has been accepted!'
          });
        }
      }
    });

    // Driver shares location
    socket.on('shareDriverLocation', (data) => {
      const { userId, location } = data;
      // Forward to rider
      if (userSockets[userId]) {
        userSockets[userId].emit('driverLocationUpdate', location);
      }
    });

    // Rider shares location (optional, for driver tracking)
    socket.on('shareRiderLocation', (data) => {
      const { driverId, location } = data;
      if (driverSockets[driverId]) {
        driverSockets[driverId].emit('riderLocationUpdate', location);
      }
    });

    // OTP verification
    socket.on('verifyOtp', (data) => {
      const { rideId, enteredOtp } = data;
      const ride = rides[rideId];
      if (!ride) return;
      if (ride.otp === enteredOtp) {
        ride.status = 'otp_verified';
        // Notify both
        if (userSockets[ride.userId]) {
          userSockets[ride.userId].emit('otpVerified', { success: true });
        }
        if (driverSockets[ride.driverId]) {
          driverSockets[ride.driverId].emit('otpVerified', { success: true });
        }
      } else {
        // Notify driver only
        if (driverSockets[ride.driverId]) {
          driverSockets[ride.driverId].emit('otpVerified', { success: false });
        }
      }
    });

    socket.on('disconnect', () => {
      if (socket.userId) delete userSockets[socket.userId];
      if (socket.driverId) delete driverSockets[socket.driverId];
    });
  });

  return io;
}

module.exports = setupSocket;
