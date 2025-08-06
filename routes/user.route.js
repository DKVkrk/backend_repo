// routes/user.route.js
import express from 'express';
import {
  forgotPasswordController,
  loginController,
  logoutController,
  refreshToken,
  registerUserController, // General registration controller
  resetPasswordController,
  uploadAvatar,
  userDetails,
  verifyEmailController,
  updateUserDetails,
  toggleDriverOnlineStatus,
  getUserProfile,
  requestRide,
  getRideHistory,
  completeRide,
  getPendingRides,
  acceptRide,
  updateDriverLocation,
  getAcceptedRides,
  rejectRide,
  cancelRide,
  getRideById,
  verifyOtp,
  sendImage,
  googleAuthHandler // Import the new Google Auth controller
} from '../controllers/usercontroller.js';
import auth from '../middleware/auth.js';
import upload from '../middleware/multer.js';

const router = express.Router();

// General Registration (now handles both user and driver based on 'role' in body)
router.post('/register', registerUserController); // Changed to a more general path

router.get('/verify-email', verifyEmailController);
router.post('/login', loginController);
router.get('/logout', auth, logoutController);
router.put('/upload-avatar', auth, upload.single('avatar'), uploadAvatar);
router.put('/update-user', auth, updateUserDetails);
router.put('/forgot-password', forgotPasswordController);
router.put('/reset-password', resetPasswordController);
router.post('/refresh-token', refreshToken);
router.get('/details', auth, userDetails);
router.post('/driver/toggle-status', auth, toggleDriverOnlineStatus);
router.get('/profile', auth, getUserProfile);

// New Google Authentication Route
router.post('/auth/google', googleAuthHandler); // This route will handle Google sign-in/sign-up for both roles

// Ride endpoints
router.post('/ride/request', auth, requestRide);
router.get('/ride/history', auth, getRideHistory);
router.put('/ride/complete', auth, completeRide);
router.put('/ride/cancel/:rideId', auth, cancelRide);
router.get('/ride/:rideId', auth, getRideById);
router.post('/ride/verify-otp', auth, verifyOtp);

// Image sharing route
router.post('/send-image', auth, upload.single('image'), sendImage);

// Driver specific endpoints
router.get('/driver/pending-rides', auth, getPendingRides);
router.post('/driver/accept-ride', auth, acceptRide);
router.post('/driver/reject-ride', auth, rejectRide);
router.get('/driver/accepted-rides', auth, getAcceptedRides);
router.post('/driver/update-location', auth, updateDriverLocation);

export default router;