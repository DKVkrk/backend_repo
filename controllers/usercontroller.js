// controllers/userController.js
import sendEmail from '../config/sendEmail.js';
import UserModel from '../models/User.js';
import bcryptjs from 'bcryptjs';
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js';
import generatedAccessToken from '../utils/generatedAccessToken.js';
import genertedRefreshToken from '../utils/generatedRefreshToken.js';
import uploadImageClodinary from '../utils/uploadImageClodinary.js';
import generatedOtp from '../utils/generatedOtp.js';
import forgotPasswordTemplate from '../utils/forgotPasswordTemplate.js';
import jwt from 'jsonwebtoken';
import { calculateDistance } from '../utils/geoUtils.js';


import { OAuth2Client } from 'google-auth-library'; // Import Google Auth Library
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);


/*
|----------------------------------------------------------
| Register (User / Driver with Role-based Control)
|----------------------------------------------------------
*/
export async function registerUserController(request, response) {
  try {
    console.log("Incoming registration data:", request.body); // Debug log

    const { name, email, password, role, licenseNumber, vehicleInfo } = request.body;

    if (!name || !email || !password || !role) {
      return response.status(400).json({ message: "Provide name, email, password, and role", success: false, error: true });
    }

    if (!['user', 'driver'].includes(role)) {
      return response.status(400).json({ message: "Invalid role specified", success: false, error: true });
    }

    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return response.status(409).json({ message: "Email already registered", success: false, error: true });
    }

    // Driver-specific validation
    if (role === 'driver') {
      if (!licenseNumber) {
        return response.status(400).json({ message: "License number required for driver", success: false, error: true });
      }
      if (!vehicleInfo) {
        return response.status(400).json({ message: "Vehicle info required for driver", success: false, error: true });
      }
    }

    const salt = await bcryptjs.genSalt(10);
    const hashPassword = await bcryptjs.hash(password, salt);

    const newUser = new UserModel({
      name,
      email,
      password: hashPassword,
      role,
      license_number: role === 'driver' ? licenseNumber : null,
      vehicle_info: role === 'driver' ? vehicleInfo : null,
      is_verified_driver: role === 'driver' ? false : null, // Drivers may need admin approval
      verify_email: false // Still require email verification
    });

    const savedUser = await newUser.save();

    const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${savedUser._id}`;
    await sendEmail({
      sendTo: email,
      subject: "Verify your email - Rilo",
      html: verifyEmailTemplate({ name, url: verifyEmailUrl })
    });

    let successMessage = "Registered successfully. Please verify your email.";
    if (role === 'driver') {
        successMessage += " Your account may require admin approval before going online.";
    }

    return response.status(201).json({
      message: successMessage,
      success: true,
      error: false,
      data: savedUser
    });
  } catch (error) {
    console.error("🔥 Registration Error:", error);
    return response.status(500).json({ message: error.message || error, success: false, error: true });
  }
}


/*
|--------------------------------------------------------------------------
| Google Authentication Handler
|--------------------------------------------------------------------------
*/
export const googleAuthHandler = async (req, res) => {
    try {
        const { token, role } = req.body; // 'token' is Google's ID Token, 'role' is passed from frontend

        if (!token) {
            return res.status(400).json({ message: "Google ID Token missing", success: false, error: true });
        }
        if (!role || !['user', 'driver'].includes(role)) {
            return res.status(400).json({ message: "Invalid or missing role for Google authentication", success: false, error: true });
        }

        // 1. Verify the ID Token with Google
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { sub: googleId, email, name, picture: avatar } = payload;

        if (!email || !name) {
            console.error("Google payload missing email or name:", payload);
            return res.status(400).json({ message: "Invalid Google token payload (missing email/name)", success: false, error: true });
        }

        // 2. Check if user already exists in your database
        let user = await UserModel.findOne({ email });

        if (user) {
            // User exists, check if their role matches the requested role
            if (user.role !== role) {
                return res.status(409).json({
                    message: `Account already exists with email ${email} as a ${user.role}. Please log in using that role.`,
                    success: false,
                    error: true
                });
            }

            // If user exists but not linked to Google, link it
            if (!user.googleId) {
                user.googleId = googleId;
                await user.save();
            }
            console.log(`User ${email} found. Logging in via Google as ${role}.`);
        } else {
            // User does not exist, create a new user account
            console.log(`User ${email} not found. Registering new user via Google as ${role}.`);

            // For driver signups via Google, you might need additional fields.
            // Here, we create a basic driver/user. A more advanced flow would ask for license/vehicle post-Google auth.
            if (role === 'driver') {
                // If a driver signs up via Google, they might not have license/vehicle info immediately.
                // You might default these to null and require them to complete their profile later.
                // Or you could make them register via regular form if those fields are mandatory from start.
                console.warn(`Driver ${email} signed up via Google, but missing license/vehicle info. They must complete their profile.`);
            }

            const newUser = new UserModel({
                name: name,
                email: email,
                password: null, // No password for Google authenticated users
                avatar: avatar,
                googleId: googleId,
                role: role, // Use the role passed from the frontend (user or driver)
                is_verified_driver: role === 'driver' ? false : null, // Drivers may need admin approval
                verify_email: true, // Google verifies the email for us
            });
            user = await newUser.save();
            console.log(`New user ${user._id} registered via Google as ${role}.`);
        }

        // 3. Generate your application's access and refresh tokens
        const accesstoken = await generatedAccessToken(user._id);
        const refreshToken = await genertedRefreshToken(user._id);

        await UserModel.findByIdAndUpdate(user._id, {
            last_login_date: new Date(),
            refresh_token: refreshToken,
        });

        const cookiesOption = {
            httpOnly: true,
            secure: true,
            sameSite: "None",
        };
        res.cookie('accessToken', accesstoken, cookiesOption);
        res.cookie('refreshToken', refreshToken, cookiesOption);

        return res.json({
            message: "Google authentication successful",
            success: true,
            error: false,
            data: {
                accesstoken,
                refreshToken,
                user: {
                    _id: user._id,
                    email: user.email,
                    role: user.role,
                    name: user.name,
                    avatar: user.avatar,
                }
            }
        });

    } catch (error) {
        console.error("🔥 Google Authentication Error:", error);
        if (error.message.includes("Invalid ID Token") || error.message.includes("Audience mismatch")) {
            return res.status(401).json({ message: "Google token verification failed. Please ensure correct Client ID.", success: false, error: true });
        }
        // Handle Mongoose duplicate key error specifically for GoogleId
        if (error.code === 11000 && error.keyPattern && error.keyPattern.googleId) {
             return res.status(409).json({ message: "This Google account is already linked to another user.", success: false, error: true });
        }
        return res.status(500).json({ message: error.message || "Google authentication failed due to server error", success: false, error: true, details: error.stack });
    }
};


/*
|----------------------------------------------------------
| Verify Email (via Query Param)
|----------------------------------------------------------
*/
export async function verifyEmailController(request, response) {
  try {
    const { code } = request.query;

    const user = await UserModel.findById(code);
    if (!user) {
      return response.status(400).json({ message: "Invalid or expired verification link", success: false, error: true });
    }

    user.verify_email = true;
    await user.save();

    return response.json({ message: "Email verified successfully", success: true, error: false });
  } catch (error) {
    return response.status(500).json({ message: error.message || error, success: false, error: true });
  }
}

/*
|--------------------------------------------------------------------------
| Login
|--------------------------------------------------------------------------
*/
export async function loginController(request, response) {
  try {
    const { email, password } = request.body;

    if (!email || !password) {
      return response.status(400).json({
        message: "provide email, password",
        error: true,
        success: false
      });
    }

    const user = await UserModel.findOne({ email });

    if (!user) {
      return response.status(400).json({
        message: "User not register",
        error: true,
        success: false
      });
    }

    if (user.status !== "active") {
      return response.status(400).json({
        message: "Contact to Admin",
        error: true,
        success: false
      });
    }

    const checkPassword = await bcryptjs.compare(password, user.password);

    if (!checkPassword) {
      return response.status(400).json({
        message: "Check your password",
        error: true,
        success: false
      });
    }

    const accesstoken = await generatedAccessToken(user._id);
    const refreshToken = await genertedRefreshToken(user._id);

    const updateUser = await UserModel.findByIdAndUpdate(user?._id, {
      last_login_date: new Date()
    });

    const cookiesOption = {
      httpOnly: true,
      secure: true,
      sameSite: "None"
    };
    response.cookie('accessToken', accesstoken, cookiesOption);
    response.cookie('refreshToken', refreshToken, cookiesOption);

    return response.json({
      message: "Login successfully",
      error: false,
      success: true,
      data: {
        accesstoken,
        refreshToken,
        user: {
          _id: user._id,
          email: user.email,
          role: user.role,
          name: user.name
        }
      }
    });

  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
}

/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/
export async function logoutController(request, response) {
  try {
    const userId = request.userId;

    const cookieOptions = { httpOnly: true, secure: true, sameSite: "None" };
    response.clearCookie("accessToken", cookieOptions);
    response.clearCookie("refreshToken", cookieOptions);

    await UserModel.findByIdAndUpdate(userId, { refresh_token: "" });

    return response.json({ message: "Logout successful", success: true, error: false });
  } catch (error) {
    return response.status(500).json({ message: error.message || error, success: false, error: true });
  }
}

/*UPLOAD AVATATR*/
export async function uploadAvatar(request, response) {
  try {
    const userId = request.userId;
    const image = request.file;

    const upload = await uploadImageClodinary(image);

    await UserModel.findByIdAndUpdate(userId, { avatar: upload.url });

    return response.json({ message: "Avatar uploaded", success: true, error: false, data: { avatar: upload.url } });
  } catch (error) {
    return response.status(500).json({ message: error.message || error, success: false, error: true });
  }
}

/*update user details*/
export async function updateUserDetails(request, response) {
  try {
    const userId = request.userId //auth middleware
    const { name, email, mobile, password } = request.body;

    let hashPassword = "";

    if (password) {
      const salt = await bcryptjs.genSalt(10);
      hashPassword = await bcryptjs.hash(password, salt);
    }

    const updateUser = await UserModel.updateOne({ _id: userId }, {
      ...(name && { name: name }),
      ...(email && { email: email }),
      ...(mobile && { mobile: mobile }),
      ...(password && { password: hashPassword })
    });

    return response.json({
      message: "Updated successfully",
      error: false,
      success: true,
      data: updateUser
    });

  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
}

//forgot password not login
export async function forgotPasswordController(request, response) {
  try {
    const { email } = request.body;

    const user = await UserModel.findOne({ email });

    if (!user) {
      return response.status(400).json({
        message: "Email not registered",
        error: true,
        success: false,
      });
    }

    const otp = generatedOtp();
    const expireTime = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now

    await UserModel.findByIdAndUpdate(user._id, {
      forgot_password_otp: otp,
      forgot_password_expiry: expireTime.toISOString(),
    });

    await sendEmail({
      sendTo: email,
      subject: "Password Reset OTP - Rilo",
      html: forgotPasswordTemplate({
        name: user.name,
        otp,
      }),
    });

    return response.json({
      message: "OTP sent to your email",
      error: false,
      success: true,
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
}

//reset password
export async function resetPasswordController(request, response) {
  try {
    const { email, otp, newPassword } = request.body;

    if (!email || !otp || !newPassword) {
      return response.status(400).json({
        message: "Email, OTP, and new password are required",
        error: true,
        success: false,
      });
    }

    const user = await UserModel.findOne({ email });

    if (!user) {
      return response.status(400).json({
        message: "Email not registered",
        error: true,
        success: false,
      });
    }

    const currentTime = new Date();

    if (!user.forgot_password_expiry || new Date(user.forgot_password_expiry) < currentTime) {
      return response.status(400).json({
        message: "OTP expired",
        error: true,
        success: false,
      });
    }

    if (user.forgot_password_otp !== otp) {
      return response.status(400).json({
        message: "Invalid OTP",
        error: true,
        success: false,
      });
    }

    // Hash new password
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(newPassword, salt);

    // Update password and clear OTP and expiry
    await UserModel.findByIdAndUpdate(user._id, {
      password: hashedPassword,
      forgot_password_otp: "",
      forgot_password_expiry: "",
    });

    return response.json({
      message: "Password reset successfully",
      error: false,
      success: true,
    });

  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
}

//verify forgot password otp
export async function verifyForgotPasswordOtp(request, response) {
  try {
    const { email, otp } = request.body;

    if (!email || !otp) {
      return response.status(400).json({
        message: "Provide required field email, otp.",
        error: true,
        success: false
      });
    }

    const user = await UserModel.findOne({ email });

    if (!user) {
      return response.status(400).json({
        message: "Email not available",
        error: true,
        success: false
      });
    }

    const currentTime = new Date().toISOString();

    if (user.forgot_password_expiry < currentTime) {
      return response.status(400).json({
        message: "Otp is expired",
        error: true,
        success: false
      });
    }

    if (otp !== user.forgot_password_otp) {
      return response.status(400).json({
        message: "Invalid otp",
        error: true,
        success: false
      });
    }

    //if otp is not expired
    //otp === user.forgot_password_otp

    const updateUser = await UserModel.findByIdAndUpdate(user?._id, {
      forgot_password_otp: "",
      forgot_password_expiry: ""
    });

    return response.json({
      message: "Verify otp successfully",
      error: false,
      success: true
    });

  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
}

export async function refreshToken(request, response) {
  try {
    const token = request.cookies.refreshToken || request.headers.authorization?.split(" ")[1];
    if (!token) return response.status(401).json({ message: "Refresh token required", success: false, error: true });

    const decoded = jwt.verify(token, process.env.SECRET_KEY_REFRESH_TOKEN);
    const newAccessToken = await generatedAccessToken(decoded._id);

    const cookieOptions = { httpOnly: true, secure: true, sameSite: "None" };
    response.cookie("accessToken", newAccessToken, cookieOptions);

    return response.json({ message: "Access token refreshed", success: true, error: false, data: { accessToken: newAccessToken } });
  } catch (error) {
    return response.status(401).json({ message: "Invalid or expired token", success: false, error: true });
  }
}

/*
|--------------------------------------------------------------------------
| Get Logged-in User Details
|--------------------------------------------------------------------------
*/
export async function userDetails(request, response) {
  try {
    const userId = request.userId;
    const user = await UserModel.findById(userId)
      .select("-password -refresh_token -forgot_password_otp -forgot_password_expiry");

    if (!user) {
      return response.status(404).json({
        message: "User not found",
        success: false,
        error: true
      });
    }

    return response.json({
      message: "User details fetched",
      success: true,
      error: false,
      data: user
    });
  } catch (error) {
    return response.status(500).json({
      message: error.message || error,
      success: false,
      error: true
    });
  }
}

// rider togle
export const toggleDriverOnlineStatus = async (req, res) => {
  try {
    const driverId = req.userId;
    const { isOnline } = req.body;

    if (typeof isOnline !== 'boolean') {
      return res.status(400).json({
        message: "Invalid isOnline value",
        success: false,
        error: true
      });
    }

    const driver = await UserModel.findByIdAndUpdate(
      driverId,
      { isOnline },
      { new: true }
    );

    if (!driver) {
      return res.status(404).json({
        message: "Driver not found",
        success: false,
        error: true
      });
    }

    res.json({
      message: `Driver is now ${driver.isOnline ? "Online" : "Offline"}`,
      isOnline: driver.isOnline,
      success: true,
      error: false
    });
  } catch (error) {
    console.error("Toggle driver status error:", error);
    res.status(500).json({
      message: error.message || "Error toggling driver status",
      success: false,
      error: true
    });
  }
};

// get user profile
export const getUserProfile = async (req, res) => {
  try {
    const user = await UserModel.findById(req.userId).select('-password');
    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

/* |--------------------------------------------------------------------------
| REQUEST RIDE (Add to upcoming_rides) 🚗
|--------------------------------------------------------------------------
*/
export const requestRide = async (req, res) => {
  try {
    const userId = req.userId;
    const { pickup_location, dropoff_location, fare, vehicle_type } = req.body;

    // Enhanced validation
    if (!pickup_location || !pickup_location.lat || !pickup_location.lng || !pickup_location.address) {
      return res.status(400).json({
        message: "Invalid pickup location data",
        error: true,
        success: false
      });
    }

    if (!dropoff_location || !dropoff_location.lat || !dropoff_location.lng || !dropoff_location.address) {
      return res.status(400).json({
        message: "Invalid dropoff location data",
        error: true,
        success: false
      });
    }

    // Generate OTP for this ride
    const otp = generatedOtp().toString();

    const ride = {
      pickup_location: {
        lat: parseFloat(pickup_location.lat),
        lng: parseFloat(pickup_location.lng),
        address: pickup_location.address
      },
      dropoff_location: {
        lat: parseFloat(dropoff_location.lat),
        lng: parseFloat(dropoff_location.lng),
        address: dropoff_location.address
      },
      driver: null,
      status: "requested",
      fare: fare ? parseFloat(fare) : 0,
      vehicle_type: vehicle_type || "Standard Car",
      requested_at: new Date(),
      completed_at: null,
      userId: userId.toString(),
      otp // Save OTP in the ride
    };

    const user = await UserModel.findByIdAndUpdate(
      userId,
      { $push: { upcoming_rides: ride } },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json({
        message: "User not found",
        error: true,
        success: false
      });
    }

    const newRide = user.upcoming_rides[user.upcoming_rides.length - 1];
    const rideIndex = user.upcoming_rides.length - 1;

    // Emit socket event
    const io = req.app.locals.io; // Access io from app.locals
    if (io) {
      io.emit('newRideRequest', {
        ...newRide.toObject(),
        userId: userId.toString(),
        rideIndex,
        _id: newRide._id.toString(), // Ensure _id is sent for frontend matching
        otp // Also send OTP in the event
      });
    }

    return res.status(201).json({
      message: "Ride requested successfully",
      error: false,
      success: true,
      data: {
        rideId: newRide._id, // Send MongoDB _id as rideId
        rideIndex,
        otp // Return OTP in the response
      }
    });
  } catch (error) {
    console.error("Ride request error:", error);
    return response.status(500).json({
      message: error.message || "Failed to request ride",
      error: true,
      success: false
    });
  }
};
/*
|--------------------------------------------------------------------------
| Accept Ride (with Socket.IO integration)
|--------------------------------------------------------------------------
*/
export const acceptRide = async (req, res) => {
  try {
    const driverId = req.userId;
    const { userId, rideIndex } = req.body;

    console.log(`[AcceptRide Debug] Received Request Body: userId=${userId}, rideIndex=${rideIndex}`);
    console.log(`[AcceptRide Debug] driverId from auth middleware (req.userId): ${driverId}`);

    // Validate inputs
    if (!userId || rideIndex === undefined || isNaN(rideIndex) || rideIndex < 0) {
      console.error(`[AcceptRide Error] Invalid input: userId=${userId}, rideIndex=${rideIndex}`);
      return res.status(400).json({
        message: "userId and a valid rideIndex are required",
        error: true,
        success: false,
      });
    }

    const user = await UserModel.findById(userId);
    console.log(`[AcceptRide Debug] User found: ${user ? user._id : 'None'}`);

    if (!user) {
      console.error(`[AcceptRide Error] User not found for userId: ${userId}`);
      return res.status(404).json({
        message: "User not found",
        error: true,
        success: false,
      });
    }
    if (!Array.isArray(user.upcoming_rides) || rideIndex >= user.upcoming_rides.length) {
      console.error(`[AcceptRide Error] Invalid ride index ${rideIndex} for user ${userId}. Upcoming rides length: ${user.upcoming_rides.length}`);
      return res.status(400).json({
        message: "Invalid ride index for this user",
        error: true,
        success: false,
      });
    }
    const driver = await UserModel.findById(driverId);
    console.log(`[AcceptRide Debug] Driver found: ${driver ? driver._id : 'None'}`);

    if (!driver) {
      console.error(`[AcceptRide Error] Driver not found for driverId: ${driverId}`);
      return res.status(404).json({
        message: "Driver not found",
        error: true,
        success: false,
      });
    }

    const ride = user.upcoming_rides[rideIndex];
    console.log(`[AcceptRide Debug] Ride object at index ${rideIndex}: ${JSON.stringify(ride)}`);

    if (!ride) { // Should ideally be caught by rideIndex check, but good for robustness
      console.error(`[AcceptRide Error] Ride object is null/undefined at index ${rideIndex} for user ${userId}`);
      return res.status(404).json({
        message: "Ride not found at the given index",
        error: true,
        success: false,
      });
    }

    // Check ride status
    if (ride.status !== "requested" || ride.driver !== null) {
      console.error(`[AcceptRide Error] Ride ${ride._id} status is ${ride.status} or already has a driver ${ride.driver}`);
      return res.status(409).json({
        message: "Ride has already been accepted or is no longer available",
        error: true,
        success: false,
      });
    }

    // Check if driver is online
    if (!driver.isOnline) {
      console.error(`[AcceptRide Error] Driver ${driverId} is offline.`);
      return res.status(400).json({
        message: "You must be online to accept rides",
        error: true,
        success: false,
      });
    }

    // Update the ride
    user.upcoming_rides[rideIndex].driver = driverId;
    user.upcoming_rides[rideIndex].status = "accepted";
    user.upcoming_rides[rideIndex].accepted_at = new Date();
    await user.save();
    console.log(`[AcceptRide Debug] Ride status updated to accepted.`);


    // Emit socket event
    const io = req.app.locals.io; // Access io from app.locals
    if (io) {
      io.to(user._id.toString()).emit('rideAccepted', { // Emit to the specific rider
        rideId: user.upcoming_rides[rideIndex]._id, // Use ride _id here
        driverId,
        userId,
        driverName: driver.name,
        vehicleType: ride.vehicle_type, // Use ride's vehicle type
        driverProfilePhoto: driver.avatar // Pass driver's profile photo
      });
      console.log(`[AcceptRide Debug] Emitted 'rideAccepted' to rider ${user._id}`);

      // Notify other drivers that this ride is taken
      io.to('drivers').emit('rideAcceptedByOther', {
        rideId: user.upcoming_rides[rideIndex]._id
      });
      console.log(`[AcceptRide Debug] Emitted 'rideAcceptedByOther' to other drivers.`);
    }

    res.json({
      message: "Ride accepted successfully",
      error: false,
      success: true,
      data: {
        rideMongoId: user.upcoming_rides[rideIndex]._id, // Send the actual Mongo ID
        userId,
        driverName: driver.name,
        vehicleType: ride.vehicle_type,
        driverProfilePhoto: driver.avatar
      }
    });
  } catch (error) {
    console.error("🔥 Accept Ride Error caught in controller:", error);
    res.status(500).json({
      message: error.message || "Failed to accept ride",
      error: true,
      success: false,
      details: error.stack // Include stack for debugging
    });
  }
};
/*
|--------------------------------------------------------------------------
| Reject Ride (with Socket.IO integration)
|--------------------------------------------------------------------------
*/
export const rejectRide = async (req, res) => {
  try {
    const { userId, rideIndex } = req.body;

    const user = await UserModel.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found", error: true, success: false });
    }

    if (!Array.isArray(user.upcoming_rides) || rideIndex >= user.upcoming_rides.length) {
      return res.status(400).json({ message: "Invalid ride index", error: true, success: false });
    }

    const ride = user.upcoming_rides[rideIndex];
    if (!ride) {
      return res.status(404).json({ message: "Ride not found", error: true, success: false });
    }

    res.json({
      message: "Ride rejected successfully",
      error: false,
      success: true
    });
  } catch (error) {
    console.error("🔥 Reject Ride Error:", error);
    res.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
};

/*
|--------------------------------------------------------------------------
| Complete Ride (with Socket.IO integration)
|--------------------------------------------------------------------------
*/
export const completeRide = async (req, res) => {
  try {
    const driverId = req.userId;
    const { customerId, rideIndex } = req.body;

    const customer = await UserModel.findById(customerId);

    if (!customer) {
      return res.status(404).json({
        message: "Customer not found",
        error: true,
        success: false
      });
    }

    if (!customer.upcoming_rides || rideIndex >= customer.upcoming_rides.length) {
      return res.status(400).json({
        message: "Invalid ride index for this customer",
        error: true,
        success: false
      });
    }

    const ride = customer.upcoming_rides[rideIndex];

    // Ensure the ride is indeed assigned to this driver and is accepted or ongoing
    if (ride.driver.toString() !== driverId.toString() || (ride.status !== "accepted" && ride.status !== "ongoing")) {
      return res.status(403).json({
        message: "You are not authorized to complete this ride or it's not in an eligible state.",
        error: true,
        success: false
      });
    }

    ride.status = "completed";
    ride.completed_at = new Date();

    // Move to ride_history
    customer.ride_history.push(ride);

    // Remove from upcoming_rides
    customer.upcoming_rides.splice(rideIndex, 1);

    await customer.save();

    // Emit socket event to notify rider
    const io = req.app.locals.io; // Access io from app.locals
    if (io) {
      io.to(customerId.toString()).emit('rideCompleted', {
        userId: customerId,
        rideId: ride._id
      });
    }

    return res.json({
      message: "Ride completed successfully",
      error: false,
      success: true
    });
  } catch (error) {
    console.error("🔥 Complete Ride Error:", error);
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
};
/*
|--------------------------------------------------------------------------
| Cancel Ride (with Socket.IO integration)
|--------------------------------------------------------------------------
*/
export const cancelRide = async (req, res) => {
  try {
    const { rideId } = req.params;
    const userId = req.userId;

    const user = await UserModel.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
        error: true,
        success: false
      });
    }

    // Find the ride in upcoming_rides
    const rideIndex = user.upcoming_rides.findIndex(r => r._id.toString() === rideId);
    if (rideIndex === -1) {
      return res.status(404).json({
        message: "Ride not found",
        error: true,
        success: false
      });
    }

    const ride = user.upcoming_rides[rideIndex];

    // Remove from upcoming_rides
    user.upcoming_rides.splice(rideIndex, 1);
    await user.save();

    // If ride was accepted, notify driver
    if (ride.status === "accepted" && ride.driver) {
      const io = req.app.locals.io; // Access io from app.locals
      if (io) {
        io.to(ride.driver.toString()).emit('rideCancelled', { // Emit to the specific driver
          rideId,
          userId // Send userId of the rider who cancelled
        });
      }
    }

    return res.json({
      message: "Ride cancelled successfully",
      error: false,
      success: true
    });
  } catch (error) {
    console.error("🔥 Cancel Ride Error:", error);
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
};

/*
|--------------------------------------------------------------------------
| Update Driver Location
|--------------------------------------------------------------------------
*/
export const updateDriverLocation = async (req, res) => {
  try {
    const driverId = req.userId;
    const { lat, lng } = req.body;

    await UserModel.findByIdAndUpdate(driverId, {
      current_location: { lat, lng }
    });

    // Emit socket event to update driver location to all connected riders
    const io = req.app.locals.io; // Access io from app.locals
    if (io) {
      // Find rides assigned to this driver that are 'accepted' or 'ongoing'
      const usersWithActiveRides = await UserModel.find({
        "upcoming_rides.driver": driverId,
        "upcoming_rides.status": { $in: ["accepted", "ongoing"] }
      });

      usersWithActiveRides.forEach(user => {
        user.upcoming_rides.forEach((ride) => {
          if (ride.driver && ride.driver.toString() === driverId.toString() && (ride.status === "accepted" || ride.status === "ongoing")) {
            io.to(user._id.toString()).emit('driverLocationUpdate', {
              driverId,
              location: { lat, lng },
              rideId: ride._id // Pass rideId to help rider identify which ride is being updated
            });
          }
        });
      });
    }

    res.json({
      message: "Location updated successfully",
      error: false,
      success: true
    });
  } catch (error) {
    console.error("Location update error:", error);
    res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
};


/* |--------------------------------------------------------------------------
| GET RIDE HISTORY 🚗
|--------------------------------------------------------------------------
*/
export const getRideHistory = async (req, res) => {
  try {
    const userId = req.userId;

    const user = await UserModel.findById(userId).select("ride_history");

    return res.json({
      message: "Ride history fetched successfully",
      error: false,
      success: true,
      data: user.ride_history
    });
  } catch (error) {
    console.error("🔥 Ride History Error:", error);
    return res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
};


/* |--------------------------------------------------------------------------
| DRIVER FETCH PENDING RIDES 🚗
|--------------------------------------------------------------------------
*/
export const getPendingRides = async (req, res) => {
  try {
    // 1️⃣ Check if driver is online
    const driver = await UserModel.findById(req.userId);

    if (!driver) {
      return res.status(404).json({
        message: "Driver not found",
        error: true,
        success: false,
      });
    }

    if (driver.role !== "driver") {
      return res.status(403).json({
        message: "Only drivers can fetch pending rides",
        error: true,
        success: false,
      });
    }

    if (!driver.isOnline) {
      return res.status(400).json({
        message: "You are offline. Go online to see pending rides.",
        error: true,
        success: false,
      });
    }

    // 2️⃣ Check if driver has current location
    if (!driver.current_location || !driver.current_location.lat) {
      return res.status(400).json({
        message: "Please enable location services to see nearby rides",
        error: true,
        success: false,
      });
    }

    // 3️⃣ Fetch pending rides within 5km radius (adjust as needed)
    const users = await UserModel.find({
      "upcoming_rides.status": "requested",
      "upcoming_rides.driver": null,
    });

    const pendingRides = [];
    const driverLat = driver.current_location.lat;
    const driverLng = driver.current_location.lng;

    users.forEach((user) => {
      user.upcoming_rides.forEach((ride, index) => {
        if (ride.status === "requested" && ride.driver === null) {
          // Calculate distance between driver and pickup point
          const distance = calculateDistance(
            driverLat,
            driverLng,
            ride.pickup_location.lat,
            ride.pickup_location.lng
          );

          // Only include rides within 5km radius (adjust as needed)
          if (distance <= 5) {
            pendingRides.push({
              userId: user._id, // IMPORTANT: Include userId
              rideIndex: index, // IMPORTANT: Include rideIndex
              _id: ride._id, // Include ride's actual _id
              pickup_location: ride.pickup_location,
              dropoff_location: ride.dropoff_location,
              fare: ride.fare,
              vehicle_type: ride.vehicle_type,
              requested_at: ride.requested_at,
              distance: distance.toFixed(2) + " km"
            });
          }
        }
      });
    });

    // Sort by distance (nearest first)
    pendingRides.sort((a, b) => parseFloat(a.distance) - parseFloat(b.distance));

    res.json({
      message: "Pending rides fetched",
      error: false,
      success: true,
      data: pendingRides,
    });
  } catch (error) {
    console.error("🔥 Pending Rides Error:", error);
    res.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
};

/* |--------------------------------------------------------------------------
| DRIVER FETCH ACCEPTED RIDES 🚗
|--------------------------------------------------------------------------
*/
export const getAcceptedRides = async (req, res) => {
  try {
    const driverId = req.userId;

    const driver = await UserModel.findById(driverId);
    if (!driver || driver.role !== "driver") {
      return res.status(403).json({
        message: "Access denied. Only drivers can view accepted rides.",
        error: true,
        success: false,
      });
    }

    // Find rides where this driver is assigned and the status is 'accepted' or 'ongoing'
    const usersWithAcceptedRides = await UserModel.find({
      "upcoming_rides.driver": driverId,
      "upcoming_rides.status": { $in: ["accepted", "ongoing"] }, // Include ongoing rides
    });

    const acceptedRides = [];
    usersWithAcceptedRides.forEach(user => {
      user.upcoming_rides.forEach((ride, index) => {
        if (ride.driver && ride.driver.toString() === driverId.toString() && (ride.status === "accepted" || ride.status === "ongoing")) {
          acceptedRides.push({
            userId: user._id, // Include userId for completing the ride later
            rideIndex: index, // Include rideIndex
            ...ride.toObject(), // Convert Mongoose subdocument to plain object
            riderName: user.name,
            riderPhone: user.mobile
          });
        }
      });
    });

    res.json({
      message: "Accepted rides fetched successfully",
      error: false,
      success: true,
      data: acceptedRides,
    });
  } catch (error) {
    console.error("🔥 Get Accepted Rides Error:", error);
    res.status(500).json({
      message: error.message || error,
      error: true,
      success: false,
    });
  }
};


/* |--------------------------------------------------------------------------
| GET RIDE STATUS (For Rider) 🚗
|--------------------------------------------------------------------------
*/
export const getRideStatus = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await UserModel.findById(userId);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
        error: true,
        success: false
      });
    }

    // Find the most recent requested/accepted/ongoing ride
    const activeRide = user.upcoming_rides.find(ride =>
      ride.status === "requested" || ride.status === "accepted" || ride.status === "ongoing"
    );

    if (!activeRide) {
      return res.status(404).json({
        message: "No active ride found",
        error: true,
        success: false
      });
    }

    let driverDetails = null;
    if (activeRide.driver) {
      const driver = await UserModel.findById(activeRide.driver)
        .select("name mobile avatar current_location isOnline");
      driverDetails = driver;
    }

    res.json({
      message: "Ride status fetched",
      error: false,
      success: true,
      data: {
        status: activeRide.status,
        rideId: activeRide._id, // Ensure rideId is sent
        pickup_location: activeRide.pickup_location,
        dropoff_location: activeRide.dropoff_location,
        fare: activeRide.fare,
        vehicle_type: activeRide.vehicle_type,
        requested_at: activeRide.requested_at,
        driver: driverDetails,
        otp: activeRide.otp // Include OTP for rider to see
      }
    });
  } catch (error) {
    console.error("🔥 Ride Status Error:", error);
    res.status(500).json({
      message: error.message || error,
      error: true,
      success: false
    });
  }
};

// Add this controller to fetch a specific ride by ID for the current user
export const getRideById = async (req, res) => {
  try {
    const userId = req.userId;
    const { rideId } = req.params;
    const user = await UserModel.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found", error: true, success: false });
    const ride = user.upcoming_rides.find(r => r._id.toString() === rideId);
    if (!ride) return res.status(404).json({ message: "Ride not found", error: true, success: false });
    return res.json({ message: "Ride fetched", error: false, success: true, data: ride });
  } catch (error) {
    return res.status(500).json({ message: error.message || error, error: true, success: false });
  }
};

/*
|--------------------------------------------------------------------------
| OTP Verification for Ride Start
|--------------------------------------------------------------------------
*/
export const verifyOtp = async (req, res) => {
  try {
    const { rideId, enteredOtp } = req.body; // Check these two
    const driverId = req.userId; // This comes from your 'auth' middleware

    console.log(`[VerifyOTP Debug] Received Request: rideId=${rideId}, enteredOtp=${enteredOtp}`);
    console.log(`[VerifyOTP Debug] driverId from auth middleware (req.userId): ${driverId}`);

    if (!driverId) {
        console.error("[VerifyOTP Error] Authentication failed: req.userId is undefined. Check auth middleware.");
        return res.status(401).json({ message: "Authentication failed. Driver ID is missing.", success: false, error: true });
    }

    const io = req.app.locals.io; // Access io from app.locals
    const activeUsersMap = req.app.locals.activeUsers; // Access activeUsers from app.locals

    console.log(`[VerifyOTP Debug] io object exists: ${!!io}`); // Check if io is defined
    console.log(`[VerifyOTP Debug] activeUsersMap exists: ${!!activeUsersMap}`); // Check if map is defined
    console.log(`[VerifyOTP Debug] Type of activeUsersMap: ${typeof activeUsersMap}`); // Should be 'object'
    console.log(`[VerifyOTP Debug] activeUsersMap is an instance of Map: ${activeUsersMap instanceof Map}`); // Should be 'true'

    if (!io || !(activeUsersMap instanceof Map)) {
        console.error("[VerifyOTP Error] Socket.IO setup issue: io or activeUsersMap not correctly initialized on app.locals.");
        return res.status(500).json({ message: "Server configuration error (Socket.IO).", success: false, error: true });
    }


    // Find the user who requested this ride
    const user = await UserModel.findOne({ "upcoming_rides._id": rideId });
    console.log(`[VerifyOTP Debug] User found: ${user ? user._id : 'None'}`);

    if (!user) {
        console.error(`[VerifyOTP Error] User not found for rideId: ${rideId}`);
        return res.status(404).json({ message: "Ride not found", success: false, error: true });
    }

    const rideIndex = user.upcoming_rides.findIndex(r => r._id.toString() === rideId);
    console.log(`[VerifyOTP Debug] Ride Index found: ${rideIndex}`); // Will be -1 if not found

    if (rideIndex === -1) {
        console.error(`[VerifyOTP Error] Ride not found at index for rideId: ${rideId}`);
        return res.status(404).json({ message: "Ride not found for this user", success: false, error: true });
    }

    const ride = user.upcoming_rides[rideIndex]; // <-- This is where 'ride' could be undefined/null if issues
    console.log(`[VerifyOTP Debug] Retrieved ride object: ${JSON.stringify(ride)}`); // LOG THE RIDE OBJECT

    // CRITICAL CHECK: Ensure 'ride' is a valid object before proceeding
    if (!ride) {
        console.error(`[VerifyOTP Error] Ride object is null/undefined after findIndex for rideId: ${rideId}, index: ${rideIndex}`);
        return res.status(404).json({ message: "Ride data is invalid.", success: false, error: true });
    }


    // Check if the driver attempting verification is the assigned driver
    if (!ride.driver || ride.driver.toString() !== driverId.toString()) {
        console.error(`[VerifyOTP Error] Driver ${driverId} not authorized for ride ${rideId}. Assigned driver: ${ride.driver}`);
        return res.status(403).json({ message: "Not authorized to verify OTP for this ride", success: false, error: true });
    }

    if (ride.otp && ride.otp === enteredOtp) {
      // Mark ride status as 'ongoing'
      user.upcoming_rides[rideIndex].status = "ongoing";
      await user.save();
      console.log(`[VerifyOTP Debug] OTP Matched and Ride status updated to ongoing.`);

      // Notify both driver and rider about successful OTP verification
      const riderSocketId = activeUsersMap.get(user._id.toString());
      const driverSocketId = activeUsersMap.get(driverId.toString());

      console.log(`[VerifyOTP Debug] Rider Socket ID: ${riderSocketId}, Driver Socket ID: ${driverSocketId}`);

      if (driverSocketId) {
          io.to(driverSocketId).emit('otpVerificationResponse', { rideId, success: true, message: 'OTP verified successfully! Ride started.', userId: user._id.toString(), driverId: driverId.toString() });
      } else {
          console.warn(`[VerifyOTP Warning] Driver ${driverId} has no active socket connection for success notification.`);
      }
      if (riderSocketId) {
          io.to(riderSocketId).emit('otpVerificationResponse', { rideId, success: true, message: 'OTP verified successfully! Your ride has started.', userId: user._id.toString(), driverId: driverId.toString() });
      } else {
          console.warn(`[VerifyOTP Warning] Rider ${user._id} has no active socket connection for success notification.`);
      }

      return res.json({ message: "OTP verified successfully", success: true, error: false });
    } else {
      console.log(`[VerifyOTP Debug] OTP Mismatch. Provided: ${enteredOtp}, Expected: ${ride.otp}`);
      // Notify both driver and rider about failed OTP verification
      const riderSocketId = activeUsersMap.get(user._id.toString());
      const driverSocketId = activeUsersMap.get(driverId.toString());

      if (driverSocketId) {
          io.to(driverSocketId).emit('otpVerificationResponse', { rideId, success: false, message: 'Invalid OTP.', userId: user._id.toString(), driverId: driverId.toString() });
      }
      if (riderSocketId) {
          io.to(riderSocketId).emit('otpVerificationResponse', { rideId, success: false, message: 'Invalid OTP.', userId: user._id.toString(), driverId: driverId.toString() });
      }

      return res.status(400).json({ message: "Invalid OTP", success: false, error: true });
    }
  } catch (error) {
    console.error("🔥 OTP verification error caught in controller:", error);
    // Include error details in the response for debugging purposes
    return response.status(500).json({ message: error.message || "Failed to verify OTP", success: false, error: true, details: error.stack });
  }
};

/*
|--------------------------------------------------------------------------
| Share Image between Rider and Driver
|--------------------------------------------------------------------------
*/
export const sendImage = async (req, res) => {
  try {
    const senderId = req.userId; // User sending the image (can be rider or driver)
    const image = req.file; // The uploaded image file
    const { rideId, recipientId } = req.body; // The ID of the ride and the recipient (other party)

    console.log(`[SendImage Debug] Received Request: rideId=${rideId}, senderId=${senderId}, recipientId=${recipientId}`);
    if (!senderId) {
        console.error("[SendImage Error] req.userId is undefined. Authentication middleware might be failing.");
        return res.status(401).json({ message: "Authentication failed. Sender ID is missing.", success: false, error: true });
    }

    if (!image) {
      console.error("[SendImage Error] No image file provided in request.");
      return res.status(400).json({ message: "No image file provided.", success: false, error: true });
    }
    if (!rideId || !recipientId) {
      console.error(`[SendImage Error] Missing rideId (${rideId}) or recipientId (${recipientId}) in request body.`);
      return res.status(400).json({ message: "Ride ID and Recipient ID are required.", success: false, error: true });
    }

    const sender = await UserModel.findById(senderId);
    const recipient = await UserModel.findById(recipientId);

    console.log(`[SendImage Debug] Sender found: ${sender ? sender._id : 'None'}, Recipient found: ${recipient ? recipient._id : 'None'}`);

    if (!sender || !recipient) {
        console.error(`[SendImage Error] Sender (${senderId}) or Recipient (${recipientId}) not found.`);
        return res.status(404).json({ message: "Sender or Recipient not found.", success: false, error: true });
    }

    // Basic validation: Ensure sender is linked to this ride and recipient is the other party
    let rideFound = false;
    let currentRide; // To store the ride object
    if (sender.role === 'user') { // Rider is sending
        currentRide = sender.upcoming_rides.find(r => r._id.toString() === rideId && r.driver && r.driver.toString() === recipientId.toString() && (r.status === 'accepted' || r.status === 'ongoing'));
        if (currentRide) rideFound = true;
    } else if (sender.role === 'driver') { // Driver is sending
        currentRide = recipient.upcoming_rides.find(r => r._id.toString() === rideId && r.driver && r.driver.toString() === senderId.toString() && (r.status === 'accepted' || r.status === 'ongoing'));
        if (currentRide) rideFound = true;
    }

    console.log(`[SendImage Debug] Ride Found Status: ${rideFound}, Current Ride: ${currentRide ? currentRide._id : 'None'}`);

    if (!rideFound || !currentRide) {
        console.error(`[SendImage Error] Authorization failed for ride ${rideId} between ${senderId} and ${recipientId}.`);
        return res.status(403).json({ message: "You are not authorized to send images for this ride to this recipient.", success: false, error: true });
    }


    const uploadedImage = await uploadImageClodinary(image); // Upload to Cloudinary
    console.log(`[SendImage Debug] Cloudinary Upload Result: ${uploadedImage ? uploadedImage.url : 'Failed'}`);

    if (!uploadedImage || !uploadedImage.url) {
        console.error("[SendImage Error] Cloudinary upload failed.");
        return res.status(500).json({ message: "Failed to upload image to cloud.", success: false, error: true });
    }

    // Get the sender's role
    const senderRole = sender.role;

    // Emit the image message via Socket.IO to the recipient
    const io = req.app.locals.io; // Access io from app.locals
    if (io) {
      // Get actual socket IDs from the Map
      const activeUsersMap = req.app.locals.activeUsers; // Access the map
      const recipientSocketId = activeUsersMap.get(recipientId.toString());
      const senderSocketId = activeUsersMap.get(senderId.toString());

      console.log(`[SendImage Debug] Recipient Socket ID: ${recipientSocketId}, Sender Socket ID: ${senderSocketId}`);

      // Emit to the recipient
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('imageMessage', {
          rideId,
          imageUrl: uploadedImage.url,
          senderId,
          senderRole
        });
        console.log(`[SendImage Debug] Emitted image to recipient ${recipientId}`);
      } else {
          console.warn(`[SendImage Warning] Recipient ${recipientId} has no active socket connection.`);
      }
      // Also emit back to the sender so they can see their own sent image in their chat view
      // Only if sender and recipient are different users
      if (senderSocketId && senderId.toString() !== recipientId.toString()) {
          io.to(senderSocketId).emit('imageMessage', {
            rideId,
            imageUrl: uploadedImage.url,
            senderId,
            senderRole
          });
          console.log(`[SendImage Debug] Emitted image back to sender ${senderId}`);
      }
    }

    return res.status(200).json({
      message: "Image sent successfully",
      success: true,
      error: false,
      data: { imageUrl: uploadedImage.url }
    });

  } catch (error) {
    console.error("🔥 Send Image Error caught in controller:", error);
    // Include error details in the response for debugging purposes
    return res.status(500).json({
      message: error.message || "Failed to send image",
      error: true,
      success: false,
      details: error.stack
    });
  }
};