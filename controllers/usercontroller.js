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

/*
|----------------------------------------------------------
| Register (User / Driver with Role-based Control)
|----------------------------------------------------------
*/
// export async function registerUserController(request, response) {
//     try {
//         console.log("Incoming user data:", request.body);

//         const { name, email, password, role = 'user', licenseNumber } = request.body;

//         if (!name || !email || !password || !role) {
//             return response.status(400).json({ message: "Provide name, email, password, and role", success: false, error: true });
//         }

//         if (!['user', 'driver'].includes(role)) {
//             return response.status(400).json({ message: "Invalid role", success: false, error: true });
//         }

//         const existingUser = await UserModel.findOne({ email });
//         if (existingUser) {
//             return response.status(409).json({ message: "Email already registered", success: false, error: true });
//         }

//         if (role === 'driver' && !licenseNumber) {
//             return response.status(400).json({ message: "License number required for driver", success: false, error: true });
//         }

//         const salt = await bcryptjs.genSalt(10);
//         const hashPassword = await bcryptjs.hash(password, salt);

//         const newUser = new UserModel({
//             name,
//             email,
//             password: hashPassword,
//             role,
//             license_number: role === 'driver' ? licenseNumber : null,
//             verify_license: role === 'driver' ? false : null,
//             verify_email: false
//         });

//         const savedUser = await newUser.save();

//         const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${savedUser._id}`;
//         await sendEmail({
//             sendTo: email,
//             subject: "Verify your email - Rilo",
//             html: verifyEmailTemplate({ name, url: verifyEmailUrl })
//         });

//         return response.status(201).json({
//             message: "Registered successfully. Verify your email.",
//             success: true,
//             error: false,
//             data: savedUser
//         });
//     } catch (error) {
//         console.error("🔥 Registration Error:", error);
//         return response.status(500).json({ message: error.message || error, success: false, error: true });
//     }
// }
export async function registerUserController(request, response) {
  try {
    const { name, email, password } = request.body;

    if (!name || !email || !password) {
      return response.status(400).json({ message: "Provide name, email, and password", success: false, error: true });
    }

    const existingUser = await UserModel.findOne({ email });
    if (existingUser) {
      return response.status(409).json({ message: "Email already registered", success: false, error: true });
    }

    const salt = await bcryptjs.genSalt(10);
    const hashPassword = await bcryptjs.hash(password, salt);

    const newUser = new UserModel({
      name,
      email,
      password: hashPassword,
      role: 'user',          // default role
      license_number: null,
      verify_license: null,
      verify_email: false
    });

    const savedUser = await newUser.save();

    const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email?code=${savedUser._id}`;
    await sendEmail({
      sendTo: email,
      subject: "Verify your email - Rilo",
      html: verifyEmailTemplate({ name, url: verifyEmailUrl })
    });

    return response.status(201).json({
      message: "User registered successfully. Verify your email.",
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
            success: false,
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

        // Notify all riders about driver status change
        if (req.app.get('io')) {
            req.app.get('io').emit('driverStatusChanged', {
                driverId: driver._id,
                isOnline: driver.isOnline
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
      console.log("[DEBUG] New ride created with OTP:", newRide.otp); // Debug log
  
      // Emit socket event
      const io = req.app.get('io');
      if (io) {
        io.emit('newRideRequest', {
          ...newRide.toObject(),
          userId: userId.toString(),
          rideIndex,
          _id: newRide._id.toString(),
          otp // Also send OTP in the event
        });
      }
  
      return res.status(201).json({
        message: "Ride requested successfully",
        error: false,
        success: true,
        data: {
          rideId: newRide._id,
          rideIndex,
          otp // Return OTP in the response
        }
      });
    } catch (error) {
      console.error("Ride request error:", error);
      return res.status(500).json({
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

        // Validate inputs
        if (!userId || rideIndex === undefined || isNaN(rideIndex) || rideIndex < 0) {
            return res.status(400).json({
                message: "userId and a valid rideIndex are required",
                error: true,
                success: false,
            });
        }

        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: "User not found",
                error: true,
                success: false,
            });
        }
        if (!Array.isArray(user.upcoming_rides) || rideIndex >= user.upcoming_rides.length) {
            return res.status(400).json({
                message: "Invalid ride index for this user",
                error: true,
                success: false,
            });
        }
        const driver = await UserModel.findById(driverId);
        if (!driver) {
            return res.status(404).json({
                message: "Driver not found",
                error: true,
                success: false,
            });
        }

        const ride = user.upcoming_rides[rideIndex];
        if (!ride) {
            return res.status(404).json({
                message: "Ride not found at the given index",
                error: true,
                success: false,
            });
        }

        // Check ride status
        if (ride.status !== "requested" || ride.driver !== null) {
            return res.status(409).json({
                message: "Ride has already been accepted or is no longer available",
                error: true,
                success: false,
            });
        }

        // Check if driver is online
        if (!driver.isOnline) {
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

        // Emit socket event
        const io = req.app.get('io');
        if (io) {
            io.emit('driverAcceptsRide', {
                rideId: user.upcoming_rides[rideIndex]._id,
                driverId,
                userId,
                driverName: driver.name,
                vehicleType: user.upcoming_rides[rideIndex].vehicle_type
            });

            // Notify other drivers that this ride is taken
            io.emit('rideAcceptedByOther', {
                rideId: user.upcoming_rides[rideIndex]._id
            });
        }

        res.json({
            message: "Ride accepted successfully",
            error: false,
            success: true,
            data: {
                rideId: user.upcoming_rides[rideIndex]._id,
                userId
            }
        });
    } catch (error) {
        console.error("Accept Ride Error:", error);
        res.status(500).json({
            message: error.message || "Failed to accept ride",
            error: true,
            success: false,
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
  
      // Emit socket event to notify rider
      const io = req.app.get('io');
      if (io) {
        io.emit('driverRejectsRide', {
          rideId: user.upcoming_rides[rideIndex]._id,
          userId
        });
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
  
      // Ensure the ride is indeed assigned to this driver and is accepted
      if (ride.driver.toString() !== driverId.toString() || ride.status !== "accepted") {
        return res.status(403).json({
          message: "You are not authorized to complete this ride or it's not accepted yet.",
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
      const io = req.app.get('io');
      if (io) {
        io.emit('rideCompleted', {
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
        const io = req.app.get('io');
        if (io) {
          io.emit('rideCancelled', {
            rideId,
            driverId: ride.driver
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
  
      // Emit socket event to update driver location
      const io = req.app.get('io');
      if (io) {
        io.emit('updateDriverLocation', {
          driverId,
          location: { lat, lng }
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

        // Find rides where this driver is assigned and the status is 'accepted'
        const usersWithAcceptedRides = await UserModel.find({
            "upcoming_rides.driver": driverId,
            "upcoming_rides.status": "accepted",
        });

        const acceptedRides = [];
        usersWithAcceptedRides.forEach(user => {
            user.upcoming_rides.forEach((ride, index) => {
                if (ride.driver && ride.driver.toString() === driverId.toString() && ride.status === "accepted") {
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

        // Find the most recent requested/accepted ride
        const activeRide = user.upcoming_rides.find(ride => 
            ride.status === "requested" || ride.status === "accepted"
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
                pickup_location: activeRide.pickup_location,
                dropoff_location: activeRide.dropoff_location,
                fare: activeRide.fare,
                vehicle_type: activeRide.vehicle_type,
                requested_at: activeRide.requested_at,
                driver: driverDetails
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
    console.log("[DEBUG] getRideById ride:", ride);
    if (!ride) return res.status(404).json({ message: "Ride not found", error: true, success: false });
    return res.json({ message: "Ride fetched", error: false, success: true, data: ride });
  } catch (error) {
    return res.status(500).json({ message: error.message || error, error: true, success: false });
  }
};

