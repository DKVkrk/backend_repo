import mongoose from "mongoose";

const rideSchema = new mongoose.Schema(
  {
    pickup_location: {
      lat: { type: Number, required: true },
      lng: { type: Number, required: true },
      address: { type: String, required: true }
    },
    dropoff_location: {
      lat: { type: Number, required: true },
      lng: { type: Number, required: true },
      address: { type: String, required: true }
    },
    driver: {
      type: mongoose.Schema.ObjectId,
      ref: "User", // Changed to "User" to correctly reference the User model
      default: null
    },
    status: {
      type: String,
      enum: ["requested", "accepted", "ongoing", "completed", "cancelled"],
      default: "requested"
    },
    fare: {
      type: Number,
      default: 0
    },
    vehicle_type: {
      type: String,
      default: "Standard Car"
    },
    requested_at: {
      type: Date,
      default: Date.now
    },
    accepted_at: {
      type: Date,
      default: null
    },
    completed_at: {
      type: Date,
      default: null
    },
    userId: {
      type: mongoose.Schema.ObjectId,
      ref: "User", // Changed to "User"
      required: true
    },
    otp: {
      type: String,
      default: null
    }
  },
  { _id: true } // Ensure _id is generated for subdocuments
);

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Provide name"]
    },
    email: {
      type: String,
      required: [true, "Provide email"],
      unique: true
    },
    password: {
      type: String,
      required: [true, "Provide password"]
    },
    avatar: {
      type: String,
      default: ""
    },
    mobile: {
      type: Number,
      default: null
    },
    current_location: {
      lat: { type: Number, default: null },
      lng: { type: Number, default: null }
    },
    refresh_token: {
      type: String,
      default: ""
    },
    verify_email: {
      type: Boolean,
      default: false
    },
    last_login_date: {
      type: Date,
      default: null
    },
    status: {
      type: String,
      enum: ["active", "inactive", "suspended"],
      default: "active"
    },
    address_details: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "address"
      }
    ],
    ride_history: [rideSchema],
    upcoming_rides: [rideSchema], // Holds pending, accepted, and ongoing rides
    preferred_payment_methods: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "payment"
      }
    ],
    forgot_password_otp: {
      type: String,
      default: null
    },
    forgot_password_expiry: {
      type: Date,
      default: null
    },
    role: {
      type: String,
      enum: ["admin", "user", "driver"],
      default: "user"
    },
    vehicle_info: {
      type: String,
      default: null
    },
    license_number: {
      type: String,
      default: null
    },
    is_verified_driver: {
      type: Boolean,
      default: false
    },
    isOnline: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
);

const UserModel = mongoose.model("User", userSchema);
export default UserModel;