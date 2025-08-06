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
      ref: "User",
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
      ref: "User",
      required: true
    },
    otp: {
      type: String,
      default: null
    }
  },
  { _id: true }
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
      default: null // Password can be null if signing up with Google
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
    upcoming_rides: [rideSchema],
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
    vehicle_info: { // Vehicle details for drivers
      type: String,
      default: null
    },
    license_number: { // Driving license number for drivers
      type: String,
      default: null
    },
    is_verified_driver: { // For optional admin verification of driver documents
      type: Boolean,
      default: false
    },
    isOnline: {
      type: Boolean,
      default: false
    },
    googleId: { // New field for Google's unique user ID (sub)
        type: String,
        default: null,
        unique: true, // Ensure each Google ID is unique
        sparse: true // Allows multiple documents to have null values, but unique for non-nulls
    }
  },
  {
    timestamps: true
  }
);

const UserModel = mongoose.model("User", userSchema);
export default UserModel;