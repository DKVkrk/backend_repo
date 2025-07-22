import mongoose from "mongoose";
import dotenv from "dotenv";
import UserModel from "../models/User.js";

dotenv.config();

function isValidRide(ride) {
  return (
    ride.userId &&
    ride.pickup_location &&
    typeof ride.pickup_location.lat === "number" &&
    typeof ride.pickup_location.lng === "number" &&
    ride.pickup_location.address &&
    ride.dropoff_location &&
    typeof ride.dropoff_location.lat === "number" &&
    typeof ride.dropoff_location.lng === "number" &&
    ride.dropoff_location.address
  );
}

async function cleanupRides() {
  await mongoose.connect(process.env.MONGO_URL);

  const users = await UserModel.find({});
  let fixedCount = 0;

  for (const user of users) {
    const origUpcoming = user.upcoming_rides.length;
    const origHistory = user.ride_history.length;

    // Remove invalid rides from both arrays
    user.upcoming_rides = user.upcoming_rides.filter(isValidRide);
    user.ride_history = user.ride_history.filter(isValidRide);

    if (
      user.upcoming_rides.length !== origUpcoming ||
      user.ride_history.length !== origHistory
    ) {
      await user.save();
      fixedCount++;
    }
  }

  console.log(`Cleaned up users: ${fixedCount}`);
  mongoose.disconnect();
}

cleanupRides();