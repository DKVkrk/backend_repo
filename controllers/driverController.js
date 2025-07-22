const User = require('../models/User.js');

// Toggle driver availability (online/offline)
exports.toggleAvailability = async (req, res) => {
  try {
    const { id } = req.params;
    const { isOnline } = req.body;
    const driver = await User.findByIdAndUpdate(
      id,
      { isOnline },
      { new: true }
    );
    if (!driver) return res.status(404).json({ error: 'Driver not found' });
    res.json({ message: 'Availability updated', data: driver });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update driver availability' });
  }
};

// List all online drivers
exports.getOnlineDrivers = async (req, res) => {
  try {
    const drivers = await User.find({ role: 'driver', isOnline: true });
    res.json({ data: drivers });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch online drivers' });
  }
};

// Get driver earnings (aggregate)
exports.getEarnings = async (req, res) => {
  try {
    const { id } = req.params;
    const driver = await User.findById(id);
    if (!driver) return res.status(404).json({ error: 'Driver not found' });
    // Aggregate earnings from ride_history
    const earnings = (driver.ride_history || [])
      .filter(ride => ride.status === 'completed')
      .reduce((sum, ride) => sum + (ride.fare || 0), 0);
    res.json({ totalEarnings: earnings });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch earnings' });
  }
};
