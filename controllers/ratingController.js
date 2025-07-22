const Rating = require('../models/rating');

// Submit a rating
exports.submitRating = async (req, res) => {
  try {
    const { rideId, fromUser, toUser, rating, feedback } = req.body;
    const newRating = new Rating({ rideId, fromUser, toUser, rating, feedback });
    await newRating.save();
    res.status(201).json({ message: 'Rating submitted', data: newRating });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit rating' });
  }
};

// Get ratings for a user (as driver or rider)
exports.getRatingsForUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const ratings = await Rating.find({ toUser: userId });
    res.json({ data: ratings });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch ratings' });
  }
};

// Get ratings given by a user
exports.getRatingsByUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const ratings = await Rating.find({ fromUser: userId });
    res.json({ data: ratings });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch ratings' });
  }
};
