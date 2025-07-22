const express = require('express');
const router = express.Router();
const ratingController = require('../controllers/ratingController');

router.post('/', ratingController.submitRating);
router.get('/user/:userId', ratingController.getRatingsForUser);
router.get('/from/:userId', ratingController.getRatingsByUser);

module.exports = router;
