const express = require('express');
const router = express.Router();
const driverController = require('../controllers/driverController');

// Toggle driver availability
router.patch('/:id/availability', driverController.toggleAvailability);

// Get all online drivers
router.get('/online', driverController.getOnlineDrivers);

// Get driver earnings
router.get('/:id/earnings', driverController.getEarnings);

module.exports = router;
