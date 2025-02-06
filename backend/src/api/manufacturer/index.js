const addBike = require('./add-bike');
const getBikes = require('./get-bikes');
const updateBikeStatus = require('./update-bike-status-manufacturer');
const { Router } = require('express');
const {verifyJWT, isManufacturer} = require("../../utils/Middleware");

const router = Router();

router.post('/bikes', verifyJWT, isManufacturer, addBike);
router.get('/bikes', verifyJWT, isManufacturer, getBikes);
router.put('/bikes/:bikeId/status', verifyJWT, isManufacturer, updateBikeStatus);

module.exports = router;
