const updateStatus = require('./update-bike-status-franchisees');
const getBikes = require('./get-bikes');

const { Router } = require('express');
const { verifyJWT } = require('../../utils/Middleware');

const router = Router();

router.post('/update-status/:id', verifyJWT, updateStatus);
router.get('/bikes', verifyJWT, getBikes);

module.exports = router;
