const getBikes = require('./get-bikes');
const getBikeById = require('./get-bike-by-id');
const recommendBikes = require('./recommend-bikes');

const { Router } = require('express');

const router = Router();

router.get('/', getBikes);
router.get('/:id', getBikeById);
router.post('/recommend', recommendBikes);


module.exports = router;
