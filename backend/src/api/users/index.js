const { Router } = require('express');
const controller = require('./controller');
const { registerSchema, loginSchema, sendVerificationMailSchema, changePasswordSchema } = require('../../utils/zodValidators');
const { validateSchema, verifyJWT, isVerified, mailSent } = require('../../utils/Middleware');

const router = Router();

router.get('/me', verifyJWT, controller.getUser);

router.put('/update', verifyJWT, controller.updateUser)

module.exports = router;