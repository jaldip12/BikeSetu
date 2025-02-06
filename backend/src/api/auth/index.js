const { Router } = require('express');
const controller = require('./controller');
const { registerSchema, loginSchema, sendVerificationMailSchema, changePasswordSchema } = require('../../utils/zodValidators');
const { validateSchema, verifyJWT, isVerified, verificationMailSent } = require('../../utils/Middleware');

const router = Router();

router.get('/me', verifyJWT, controller.getUser);

router.post('/register', validateSchema(registerSchema), controller.register);
router.post('/login', validateSchema(loginSchema), controller.login);
router.post('/logout', verifyJWT, controller.logout);

router.post('/send-reset-password-link', controller.sendResetPasswordLink);
router.get('/verify-reset-password-link/:token', controller.verifyResetPasswordLink);
router.post('/reset-password', controller.resetPassword);
router.post('/change-password', verifyJWT, validateSchema(changePasswordSchema), controller.changePassword);

router.get('/google', controller.continueWithGoogle);
router.get('/google/callback', controller.googleCallBack);

router.post('/send-verification-mail', verifyJWT, verificationMailSent, controller.sendVerificationMail);
router.put('/verify/:token', controller.verify);

module.exports = router;