const express = require('express');
const router = express.Router();
const {
  registerUser,
  verifyOtp,
  setPassword,
  loginUser,
  forgotPassword,
  verifyForgotOtp,
  resetPassword,
} = require('../controllers/authController');

router.post('/register', registerUser);
router.post('/verify-otp', verifyOtp);
router.post('/set-password', setPassword);
router.post('/login', loginUser);
router.post('/forgot-password', forgotPassword);
router.post('/verify-forgot-otp', verifyForgotOtp);
router.post('/reset-password', resetPassword);

module.exports = router;
