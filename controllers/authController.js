const express = require('express');
const {
  login,
  getMe,
  forgotPassword,
  resetPassword,
  updateDetails,
  updatePassword,
  logout
} = require('./authcontroller');

const router = express.Router();

const { protect } = require('../middleware/auth');

router.post('/login', login);
router.get('/me', protect, getMe);                                                         
router.put('/updatedetails', protect, updateDetails);
router.put('/updatepassword', protect, updatePassword);
router.post('/forgotpassword', forgotPassword);
router.put('/resetpassword/:resettoken', resetPassword);
router.get('/logout', protect, logout);

module.exports = router;