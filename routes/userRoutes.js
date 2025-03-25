const express = require("express");
const router = express.Router();
const {
  registerUser,
  verifyOtp,
  loginUser,
  logoutUser,
  refreshTokenHandler,
  getUserData,
  updateUserData,
  getAllUsers, // New function added
} = require("../controllers/userController");
const {
  validateUser,
  handleValidationErrors,
} = require("../middlewares/validateUser");
const {
  validateOtp,
  handleValidationErrors: handleOtpValidationErrors,
} = require("../middlewares/validateOtp");

router.post("/register", validateUser, handleValidationErrors, registerUser);
router.post("/verify-otp", validateOtp, handleOtpValidationErrors, verifyOtp);
router.post("/login", loginUser);
router.post("/logout", logoutUser);
router.post("/refresh-token", refreshTokenHandler);
router.get("/user/:userId", getUserData); // Fetch single user
router.put("/user/:userId", updateUserData); // Update user
router.get("/user", getAllUsers); // Fetch all users

module.exports = router;