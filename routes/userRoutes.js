const express = require("express");
const router = express.Router();
const {
  registerUser,
  deleteUser, // Added
  verifyOtp,
  loginUser,
  logoutUser,
  refreshTokenHandler,
  getUserData,
  updateUserData,
  getAllUsers,
} = require("../controllers/userController");
const { validateUser, handleValidationErrors } = require("../middlewares/validateUser");
const { validateOtp, handleValidationErrors: handleOtpValidationErrors } = require("../middlewares/validateOtp");

router.post("/register", validateUser, handleValidationErrors, registerUser);
router.delete("/user", deleteUser); // New delete route
router.post("/verify-otp", validateOtp, handleOtpValidationErrors, verifyOtp);
router.post("/login", loginUser);
router.post("/logout", logoutUser);
router.post("/refresh-token", refreshTokenHandler);
router.get("/user/:userId", getUserData);
router.put("/user/:userId", updateUserData);
router.get("/user", getAllUsers);

module.exports = router;
