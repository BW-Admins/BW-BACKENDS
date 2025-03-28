const User = require("../models/User");
const { generateOtp } = require("../utils/otpUtils");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwtUtils");

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Send OTP via email
const sendOtpEmail = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "OTP for Email Verification",
    text: `Your OTP is: ${otp}`,
  };
  await transporter.sendMail(mailOptions);
};

// Register User
const registerUser = async (req, res) => {
  const { name, email, mobile, password, acceptNotifications } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }
    // Removed mobile uniqueness check
    // const existingMobile = await User.findOne({ mobile });
    // if (existingMobile) {
    //   return res.status(400).json({ message: "Mobile number already exists" });
    // }

    const hashedPassword = await bcrypt.hash(password, 12);
    const otp = generateOtp();
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    const user = new User({
      name,
      email,
      mobile,
      password: hashedPassword,
      acceptNotifications,
      otp,
      otpExpiry,
      isOtpVerified: false,
      failedOtpAttempts: 0,
      accountLocked: false,
    });

    await user.save();
    try {
      await sendOtpEmail(email, otp);
    } catch (emailError) {
      console.error("Email Error:", emailError);
      return res.status(500).json({ message: "Error sending OTP. Try again later." });
    }
    res.status(201).json({ message: "OTP sent to your email", userId: user.userId });
  } catch (error) {
    if (error.code === 11000) { // MongoDB duplicate key error
      const field = Object.keys(error.keyValue)[0];
      return res.status(400).json({ message: `${field} already exists` });
    }
    console.error("Registration Error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
};

// Delete User
const deleteUser = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOneAndDelete({ email });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Delete Error:", error);
    res.status(500).json({ message: "Server error during deletion" });
  }
};

// ... (rest of the file unchanged: verifyOtp, loginUser, etc.)

module.exports = {
  registerUser,
  deleteUser,
  verifyOtp,
  loginUser,
  logoutUser,
  refreshTokenHandler,
  getUserData,
  updateUserData,
  getAllUsers,
};
