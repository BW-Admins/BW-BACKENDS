const User = require("../models/User");
const { generateOtp, isOtpExpired } = require("../utils/otpUtils");
const nodemailer = require("nodemailer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/jwtUtils");

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
      return res.status(400).json({ message: "User already exists" });
    }

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
      return res
        .status(500)
        .json({ message: "Error sending OTP. Try again later." });
    }

    res
      .status(201)
      .json({ message: "OTP sent to your email", userId: user.userId });
  } catch (error) {
    console.error("Registration Error:", error);
    res.status(500).json({ message: "Server error during registration" });
  }
};

// Verify OTP
const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.accountLocked) {
      return res
        .status(400)
        .json({ message: "Account locked due to too many failed attempts" });
    }

    if (!user.otp || new Date() > new Date(user.otpExpiry)) {
      return res
        .status(400)
        .json({ message: "OTP expired. Request a new one." });
    }

    if (user.otp !== otp) {
      user.failedOtpAttempts += 1;
      if (user.failedOtpAttempts >= 3) {
        user.accountLocked = true;
      }
      await user.save();
      return res.status(400).json({ message: "Invalid OTP" });
    }

    user.isOtpVerified = true;
    user.otp = null;
    user.otpExpiry = null;
    user.failedOtpAttempts = 0;
    await user.save();

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("OTP Verification Error:", error);
    res.status(500).json({ message: "Server error during OTP verification" });
  }
};

// Login User
const loginUser = async (req, res) => {
  try {
    const { email, password, rememberMe } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    if (!user.isOtpVerified) {
      return res
        .status(403)
        .json({ message: "Please verify your email first" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    user.refreshToken = refreshToken;
    user.isRememberMe = rememberMe;
    user.isLoggedIn = true;
    user.lastLoggedIn = new Date();
    await user.save();

    res.status(200).json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        userId: user.userId,
        name: user.name,
        email: user.email,
        mobile: user.mobile,
        isLoggedIn: user.isLoggedIn,
      },
    });
  } catch (error) {
    console.error("Server Error during login:", error);
    res.status(500).json({ message: "Server error during login" });
  }
};

// Logout User
const logoutUser = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res
        .status(400)
        .json({ message: "User ID is required for logout" });
    }

    const user = await User.findOne({ userId });
    if (!user) return res.status(404).json({ message: "User not found" });

    user.isLoggedIn = false;
    user.refreshToken = null;
    await user.save();

    res.json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout Error:", error);
    res.status(500).json({ message: "Server error. Try again." });
  }
};

// Fetch Single User Data
const getUserData = async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findOne({ userId });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ message: "Server error fetching user data" });
  }
};

// Fetch All Users
const getAllUsers = async (req, res) => {
  try {
    const users = await User.find(); // Fetch all users
    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching all users:", error);
    res.status(500).json({ message: "Server error fetching users" });
  }
};

// Update User Data
const updateUserData = async (req, res) => {
  try {
    const userId = req.params.userId;
    const updatedData = req.body;
    const user = await User.findOneAndUpdate({ userId }, updatedData, {
      new: true,
    });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(user);
  } catch (error) {
    res.status(400).json({ message: "Error updating user", error });
  }
};

// Refresh Token Handler
const refreshTokenHandler = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken)
      return res.status(403).json({ message: "Refresh token required" });

    const user = await User.findOne({ refreshToken });
    if (!user)
      return res.status(403).json({ message: "Invalid refresh token" });

    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (err, decoded) => {
        if (err)
          return res
            .status(403)
            .json({ message: "Invalid or expired refresh token" });

        const newAccessToken = jwt.sign(
          { id: user._id },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "1h" }
        );
        const newRefreshToken = jwt.sign(
          { id: user._id },
          process.env.REFRESH_TOKEN_SECRET,
          { expiresIn: "7d" }
        );

        user.refreshToken = newRefreshToken;
        user.save();

        res.json({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        });
      }
    );
  } catch (error) {
    console.error("Refresh Token Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
};

module.exports = {
  registerUser,
  verifyOtp,
  loginUser,
  logoutUser,
  refreshTokenHandler,
  getUserData,
  updateUserData,
  getAllUsers,
};