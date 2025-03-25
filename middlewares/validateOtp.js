const { body, validationResult } = require('express-validator');

const validateOtp = [
  body('email').isEmail().withMessage('Invalid email'),
  body('otp').isLength({ min: 4, max: 4 }).withMessage('OTP must be 4 digits'),
];

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

module.exports = { validateOtp, handleValidationErrors };