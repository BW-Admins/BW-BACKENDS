const generateOtp = () => Math.floor(1000 + Math.random() * 9000).toString();

const isOtpExpired = (otpExpiry) => {
  return Date.now() > new Date(otpExpiry).getTime();
};

module.exports = { generateOtp, isOtpExpired };