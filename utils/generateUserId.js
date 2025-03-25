const generateUserId = () => {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let userId = "";
    for (let i = 0; i < 8; i++) {
      userId += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return userId;
  };
  
  module.exports = generateUserId;
  