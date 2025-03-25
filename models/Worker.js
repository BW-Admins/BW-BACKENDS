const mongoose = require("mongoose");

// Check if the model is already compiled
const Worker =
  mongoose.models.Worker ||
  mongoose.model(
    "Worker",
    new mongoose.Schema({
      name: { type: String, required: true },
      email: { type: String, required: true, unique: true },
      mobile: { type: String, required: true },
      secondaryMobile: { type: String },
      jobTitle: { type: String, required: true },
      jobRole: { type: String, required: true },
      experience: { type: String },
      workAvailability: { type: String },
      skills: { type: String },
      expectedSalary: { type: String },
    })
  );

module.exports = Worker;
