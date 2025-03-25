const mongoose = require("mongoose");

const JobTitleSchema = new mongoose.Schema({
  title: { type: String, required: true, unique: true },
});

const JobTitle = mongoose.model("JobTitle", JobTitleSchema);

module.exports = JobTitle;
