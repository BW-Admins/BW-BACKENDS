const JobTitle = require("../models/JobTitle");

// Fetch all job titles
const getJobTitles = async (req, res) => {
  try {
    const jobTitles = await JobTitle.find();
    res.status(200).json(jobTitles); // Corrected typo
  } catch (error) {
    res.status(500).json({ message: "Error fetching job titles.", error });
  }
};

// Create a new job title
const createJobTitle = async (req, res) => {
  try {
    const { title } = req.body;
    const jobTitle = new JobTitle({ title });
    await jobTitle.save();
    res
      .status(201)
      .json({ message: "Job title created successfully!", jobTitle });
  } catch (error) {
    res.status(500).json({ message: "Error creating job title.", error });
  }
};

module.exports = { getJobTitles, createJobTitle };
