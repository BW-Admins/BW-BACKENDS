const Worker = require("../models/Worker");

// Create a new worker
const createWorker = async (req, res) => {
  try {
    const worker = new Worker(req.body); // Create new worker document
    await worker.save(); // Save to database
    res
      .status(201)
      .json({ message: "Worker registered successfully!", worker });
  } catch (error) {
    res.status(500).json({ message: "Error registering worker.", error });
  }
};

module.exports = { createWorker };
