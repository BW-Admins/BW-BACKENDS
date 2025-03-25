const Worker = require("../models/Worker");

// Fetch employees by specific role
const getEmployeesBySpecificRole = async (req, res) => {
  try {
    const { specificRole } = req.query;
    const employees = await Worker.find({ jobRole: specificRole });
    res.status(200).json(employees);
  } catch (error) {
    res.status(500).json({ message: "Error fetching employees.", error });
  }
};

module.exports = { getEmployeesBySpecificRole };
