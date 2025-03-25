const express = require("express");
const {
  getEmployeesBySpecificRole,
} = require("../controllers/employeeController");

const router = express.Router();

router.get("/employees", getEmployeesBySpecificRole);

module.exports = router;
