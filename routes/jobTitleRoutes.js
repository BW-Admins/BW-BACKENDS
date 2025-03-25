const express = require("express");
const {
  getJobTitles,
  createJobTitle,
} = require("../controllers/jobTitleController");

const router = express.Router();

router.get("/jobTitle", getJobTitles);
router.post("/jobTitle", createJobTitle);

module.exports = router;
