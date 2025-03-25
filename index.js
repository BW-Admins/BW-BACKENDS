require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const connectDB = require("./config/connectDB");
const userRoutes = require("./routes/userRoutes");
const workerRoutes = require("./routes/workerRoutes");
const jobTitleRoutes = require("./routes/jobTitleRoutes");
const employeeRoutes = require("./routes/employeeRoutes");

connectDB();

const app = express();

app.use(cors());
app.use(bodyParser.json());

app.use("/api/", userRoutes);
app.use("/api/", workerRoutes);
app.use("/api/", jobTitleRoutes); // Add job title routes
app.use("/api/", employeeRoutes); // Add employee routes

const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
