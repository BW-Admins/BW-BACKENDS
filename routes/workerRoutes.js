const express = require('express');
const { createWorker } = require('../controllers/workerController');

const router = express.Router();

// POST route for registering workers
router.post('/registerWorker', createWorker);

module.exports = router;
