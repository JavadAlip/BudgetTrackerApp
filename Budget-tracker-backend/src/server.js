const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');

require('dotenv').config();
connectDB();

const app = express();

app.use(cors());
app.use(express.json());

app.use('/auth', require('./routes/authRoutes'));

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
