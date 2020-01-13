const express = require('express');
const connectDB = require('./config/db');

// Express server
const app = express();

// Connect database
connectDB();

// Init Middleware
app.use(express.json({ extented: false }));

// Routes to check endpoints

app.use('/api/users', require('./controllers/userController'));

// Server PORT

const PORT = process.env.PORT || 5000;

// Server listning on PORT
app.listen(PORT, () => console.log(`Server started on PORT ${PORT}`));
