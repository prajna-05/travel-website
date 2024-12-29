const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Serve static files from 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// User schema and model
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
});

const User = mongoose.model('User', userSchema);

// Booking schema and model
const bookingSchema = new mongoose.Schema({
    referenceId: String,
    destination: String,
    numPeople: Number,
    bookingDate: Date,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

const Booking = mongoose.model('Booking', bookingSchema);

// Register endpoint
app.post('/api/user/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save the new user with hashed password
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();  // Ensure this is saving to the database

        const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        // Log the error for debugging
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Login endpoint
app.post('/api/user/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Compare the entered password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Booking endpoint
app.post('/api/user/book', async (req, res) => {
    const { destination, numPeople, bookingDate } = req.body;
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const booking = new Booking({
            referenceId: `REF${Math.floor(Math.random() * 100000)}`,
            destination,
            numPeople,
            bookingDate,
            userId: decoded.id,
        });

        await booking.save();
        res.json(booking);
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
});

// Define route for the home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
