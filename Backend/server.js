// Import Dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Initialize App
const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('MongoDB Connected');
        initializeAdmin(); // Initialize admin after connecting to the database
    })
    .catch(err => console.error('MongoDB Connection Failed:', err));

// Models
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    designation: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isApproved: { type: Boolean, default: false },
    profilePicture: { type: String, default: 'https://via.placeholder.com/150' },
    connections: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    requests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
});

const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const contentSchema = new mongoose.Schema({
    content: { type: String, required: true }, // Stores the main page content
    lastUpdated: { type: Date, default: Date.now },
});

const Content = mongoose.model('Content', contentSchema);

const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);

// Middleware for Authentication
const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Function to Initialize Admin
const initializeAdmin = async () => {
    try {
        const adminEmail = "admin@example.com";
        const adminPassword = "admin123";

        const existingAdmin = await Admin.findOne({ email: adminEmail });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash(adminPassword, 10);
            const newAdmin = new Admin({ email: adminEmail, password: hashedPassword });
            await newAdmin.save();
            console.log(`Admin initialized with email: ${adminEmail}`);
        } else {
            console.log(`Admin already exists with email: ${adminEmail}`);
        }
    } catch (error) {
        console.error('Error initializing admin:', error);
    }
};

const initializeContent = async () => {
    try {
        const existingContent = await Content.findOne();
        if (!existingContent) {
            const defaultContent = new Content({ content: 'Welcome to the website!' });
            await defaultContent.save();
            console.log('Initialized default content in the database');
        }
    } catch (err) {
        console.error('Error initializing content:', err);
    }
};

// Serve Static Files
app.use(express.static(path.join(__dirname, '../frontend')));

// Routes

// User Signup
app.post('/api/auth/register', async (req, res) => {
    const { name, designation, email, password, confirmPassword } = req.body;

    if (password !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: 'User already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ name, designation, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered. Awaiting admin approval.' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        if (!user.isApproved) return res.status(403).json({ message: 'User not approved' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ token, user });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Admin Login
app.post('/api/auth/admin-login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const admin = await Admin.findOne({ email });
        if (!admin) return res.status(404).json({ message: 'Admin not found' });

        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: admin._id, isAdmin: true }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.status(200).json({ token });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

const verifyAdmin = async (req, res, next) => {
    try {
        const admin = await Admin.findById(req.user.id);
        if (!admin) return res.status(403).json({ message: 'Not authorized as admin' });
        next();
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

// Add this new endpoint to verify admin status
app.get('/api/users/me', authenticate, async (req, res) => {
    try {
        if (req.user.isAdmin) {
            const admin = await Admin.findById(req.user.id);
            if (admin) {
                return res.json({ isAdmin: true });
            }
        }
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ isAdmin: false, ...user._doc });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Update your existing admin endpoints to use the verifyAdmin middleware
app.get('/api/admin/pending-requests', authenticate, verifyAdmin, async (req, res) => {
    try {
        const pendingUsers = await User.find({ isApproved: false }).select('name email designation');
        res.status(200).json(pendingUsers);
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/admin/approve/:id', authenticate, verifyAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        user.isApproved = true;
        await user.save();

        res.status(200).json({ message: 'User approved' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/admin/reject/:id', authenticate, verifyAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        await User.deleteOne({ _id: req.params.id });
        res.status(200).json({ message: 'User rejected and removed' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Send Connection Request
app.post('/api/connections/send/:id', authenticate, async (req, res) => {
    try {
        const recipient = await User.findById(req.params.id);
        const sender = await User.findById(req.user.id);

        if (!recipient || !sender) return res.status(404).json({ message: 'User not found' });
        if (recipient.requests.includes(sender._id)) return res.status(400).json({ message: 'Request already sent' });

        recipient.requests.push(sender._id);
        await recipient.save();

        res.status(200).json({ message: 'Connection request sent' });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Respond to Connection Request
app.put('/api/connections/respond/:id', authenticate, async (req, res) => {
    const { action } = req.body; // "accept" or "decline"

    try {
        const sender = await User.findById(req.params.id);
        const recipient = await User.findById(req.user.id);

        if (!sender || !recipient) return res.status(404).json({ message: 'User not found' });

        if (!recipient.requests.includes(sender._id)) return res.status(400).json({ message: 'Request not found' });

        if (action === 'accept') {
            recipient.connections.push(sender._id);
            sender.connections.push(recipient._id);
        }

        recipient.requests = recipient.requests.filter(id => id.toString() !== sender._id.toString());
        await recipient.save();
        await sender.save();

        res.status(200).json({ message: `Request ${action}ed` });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get Connections, Requests, and Members
app.get('/api/connections/all', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).populate('connections', 'name designation email profilePicture');
        const allUsers = await User.find().select('name profilePicture');

        res.status(200).json({
            connections: user.connections,
            requests: user.requests,
            members: allUsers,
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

const contentFilePath = path.join(__dirname, 'content.md');


app.get('/getContent', async (req, res) => {
    try {
        const content = await Content.findOne();
        if (!content) return res.status(404).send('Content not found');
        res.status(200).send(content);
    } catch (err) {
        console.error('Error fetching content:', err);
        res.status(500).send('Server error');
    }
});

app.post('/updateContent', async (req, res) => {
    const { content } = req.body;

    if (!content) {
        return res.status(400).send('Content is required');
    }

    try {
        const updatedContent = await Content.findOneAndUpdate(
            {},
            { content, lastUpdated: Date.now() },
            { new: true, upsert: true } // Create a new document if none exists
        );
        res.status(200).send({ message: 'Content updated successfully', updatedContent });
    } catch (err) {
        console.error('Error updating content:', err);
        res.status(500).send('Server error');
    }
});



// Start Server
const PORT = process.env.PORT || 5002;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));