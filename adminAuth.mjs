import express from 'express';
import bcrypt from 'bcryptjs';
import Admin from '../models/Admin.mjs';
import jwt from 'jsonwebtoken';
import { check, validationResult } from 'express-validator';

const router = express.Router();

// Admin Registration
router.post('/register', [
    check('fullName').notEmpty().withMessage('Full name is required'),
    check('username').isAlphanumeric().isLength({ min: 3 }).withMessage('Username must be alphanumeric and at least 3 characters'),
    check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { fullName, username, password } = req.body;

    // Hash and salt password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newAdmin = new Admin({ fullName, username, password: hashedPassword });
    
    try {
        await newAdmin.save();
        res.status(201).json({ message: 'Admin registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error registering admin', error: err.message });
    }
});

// Admin Login
router.post('/login', [
    check('username').notEmpty().withMessage('Username is required'),
    check('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;

    try {
        const admin = await Admin.findOne({ username });
        if (!admin) return res.status(400).json({ message: 'Login failed: Invalid credentials' });

        const validPass = await bcrypt.compare(password, admin.password);
        if (!validPass) return res.status(400).json({ message: 'Login failed: Invalid credentials' });

        const token = jwt.sign({ id: admin._id, isAdmin: admin.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ message: 'Login failed: Server error', error: err.message });
    }
});

export default router;
