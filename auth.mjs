import express from 'express';
import bcrypt from 'bcryptjs';
import User from '../models/user.mjs';
import jwt from 'jsonwebtoken';
import { check, validationResult } from 'express-validator';

const router = express.Router();

// User Registration
router.post('/register', [
    check('fullName')
        .notEmpty().withMessage('Full name is required')
        .matches(/^[A-Za-z\s]+$/).withMessage('Full name must only contain letters and spaces'),
    check('username')
        .notEmpty().withMessage('Username is required')
        .isAlphanumeric().withMessage('Username must be alphanumeric')
        .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    check('idNumber')
        .isLength({ min: 6, max: 13 }).withMessage('ID number must be between 6 and 13 characters')
        .matches(/^\d+$/).withMessage('ID number must be numeric'),
    check('accountNumber')
        .notEmpty().withMessage('Account number is required')
        .matches(/^\d+$/).withMessage('Account number must be numeric'),
    check('password')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { fullName, username, idNumber, accountNumber, password } = req.body;

    // Hash and salt password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ fullName, username, idNumber, accountNumber, password: hashedPassword });
    
    try {
        await newUser.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ message: 'Error registering user', error: err.message });
    }
});

// User Login
router.post('/login', [
    check('username')
        .notEmpty().withMessage('Username is required'),
    check('accountNumber')
        .notEmpty().withMessage('Account number is required')
        .matches(/^\d+$/).withMessage('Account number must be numeric'),
    check('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, accountNumber, password } = req.body;

    try {
        // Find the user by both username and account number
        const user = await User.findOne({ username, accountNumber });
        if (!user) return res.status(400).json({ message: 'Login failed: Invalid credentials' });

        // Check if password is correct
        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ message: 'Login failed: Invalid credentials' });

        // Generate JWT token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Return success message and token
        res.status(200).json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ message: 'Login failed: Server error', error: err.message });
    }
});

export default router;
