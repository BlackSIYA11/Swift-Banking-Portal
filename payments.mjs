import express from 'express';
import Transaction from '../models/Transaction.mjs';
import auth from '../middleware/auth.mjs';
import { check, validationResult } from 'express-validator';

const router = express.Router();

// Make Payment
router.post('/payments', auth, [
    check('amount').isNumeric().withMessage('Amount must be a number'),
    check('currency').not().isEmpty().withMessage('Currency is required'),
    check('provider').not().isEmpty().withMessage('Provider is required'),
    check('payeeAccount').not().isEmpty().withMessage('Payee account is required'),
    check('swiftCode').not().isEmpty().withMessage('SWIFT code is required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { amount, currency, provider, payeeAccount, swiftCode } = req.body;

    const transaction = new Transaction({
        userId: req.user.id,
        amount,
        currency,
        provider,
        payeeAccount,
        swiftCode,
    });

    try {
        await transaction.save();
        res.status(201).json({ message: 'Transaction successful', transaction });
    } catch (err) {
        res.status(500).json({ message: 'Error processing transaction', error: err.message });
    }
});

// Get Transactions
router.get('/transactions', auth, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user.id });
        res.status(200).json(transactions);
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving transactions', error: err.message });
    }
});

export default router;
