import express from 'express';
import Transaction from '../models/Transaction.mjs';
import authAdmin from '../middleware/authAdmin.mjs';

const router = express.Router();

// Get All Transactions (Admin view)
router.get('/transactions', authAdmin, async (req, res) => {
    try {
        const transactions = await Transaction.find({});
        res.status(200).json(transactions);
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving transactions', error: err.message });
    }
});

// Get a specific transaction (Admin view)
router.get('/transactions/:id', authAdmin, async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) return res.status(404).json({ message: 'Transaction not found' });
        res.status(200).json(transaction);
    } catch (err) {
        res.status(500).json({ message: 'Error retrieving transaction', error: err.message });
    }
});

// Update transaction status (Approve/Reject)
router.patch('/transactions/:id', authAdmin, async (req, res) => {
    try {
        const { status } = req.body;

        // Ensure that status is either 'approved' or 'rejected'
        if (!['approved', 'rejected'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status. Must be "approved" or "rejected".' });
        }

        // Find the transaction by ID and update the status
        const transaction = await Transaction.findByIdAndUpdate(
            req.params.id,
            { status: status },
            { new: true } // Return the updated document
        );

        if (!transaction) {
            return res.status(404).json({ message: 'Transaction not found' });
        }

        res.status(200).json({
            message: `Transaction ${status} successfully`,
            transaction,
        });
    } catch (err) {
        res.status(500).json({ message: 'Error updating transaction status', error: err.message });
    }
});

export default router;
