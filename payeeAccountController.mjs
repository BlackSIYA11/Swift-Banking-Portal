import PayeeAccount from '../models/payeeAccount.mjs';

export const getPredefinedPayeeAccounts = async (req, res) => {
    try {
        const payeeAccounts = await PayeeAccount.find();
        return res.status(200).json(payeeAccounts);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching payee accounts' });
    }
};
