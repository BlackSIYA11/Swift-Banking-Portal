// models/payeeAccount.mjs
import mongoose from 'mongoose';

const payeeAccountSchema = new mongoose.Schema({
    payeeAccount: {
        type: String,
        required: true,
    },
    swiftCode: {
        type: String,
        required: true,
    },
    provider: {
        type: String,
        required: true,
    },
});

const PayeeAccount = mongoose.model('PayeeAccount', payeeAccountSchema);

export default PayeeAccount;
