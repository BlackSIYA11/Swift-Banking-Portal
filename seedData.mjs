import mongoose from 'mongoose';

// Ensure the correct path to the model file
import PayeeAccount from './models/payeeAccount.mjs'; 

// Connecting to the "test" database
mongoose.connect('mongodb://localhost:27017/test', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const payeeAccounts = [
    { payeeAccount: '123456789', swiftCode: 'BANKUSXX', provider: 'Bank' },
    { payeeAccount: '123456789', swiftCode: 'BANKUSXX', provider: 'Bank' },
    { payeeAccount: '12365780', swiftCode: 'BANKZARAB', provider: 'Absa Bank' },
    { payeeAccount: '123456798', swiftCode: 'ABSAZAR', provider: 'SWIFT' },
    { payeeAccount: '223456789', swiftCode: 'BANKUSYY', provider: 'Bank' },
    { payeeAccount: '223456789', swiftCode: 'BANKUSYY', provider: 'Bank' },
    { payeeAccount: '323457890', swiftCode: 'BANKUKXX', provider: 'HSBC' },
    { payeeAccount: '423456789', swiftCode: 'BANKUKYY', provider: 'Barclays' },
    { payeeAccount: '523456789', swiftCode: 'BANKZAAC', provider: 'Capitec Bank' },
    { payeeAccount: '623456789', swiftCode: 'BANKZAAD', provider: 'Standard Bank' },
    { payeeAccount: '723456789', swiftCode: 'BANKZAEE', provider: 'FNB' },
];

// Function to seed the PayeeAccount collection in the "test" database
const seedDatabase = async () => {
    try {
        // Insert data into the "payeeaccounts" collection (the fourth collection)
        await PayeeAccount.insertMany(payeeAccounts);
        console.log('Seed data inserted into the fourth collection (payeeaccounts)!');
    } catch (error) {
        console.error('Error inserting seed data:', error);
    } finally {
        mongoose.disconnect();  // Disconnect after the operation is complete
    }
};

// Export the seedDatabase function
export { seedDatabase };
