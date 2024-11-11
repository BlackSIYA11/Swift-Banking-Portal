import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    username: { type: String, required: true, unique: true },  
    idNumber: { type: String, required: true, unique: true },
    accountNumber: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

export default mongoose.model('User', UserSchema);
