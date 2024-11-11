import mongoose from 'mongoose';

const AdminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    username: { type: String, required: true, unique: true },  
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: true },
});

export default mongoose.model('Admin', AdminSchema);
