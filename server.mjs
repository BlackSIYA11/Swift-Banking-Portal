import express from 'express';
import mongoose from 'mongoose';
import helmet from 'helmet';
import cors from 'cors';
import authRoutes from './routes/auth.mjs';
import paymentRoutes from './routes/payments.mjs';
import adminAuthRoutes from './routes/adminAuth.mjs';
import adminPaymentRoutes from './routes/adminPayments.mjs';
import payeeAccountRoutes from './routes/payeeAccountRoutes.mjs'; 
import https from 'https';
import fs from 'fs';
import rateLimit from 'express-rate-limit';
import xss from 'xss-clean';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

// Middleware
app.use(express.json());

app.use(cors({
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
}));

app.use(helmet());
app.use(xss());

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

app.use(helmet.frameguard({ action: 'deny' }));
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}));

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// Routes
app.use('/api', authRoutes);
app.use('/api', paymentRoutes);
app.use('/api/admin', adminAuthRoutes);  // Admin routes
app.use('/api/admin', adminPaymentRoutes);  // Admin payment routes
app.use('/api', payeeAccountRoutes); 

const PORT = process.env.PORT || 5000;

const sslOptions = {
    key: fs.readFileSync('keys/privatekey.pem'),
    cert: fs.readFileSync('keys/certificate.pem'),
};

https.createServer(sslOptions, app)
    .listen(PORT, () => {
        console.log(`Secure server running on port ${PORT}`);
    });
