// routes/payeeAccountRoutes.mjs
import express from 'express';
import { getPredefinedPayeeAccounts } from '../controllers/payeeAccountController.mjs';

const router = express.Router();

// Route to fetch predefined payee accounts
router.get('/payee-accounts', getPredefinedPayeeAccounts);

export default router;
