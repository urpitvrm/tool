import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config } from './src/config/index.js';
import userRoutes from './src/routes/user.routes.js';
import systemRoutes from './src/routes/system.routes.js';
import apiRoutes from './src/routes/api.routes.js';
import { errorHandler } from './src/utils/helpers.js';

const app = express();

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: config.corsOrigins, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.use('/api/v1/auth/login', rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false }));

app.use('/api/v1', systemRoutes);
app.use('/api/v1', userRoutes);
app.use('/api/v1', apiRoutes);
app.use(errorHandler);
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

export default app;
