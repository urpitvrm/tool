import { Router } from 'express';
import { documentedApiPaths } from '../constants/api-paths.js';
import { integrationHealth } from '../services/integration.service.js';
import { asyncHandler } from '../utils/helpers.js';

const router = Router();
router.get('/health', asyncHandler(async (_req, res) => {
  res.json({ api: 'ok', integrations: await integrationHealth() });
}));

router.get('/openapi.json', (_req, res) => res.json({
  openapi: '3.0.3',
  info: { title: 'Sentinel SOC API', version: '1.0.0' },
  servers: [{ url: '/api/v1' }],
  paths: Object.fromEntries(documentedApiPaths.map((path) => [`/${path}`, {
    get: {
      summary: `Sentinel SOC ${path.replaceAll('/', ' ')}`,
      responses: {
        200: { description: 'Successful response' },
        401: { description: 'Authentication required' },
        503: { description: 'Integration unavailable' },
      },
    },
  }])),
}));

export default router;
