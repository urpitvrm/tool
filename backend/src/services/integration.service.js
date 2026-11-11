
import { Client } from '@opensearch-project/opensearch';
import axios from 'axios';
import https from 'node:https';
import fs from 'node:fs';
import { config } from '../config/index.js';
import { pool } from '../config/db.js';

// ==================================================
// TLS CONFIGURATION
// ==================================================

const wazuhVerifyTls = config.wazuhVerifyTls !== false;

const wazuhHttpsAgent = new https.Agent({
  rejectUnauthorized: wazuhVerifyTls,
  ...(wazuhVerifyTls && config.wazuhCaFile
    ? { ca: fs.readFileSync(config.wazuhCaFile) }
    : {}),
  keepAlive: true,
});

// ==================================================
// OPENSEARCH
// ==================================================

let searchClient;

export function opensearch() {
  if (!config.searchNodes?.length) {
    throw Object.assign(
      new Error('OpenSearch is not configured'),
      { status: 503 }
    );
  }

  if (!searchClient) {
    const hasSearchUsername = Boolean(config.searchUsername);
    const hasSearchPassword = Boolean(config.searchPassword);

    if (hasSearchUsername !== hasSearchPassword) {
      throw Object.assign(
        new Error(
          'Set both OPENSEARCH_USERNAME and OPENSEARCH_PASSWORD, or leave both empty for an anonymous cluster.'
        ),
        { status: 503 }
      );
    }

    console.log('Initializing OpenSearch client with nodes:');

    searchClient = new Client({
      nodes: config.searchNodes,

      auth: hasSearchUsername
        ? {
            username: config.searchUsername,
            password: config.searchPassword,
          }
        : undefined,

      ssl: {
        rejectUnauthorized: config.verifyTls,
      },

      requestTimeout: config.opensearchRequestTimeoutMs,
      maxRetries: 0,
    });
  }

  return searchClient;
}

// Named export for SIEM services.
// This is a function, so call openSearchClient() to get the client.
export const openSearchClient = opensearch;

// ==================================================
// WAZUH CONFIGURATION
// ==================================================

let managerToken = null;
let tokenUntil = 0;
let authenticationPromise = null;

const TOKEN_REFRESH_MS = 14 * 60 * 1000;

function managerConfigured() {
  return Boolean(
    config.manager &&
    config.managerUser &&
    config.managerPassword
  );
}

function managerUrl(path) {
  return `${config.manager.replace(/\/+$/, '')}/${String(path).replace(/^\/+/, '')}`;
}

// ==================================================
// WAZUH AUTHENTICATION
// ==================================================

async function authenticateWazuh(force = false) {
  if (!managerConfigured()) {
    throw Object.assign(
      new Error('Wazuh Manager is not configured'),
      { status: 503 }
    );
  }

  if (!force && managerToken && Date.now() < tokenUntil) {
    return managerToken;
  }

  if (authenticationPromise) {
    return authenticationPromise;
  }

  authenticationPromise = (async () => {
    try {
      const response = await axios.post(
        managerUrl('/security/user/authenticate'),
        null,
        {
          auth: {
            username: config.managerUser,
            password: config.managerPassword,
          },
          timeout: config.wazuhRequestTimeoutMs,
          httpsAgent: wazuhHttpsAgent,
        }
      );

      const token =
        response.data?.data?.token ||
        response.data?.token;

      if (!token) {
        throw new Error(
          'Wazuh Manager did not return an authentication token'
        );
      }

      managerToken = token;
      tokenUntil = Date.now() + TOKEN_REFRESH_MS;

      return token;
    } catch (error) {
      managerToken = null;
      tokenUntil = 0;
      throw error;
    } finally {
      authenticationPromise = null;
    }
  })();

  return authenticationPromise;
}

// ==================================================
// WAZUH API REQUEST
// ==================================================

export async function wazuh(path, options = {}) {
  if (!managerConfigured()) {
    throw Object.assign(
      new Error('Wazuh Manager is not configured'),
      { status: 503 }
    );
  }

  const {
    method = 'GET',
    headers = {},
    ...requestOptions
  } = options;

  let token = await authenticateWazuh();

  const makeRequest = async (accessToken) => {
    const response = await axios({
      url: managerUrl(path),
      method,
      ...requestOptions,
      timeout: config.wazuhRequestTimeoutMs,
      httpsAgent: wazuhHttpsAgent,
      headers: {
        ...headers,
        Authorization: `Bearer ${accessToken}`,
      },
    });

    console.log(
      `Wazuh response: ${response.status} ${response.statusText}`
    );

    return response;
  };

  try {
    return await makeRequest(token);
  } catch (error) {
    console.log(`Wazuh request error: ${error.message}`);

    if (error.response?.status !== 401) {
      throw error;
    }

    managerToken = null;
    tokenUntil = 0;

    token = await authenticateWazuh(true);

    return makeRequest(token);
  }
}

// ==================================================
// SAFE ERROR HANDLING
// ==================================================

function safeMessage(error) {
  const message = String(
    error?.response?.data?.message ||
    error?.response?.data?.error ||
    error?.message ||
    'Connection failed'
  );

  if (/\b(EAI_AGAIN|ENOTFOUND)\b/i.test(message)) {
    return config.usingSupabase
      ? 'DNS lookup failed for the Supabase database host. Verify the hostname or use the Supabase Session Pooler.'
      : 'DNS lookup failed for the configured integration host.';
  }

  if (/ECONNREFUSED/i.test(message)) {
    return 'Connection refused by the configured integration service.';
  }

  if (/ETIMEDOUT|ECONNABORTED/i.test(message)) {
    return 'Connection timed out while contacting the integration service.';
  }

  if (/self.signed certificate|certificate/i.test(message)) {
    return 'TLS certificate verification failed. Verify the configured CA certificate or TLS settings.';
  }

  if (/401|unauthorized/i.test(message)) {
    return 'Authentication failed. Verify integration credentials.';
  }

  if (/403|forbidden/i.test(message)) {
    return 'Access denied by the integration service.';
  }

  return message
    .replace(
      /postgres(?:ql)?:\/\/[^\s@]+@[^\s/]+/ig,
      'postgresql://[redacted]'
    )
    .replace(
      /[a-z0-9-]+\.supabase\.co/ig,
      '[supabase-host]'
    )
    .replace(
      /(password|token|authorization|secret|api[_-]?key)=?[^\s&]+/ig,
      '$1=[redacted]'
    )
    .slice(0, 180);
}

// ==================================================
// INTEGRATION HEALTH CHECKS
// ==================================================

export async function integrationHealth() {
  const state = {
    postgresql: {
      status: 'unavailable',
    },

    opensearch: {
      status: config.searchNodes?.length
        ? 'unavailable'
        : 'unconfigured',
    },

    wazuh: {
      status: managerConfigured()
        ? 'unavailable'
        : 'unconfigured',
    },
  };

  const checks = [
    // PostgreSQL
    (async () => {
      try {
        await pool.query('SELECT 1');

        state.postgresql = {
          status: 'connected',
        };
      } catch (error) {
        state.postgresql = {
          status: 'unavailable',
          message: safeMessage(error),
        };
      }
    })(),

    // OpenSearch
    (async () => {
      if (!config.searchNodes?.length) return;

      try {
        const response = await openSearchClient().cluster.health();

        const health = response.body;

        state.opensearch = {
          status: 'connected',
          cluster: health.cluster_name,
          health: health.status,
        };
      } catch (error) {
        state.opensearch = {
          status: 'unavailable',
          message: safeMessage(error),
        };
      }
    })(),

    // Wazuh
    (async () => {
      if (!managerConfigured()) return;

      try {
        const response = await wazuh('/');

        state.wazuh = {
          status: 'connected',
          api:
            response.data?.data?.api_version ||
            'available',
        };
      } catch (error) {
        state.wazuh = {
          status: 'unavailable',
          message: safeMessage(error),
        };
      }
    })(),
  ];

  await Promise.all(checks);

  return state;
}

// ==================================================
// CLEANUP
// ==================================================

export async function closeIntegrations() {
  managerToken = null;
  tokenUntil = 0;

  if (searchClient) {
    await searchClient.close();
    searchClient = null;
  }

  wazuhHttpsAgent.destroy();
}
