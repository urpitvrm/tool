import axios from 'axios';
// OpenSearch can take longer than a typical CRUD request to answer event searches.
// Keep the browser waiting long enough for the backend's request timeout/retry to finish.
export const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || '/api/v1', timeout: 30000 });
api.interceptors.request.use((config) => { const token = localStorage.getItem('siem_token'); if (token) config.headers.Authorization = 'Bearer ' + token; return config; });
api.interceptors.response.use((x) => x, (error) => { if (error.response?.status === 401 && !String(error.config?.url).includes('/auth/login')) { localStorage.removeItem('siem_token'); window.dispatchEvent(new Event('siem-logout')); } return Promise.reject(error); });
export const apiError = (error) => error?.response?.data?.detail || error?.response?.data?.error || error.message || 'Request failed';
