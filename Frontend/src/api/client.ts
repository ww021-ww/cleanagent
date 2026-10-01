import axios from 'axios';

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.trim() || 'http://127.0.0.1:8001';

const client = axios.create({
  baseURL: apiBaseUrl,
  timeout: 15000,
});

export default client;
