const isDevelopment = false;
const isProduction = true;
const API_URLS = {
  // Local development backend
  production: "https://monitor-legislativo-v4-production.up.railway.app"
};
const getApiBaseUrl = () => {
  return API_URLS.production;
};
const buildApiUrl = (endpoint, params) => {
  const baseUrl = getApiBaseUrl();
  let url = `${baseUrl}${endpoint}`;
  return url;
};
const API_CONFIG = {
  timeout: 3e4,
  headers: {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Client": "monitor-legislativo-frontend",
    "X-Version": "4.0.0"
  }
};
const CORS_CONFIG = {
  credentials: "same-origin",
  mode: "cors"
};
console.log(`API Configuration initialized:`, {
  mode: "production",
  baseUrl: getApiBaseUrl(),
  isDevelopment,
  isProduction
});
export {
  API_CONFIG as A,
  CORS_CONFIG as C,
  buildApiUrl as b,
  getApiBaseUrl as g
};
