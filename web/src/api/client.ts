/**
 * API Client for Monitor Legislativo
 *
 * Handles all HTTP requests to the R Plumber API with:
 * - Error handling
 * - Type safety
 * - Base URL configuration
 */

export interface ApiError {
  error: string;
  message: string;
  request_id?: string;
  status?: number;
}

/**
 * Base API client with error handling
 *
 * @param path - API endpoint path (e.g., '/api/v1/search')
 * @param init - Fetch RequestInit options
 * @returns Parsed JSON response
 * @throws ApiError on HTTP errors
 */
export const api = async <T = any>(
  path: string,
  init?: RequestInit
): Promise<T> => {
  const baseUrl = import.meta.env.VITE_API_BASE || '';
  const url = `${baseUrl}${path}`;

  try {
    const response = await fetch(url, {
      headers: {
        'Content-Type': 'application/json',
        ...init?.headers,
      },
      ...init,
    });

    // Handle non-OK responses
    if (!response.ok) {
      const error = await response.json().catch(() => ({
        error: 'http_error',
        message: `HTTP ${response.status}: ${response.statusText}`,
        status: response.status,
      }));

      throw error;
    }

    return response.json();
  } catch (error) {
    // Re-throw API errors as-is
    if (typeof error === 'object' && error !== null && 'error' in error) {
      throw error as ApiError;
    }

    // Network errors or other exceptions
    throw {
      error: 'network_error',
      message: error instanceof Error ? error.message : 'Network request failed',
    } as ApiError;
  }
};

/**
 * Build query string from object
 *
 * @param params - Query parameters object
 * @returns URL-encoded query string
 */
export const buildQueryString = (
  params: Record<string, string | number | boolean | undefined>
): string => {
  const filtered = Object.entries(params)
    .filter(([_, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join('&');

  return filtered ? `?${filtered}` : '';
};

/**
 * API client with query string builder
 *
 * @param path - API endpoint path
 * @param params - Query parameters
 * @param init - Fetch RequestInit options
 * @returns Parsed JSON response
 */
export const apiWithParams = <T = any>(
  path: string,
  params: Record<string, string | number | boolean | undefined>,
  init?: RequestInit
): Promise<T> => {
  const queryString = buildQueryString(params);
  return api<T>(`${path}${queryString}`, init);
};
