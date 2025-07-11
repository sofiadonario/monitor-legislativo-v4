/**
 * API Client Service for Monitor Legislativo
 * Handles all HTTP requests to the backend API
 */

import { API_CONFIG, getApiBaseUrl, buildApiUrl, CORS_CONFIG } from '../config/api';

export interface ApiResponse<T = any> {
  data?: T;
  error?: string;
  status: number;
  success: boolean;
}

export class ApiClient {
  private baseUrl: string;
  private defaultHeaders: Record<string, string>;

  constructor() {
    this.baseUrl = getApiBaseUrl();
    this.defaultHeaders = {
      ...API_CONFIG.headers,
    };
  }

  private async makeRequest<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = buildApiUrl(endpoint);
    
    try {
      const response = await fetch(url, {
        ...options,
        ...CORS_CONFIG,
        headers: {
          ...this.defaultHeaders,
          ...options.headers,
        },
        signal: AbortSignal.timeout(API_CONFIG.timeout),
      });

      const data = await response.json().catch(() => null);

      return {
        data,
        status: response.status,
        success: response.ok,
        error: !response.ok ? `HTTP ${response.status}: ${response.statusText}` : undefined,
      };
    } catch (error) {
      console.error('API Request failed:', error);
      return {
        status: 0,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  async get<T>(endpoint: string, params?: Record<string, string>): Promise<ApiResponse<T>> {
    const url = params ? buildApiUrl(endpoint, params) : endpoint;
    return this.makeRequest<T>(url, { method: 'GET' });
  }

  async post<T>(endpoint: string, data?: any): Promise<ApiResponse<T>> {
    return this.makeRequest<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put<T>(endpoint: string, data?: any): Promise<ApiResponse<T>> {
    return this.makeRequest<T>(endpoint, {
      method: 'PUT',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete<T>(endpoint: string): Promise<ApiResponse<T>> {
    return this.makeRequest<T>(endpoint, { method: 'DELETE' });
  }

  // Health check
  async healthCheck(): Promise<ApiResponse<{ status: string; service: string; timestamp: string }>> {
    return this.get('/health');
  }

  // Search functionality
  async search(query: string, limit: number = 10): Promise<ApiResponse<any[]>> {
    return this.get('/lexml/search', { query, limit: limit.toString() });
  }
}

// Export singleton instance
export const apiClient = new ApiClient();
export default apiClient;