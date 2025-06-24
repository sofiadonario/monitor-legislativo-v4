import api from './api'

export interface HealthStatus {
  overall_status: 'healthy' | 'degraded' | 'unhealthy'
  timestamp: string
  components: {
    database?: {
      status: string
      connectivity: boolean
      pool_stats?: any
    }
    collector?: {
      status: string
      last_collection?: string
      success_rate?: number
    }
    lexml_api?: {
      status: string
      response_time?: number
    }
    circuit_breakers?: Record<string, any>
  }
  metrics?: {
    success_rate: number
    total_collections: number
    documents_collected: number
    average_time_ms: number
  }
}

export const healthService = {
  async getHealth(): Promise<HealthStatus> {
    const response = await api.get('/health')
    return response.data
  },

  async getDetailedHealth(): Promise<any> {
    const response = await api.get('/health/detailed')
    return response.data
  },

  async getMetrics(): Promise<any> {
    const response = await api.get('/metrics')
    return response.data
  }
}