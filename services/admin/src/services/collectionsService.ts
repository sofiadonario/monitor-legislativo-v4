import api from './api'

export interface Collection {
  id: number
  search_term_id: number
  search_term: string
  collection_type: 'automated' | 'manual'
  status: 'pending' | 'running' | 'completed' | 'failed'
  records_collected: number
  records_new: number
  records_updated: number
  records_skipped: number
  execution_time_ms: number
  error_message?: string
  error_type?: string
  started_at: string
  completed_at?: string
  api_response_time_ms?: number
  sources_used: string[]
}

export interface CollectionsFilters {
  status?: string
  collection_type?: string
  search_term_id?: number
  date_from?: string
  date_to?: string
  page?: number
  limit?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
}

export interface CollectionsResponse {
  data: Collection[]
  total: number
  page: number
  limit: number
  total_pages: number
}

export interface ManualCollectionRequest {
  search_term_ids: number[]
  sources?: string[]
  max_records?: number
}

export const collectionsService = {
  async getCollections(filters: CollectionsFilters = {}): Promise<CollectionsResponse> {
    const response = await api.get('/collections', { params: filters })
    return response.data
  },

  async getCollection(id: number): Promise<Collection> {
    const response = await api.get(`/collections/${id}`)
    return response.data
  },

  async startManualCollection(data: ManualCollectionRequest): Promise<{ flow_run_id: string }> {
    const response = await api.post('/collections/manual', data)
    return response.data
  },

  async getCollectionLogs(id: number): Promise<any> {
    const response = await api.get(`/collections/${id}/logs`)
    return response.data
  },

  async retryCollection(id: number): Promise<{ flow_run_id: string }> {
    const response = await api.post(`/collections/${id}/retry`)
    return response.data
  },

  async cancelCollection(id: number): Promise<void> {
    await api.post(`/collections/${id}/cancel`)
  },

  async getCollectionStats(): Promise<any> {
    const response = await api.get('/collections/statistics')
    return response.data
  },

  async exportCollections(filters: CollectionsFilters = {}, format: 'csv' | 'json' | 'xlsx' = 'csv'): Promise<Blob> {
    const response = await api.get('/collections/export', {
      params: { ...filters, format },
      responseType: 'blob'
    })
    return response.data
  }
}