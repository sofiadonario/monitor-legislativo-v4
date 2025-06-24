import api from './api'

export interface SearchTerm {
  id: number
  term: string
  category: string
  cql_query?: string
  collection_frequency: 'daily' | 'weekly' | 'monthly' | 'custom'
  priority: number
  active: boolean
  created_at: string
  updated_at: string
  next_collection?: string
  last_collection?: string
  total_documents?: number
  success_rate?: number
}

export interface CreateSearchTermRequest {
  term: string
  category: string
  cql_query?: string
  collection_frequency: 'daily' | 'weekly' | 'monthly' | 'custom'
  priority?: number
  active?: boolean
}

export interface UpdateSearchTermRequest extends Partial<CreateSearchTermRequest> {
  id: number
}

export interface SearchTermsFilters {
  category?: string
  active?: boolean
  collection_frequency?: string
  search?: string
  page?: number
  per_page?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
}

export interface SearchTermsResponse {
  data: SearchTerm[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

export const searchTermsService = {
  async getSearchTerms(filters: SearchTermsFilters = {}): Promise<SearchTermsResponse> {
    const response = await api.get('/search-terms', { params: filters })
    return response.data
  },

  async getSearchTerm(id: number): Promise<SearchTerm> {
    const response = await api.get(`/search-terms/${id}`)
    return response.data
  },

  async createSearchTerm(data: CreateSearchTermRequest): Promise<SearchTerm> {
    const response = await api.post('/search-terms', data)
    return response.data
  },

  async updateSearchTerm(data: UpdateSearchTermRequest): Promise<SearchTerm> {
    const { id, ...updateData } = data
    const response = await api.put(`/search-terms/${id}`, updateData)
    return response.data
  },

  async deleteSearchTerm(id: number): Promise<void> {
    await api.delete(`/search-terms/${id}`)
  },

  async duplicateSearchTerm(id: number, newTerm: string): Promise<SearchTerm> {
    const response = await api.post(`/search-terms/${id}/duplicate`, { term: newTerm })
    return response.data
  },

  async toggleActive(id: number, active: boolean): Promise<SearchTerm> {
    const response = await api.patch(`/search-terms/${id}/toggle`, { active })
    return response.data
  },

  async bulkUpdate(ids: number[], data: Partial<CreateSearchTermRequest>): Promise<SearchTerm[]> {
    const response = await api.patch('/search-terms/bulk', { ids, data })
    return response.data
  },

  async getCategories(): Promise<string[]> {
    const response = await api.get('/search-terms/categories')
    return response.data
  },

  async getTermsStatistics(): Promise<any> {
    const response = await api.get('/search-terms/statistics')
    return response.data
  },

  async validateCQLQuery(query: string): Promise<{ valid: boolean; error?: string; suggestions?: string[] }> {
    const response = await api.post('/search-terms/validate-cql', { query })
    return response.data
  },

  async previewSearchResults(termId: number, limit?: number): Promise<any> {
    const response = await api.get(`/search-terms/${termId}/preview`, { 
      params: { limit: limit || 10 } 
    })
    return response.data
  },

  async exportSearchTerms(format: 'csv' | 'json' | 'xlsx' = 'csv'): Promise<Blob> {
    const response = await api.get('/search-terms/export', {
      params: { format },
      responseType: 'blob'
    })
    return response.data
  },

  async importSearchTerms(file: File): Promise<{ imported: number; errors: any[] }> {
    const formData = new FormData()
    formData.append('file', file)
    
    const response = await api.post('/search-terms/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    })
    return response.data
  }
}