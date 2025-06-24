import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Plus, 
  Search, 
  Filter, 
  MoreHorizontal, 
  Edit2, 
  Trash2, 
  Play, 
  Pause,
  Copy,
  Download,
  Upload,
  Eye,
  CheckCircle,
  XCircle,
  Clock
} from 'lucide-react'
import { searchTermsService, SearchTerm, SearchTermsFilters } from '../services/searchTermsService'
import { cn } from '../utils/cn'
import SearchTermModal from '../components/SearchTermModal'
import CQLQueryBuilder from '../components/CQLQueryBuilder'
import BulkActionsModal from '../components/BulkActionsModal'

const SearchTerms: React.FC = () => {
  const [filters, setFilters] = useState<SearchTermsFilters>({
    page: 1,
    per_page: 20,
    sort_by: 'updated_at',
    sort_order: 'desc'
  })
  
  const [selectedTerms, setSelectedTerms] = useState<number[]>([])
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingTerm, setEditingTerm] = useState<SearchTerm | null>(null)
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')

  const queryClient = useQueryClient()

  const { data: searchTermsData, isLoading } = useQuery({
    queryKey: ['search-terms', filters],
    queryFn: () => searchTermsService.getSearchTerms(filters),
  })

  const { data: categories } = useQuery({
    queryKey: ['search-terms-categories'],
    queryFn: searchTermsService.getCategories,
  })

  const { data: statistics } = useQuery({
    queryKey: ['search-terms-statistics'],
    queryFn: searchTermsService.getTermsStatistics,
  })

  const deleteMutation = useMutation({
    mutationFn: searchTermsService.deleteSearchTerm,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['search-terms'] })
    },
  })

  const toggleActiveMutation = useMutation({
    mutationFn: ({ id, active }: { id: number; active: boolean }) => 
      searchTermsService.toggleActive(id, active),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['search-terms'] })
    },
  })

  const duplicateMutation = useMutation({
    mutationFn: ({ id, newTerm }: { id: number; newTerm: string }) => 
      searchTermsService.duplicateSearchTerm(id, newTerm),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['search-terms'] })
    },
  })

  const handleSearch = (query: string) => {
    setSearchQuery(query)
    setFilters(prev => ({ ...prev, search: query, page: 1 }))
  }

  const handleFilterChange = (key: keyof SearchTermsFilters, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value, page: 1 }))
  }

  const handleSelectAll = () => {
    if (selectedTerms.length === searchTermsData?.data.length) {
      setSelectedTerms([])
    } else {
      setSelectedTerms(searchTermsData?.data.map(term => term.id) || [])
    }
  }

  const handleSelectTerm = (id: number) => {
    setSelectedTerms(prev => 
      prev.includes(id) 
        ? prev.filter(termId => termId !== id)
        : [...prev, id]
    )
  }

  const handleEdit = (term: SearchTerm) => {
    setEditingTerm(term)
    setIsModalOpen(true)
  }

  const handleDuplicate = (term: SearchTerm) => {
    const newTerm = prompt('Digite o novo termo:', `${term.term} (cópia)`)
    if (newTerm && newTerm.trim()) {
      duplicateMutation.mutate({ id: term.id, newTerm: newTerm.trim() })
    }
  }

  const handleDelete = (term: SearchTerm) => {
    if (confirm(`Tem certeza que deseja excluir o termo "${term.term}"?`)) {
      deleteMutation.mutate(term.id)
    }
  }

  const handleToggleActive = (term: SearchTerm) => {
    toggleActiveMutation.mutate({ id: term.id, active: !term.active })
  }

  const getStatusIcon = (term: SearchTerm) => {
    if (!term.active) return <Pause className="h-4 w-4 text-gray-400" />
    if (term.success_rate && term.success_rate > 80) return <CheckCircle className="h-4 w-4 text-success-500" />
    if (term.success_rate && term.success_rate < 50) return <XCircle className="h-4 w-4 text-error-500" />
    return <Clock className="h-4 w-4 text-warning-500" />
  }

  const getFrequencyLabel = (frequency: string) => {
    const labels = {
      daily: 'Diário',
      weekly: 'Semanal', 
      monthly: 'Mensal',
      custom: 'Personalizado'
    }
    return labels[frequency as keyof typeof labels] || frequency
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Termos de Busca</h1>
          <p className="text-gray-600">Gerencie os termos utilizados para coleta automática</p>
        </div>
        <div className="flex space-x-3">
          <button 
            className="btn btn-outline btn-sm"
            onClick={() => {/* TODO: Export */}}
          >
            <Download className="h-4 w-4 mr-1" />
            Exportar
          </button>
          <button 
            className="btn btn-outline btn-sm"
            onClick={() => {/* TODO: Import */}}
          >
            <Upload className="h-4 w-4 mr-1" />
            Importar
          </button>
          <button 
            className="btn btn-primary btn-sm"
            onClick={() => {
              setEditingTerm(null)
              setIsModalOpen(true)
            }}
          >
            <Plus className="h-4 w-4 mr-1" />
            Novo Termo
          </button>
        </div>
      </div>

      {/* Statistics cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Search className="h-6 w-6 text-primary-600" />
              </div>
              <div className="ml-3">
                <div className="text-sm font-medium text-gray-500">Total de Termos</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {statistics?.total_terms || 0}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Play className="h-6 w-6 text-success-600" />
              </div>
              <div className="ml-3">
                <div className="text-sm font-medium text-gray-500">Ativos</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {statistics?.active_terms || 0}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Clock className="h-6 w-6 text-warning-600" />
              </div>
              <div className="ml-3">
                <div className="text-sm font-medium text-gray-500">Próximas Coletas</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {statistics?.pending_collections || 0}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CheckCircle className="h-6 w-6 text-success-600" />
              </div>
              <div className="ml-3">
                <div className="text-sm font-medium text-gray-500">Taxa de Sucesso</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {statistics?.average_success_rate ? `${statistics.average_success_rate.toFixed(1)}%` : '—'}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Filters and search */}
      <div className="card">
        <div className="card-content">
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Search */}
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Buscar termos..."
                  className="form-input pl-10"
                  value={searchQuery}
                  onChange={(e) => handleSearch(e.target.value)}
                />
              </div>
            </div>

            {/* Category filter */}
            <div className="sm:w-48">
              <select
                className="form-select"
                value={filters.category || ''}
                onChange={(e) => handleFilterChange('category', e.target.value || undefined)}
              >
                <option value="">Todas as categorias</option>
                {categories?.map(category => (
                  <option key={category} value={category}>{category}</option>
                ))}
              </select>
            </div>

            {/* Status filter */}
            <div className="sm:w-32">
              <select
                className="form-select"
                value={filters.active?.toString() || ''}
                onChange={(e) => handleFilterChange('active', e.target.value ? e.target.value === 'true' : undefined)}
              >
                <option value="">Todos</option>
                <option value="true">Ativos</option>
                <option value="false">Inativos</option>
              </select>
            </div>

            {/* Frequency filter */}
            <div className="sm:w-40">
              <select
                className="form-select"
                value={filters.collection_frequency || ''}
                onChange={(e) => handleFilterChange('collection_frequency', e.target.value || undefined)}
              >
                <option value="">Todas as frequências</option>
                <option value="daily">Diário</option>
                <option value="weekly">Semanal</option>
                <option value="monthly">Mensal</option>
                <option value="custom">Personalizado</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Bulk actions */}
      {selectedTerms.length > 0 && (
        <div className="card border-primary-200 bg-primary-50">
          <div className="card-content">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <span className="text-sm font-medium text-primary-900">
                  {selectedTerms.length} termo(s) selecionado(s)
                </span>
                <button
                  onClick={() => setSelectedTerms([])}
                  className="text-sm text-primary-600 hover:text-primary-800"
                >
                  Limpar seleção
                </button>
              </div>
              <button
                onClick={() => setIsBulkModalOpen(true)}
                className="btn btn-primary btn-sm"
              >
                Ações em lote
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Search terms table */}
      <div className="card">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="w-4 px-6 py-3">
                  <input
                    type="checkbox"
                    checked={selectedTerms.length === searchTermsData?.data.length && searchTermsData?.data.length > 0}
                    onChange={handleSelectAll}
                    className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  />
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Termo
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Categoria
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Frequência
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Documentos
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Última Coleta
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Ações
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="px-6 py-12 text-center">
                    <div className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-600"></div>
                      <span className="ml-2 text-gray-500">Carregando...</span>
                    </div>
                  </td>
                </tr>
              ) : searchTermsData?.data.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-12 text-center">
                    <Search className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                    <p className="text-gray-500">Nenhum termo encontrado</p>
                  </td>
                </tr>
              ) : (
                searchTermsData?.data.map((term) => (
                  <tr key={term.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <input
                        type="checkbox"
                        checked={selectedTerms.includes(term.id)}
                        onChange={() => handleSelectTerm(term.id)}
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        {getStatusIcon(term)}
                        <span className={cn(
                          "ml-2 inline-flex px-2 py-1 text-xs font-medium rounded-full",
                          term.active ? "bg-success-100 text-success-800" : "bg-gray-100 text-gray-800"
                        )}>
                          {term.active ? 'Ativo' : 'Inativo'}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{term.term}</div>
                        {term.cql_query && (
                          <div className="text-xs text-gray-500 truncate max-w-xs">
                            CQL: {term.cql_query}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      <span className="badge badge-secondary">{term.category}</span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {getFrequencyLabel(term.collection_frequency)}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {term.total_documents?.toLocaleString('pt-BR') || '—'}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {term.last_collection ? new Date(term.last_collection).toLocaleDateString('pt-BR') : '—'}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleToggleActive(term)}
                          className={cn(
                            "p-1 rounded hover:bg-gray-100",
                            term.active ? "text-warning-600" : "text-success-600"
                          )}
                          title={term.active ? "Pausar" : "Ativar"}
                        >
                          {term.active ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                        </button>
                        <button
                          onClick={() => handleEdit(term)}
                          className="p-1 rounded hover:bg-gray-100 text-gray-600"
                          title="Editar"
                        >
                          <Edit2 className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDuplicate(term)}
                          className="p-1 rounded hover:bg-gray-100 text-gray-600"
                          title="Duplicar"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDelete(term)}
                          className="p-1 rounded hover:bg-gray-100 text-error-600"
                          title="Excluir"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {searchTermsData && searchTermsData.total_pages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-700">
                Mostrando {((filters.page! - 1) * filters.per_page!) + 1} a{' '}
                {Math.min(filters.page! * filters.per_page!, searchTermsData.total)} de{' '}
                {searchTermsData.total} resultados
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => setFilters(prev => ({ ...prev, page: prev.page! - 1 }))}
                  disabled={filters.page === 1}
                  className="btn btn-outline btn-sm disabled:opacity-50"
                >
                  Anterior
                </button>
                <button
                  onClick={() => setFilters(prev => ({ ...prev, page: prev.page! + 1 }))}
                  disabled={filters.page === searchTermsData.total_pages}
                  className="btn btn-outline btn-sm disabled:opacity-50"
                >
                  Próximo
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {isModalOpen && (
        <SearchTermModal
          term={editingTerm}
          isOpen={isModalOpen}
          onClose={() => {
            setIsModalOpen(false)
            setEditingTerm(null)
          }}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['search-terms'] })
            setIsModalOpen(false)
            setEditingTerm(null)
          }}
        />
      )}

      {isBulkModalOpen && (
        <BulkActionsModal
          selectedIds={selectedTerms}
          isOpen={isBulkModalOpen}
          onClose={() => setIsBulkModalOpen(false)}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['search-terms'] })
            setIsBulkModalOpen(false)
            setSelectedTerms([])
          }}
        />
      )}
    </div>
  )
}

export default SearchTerms