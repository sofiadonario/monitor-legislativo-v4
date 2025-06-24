import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Play, 
  Pause, 
  RotateCcw, 
  Download, 
  Filter,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle
} from 'lucide-react'
import { collectionsService, Collection, CollectionsFilters } from '../services/collectionsService'
import { searchTermsService } from '../services/searchTermsService'
import { cn } from '../utils/cn'
import ManualCollectionModal from '../components/ManualCollectionModal'

const Collections: React.FC = () => {
  const [filters, setFilters] = useState<CollectionsFilters>({
    page: 1,
    limit: 20,
    sort_by: 'started_at',
    sort_order: 'desc'
  })
  
  const [isManualModalOpen, setIsManualModalOpen] = useState(false)

  const queryClient = useQueryClient()

  const { data: collectionsData, isLoading } = useQuery({
    queryKey: ['collections', filters],
    queryFn: () => collectionsService.getCollections(filters),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const { data: stats } = useQuery({
    queryKey: ['collections-stats'],
    queryFn: collectionsService.getCollectionStats,
  })

  const retryMutation = useMutation({
    mutationFn: collectionsService.retryCollection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['collections'] })
    },
  })

  const cancelMutation = useMutation({
    mutationFn: collectionsService.cancelCollection,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['collections'] })
    },
  })

  const handleFilterChange = (key: keyof CollectionsFilters, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value, page: 1 }))
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-success-500" />
      case 'failed':
        return <XCircle className="h-4 w-4 text-error-500" />
      case 'running':
        return <Clock className="h-4 w-4 text-warning-500 animate-pulse" />
      case 'pending':
        return <Clock className="h-4 w-4 text-gray-400" />
      default:
        return <AlertTriangle className="h-4 w-4 text-gray-400" />
    }
  }

  const getStatusLabel = (status: string) => {
    const labels = {
      pending: 'Pendente',
      running: 'Em execução',
      completed: 'Concluído',
      failed: 'Falhou'
    }
    return labels[status as keyof typeof labels] || status
  }

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'completed':
        return 'badge-success'
      case 'failed':
        return 'badge-error'
      case 'running':
        return 'badge-warning'
      case 'pending':
        return 'badge-secondary'
      default:
        return 'badge-secondary'
    }
  }

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`
    const seconds = Math.floor(ms / 1000)
    if (seconds < 60) return `${seconds}s`
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}m ${remainingSeconds}s`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Coletas</h1>
          <p className="text-gray-600">Histórico e gerenciamento de coletas de documentos</p>
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
            className="btn btn-primary btn-sm"
            onClick={() => setIsManualModalOpen(true)}
          >
            <Play className="h-4 w-4 mr-1" />
            Nova Coleta
          </button>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CheckCircle className="h-6 w-6 text-success-600" />
              </div>
              <div className="ml-3">
                <div className="text-sm font-medium text-gray-500">Concluídas Hoje</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {stats?.completed_today || 0}
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
                <div className="text-sm font-medium text-gray-500">Em Execução</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {stats?.running || 0}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <XCircle className="h-6 w-6 text-error-600" />
              </div>
              <div className="ml-3">
                <div className="text-sm font-medium text-gray-500">Falhas Hoje</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {stats?.failed_today || 0}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Download className="h-6 w-6 text-primary-600" />
              </div>
              <div className="ml-3">
                <div className="text-sm font-medium text-gray-500">Documentos Hoje</div>
                <div className="text-2xl font-semibold text-gray-900">
                  {stats?.documents_today?.toLocaleString('pt-BR') || 0}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="card-content">
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="sm:w-40">
              <select
                value={filters.status || ''}
                onChange={(e) => handleFilterChange('status', e.target.value || undefined)}
                className="form-select"
              >
                <option value="">Todos os status</option>
                <option value="pending">Pendente</option>
                <option value="running">Em execução</option>
                <option value="completed">Concluído</option>
                <option value="failed">Falhou</option>
              </select>
            </div>

            <div className="sm:w-40">
              <select
                value={filters.collection_type || ''}
                onChange={(e) => handleFilterChange('collection_type', e.target.value || undefined)}
                className="form-select"
              >
                <option value="">Todos os tipos</option>
                <option value="automated">Automática</option>
                <option value="manual">Manual</option>
              </select>
            </div>

            <div className="flex-1">
              <input
                type="date"
                value={filters.date_from || ''}
                onChange={(e) => handleFilterChange('date_from', e.target.value || undefined)}
                className="form-input"
                placeholder="Data inicial"
              />
            </div>

            <div className="flex-1">
              <input
                type="date"
                value={filters.date_to || ''}
                onChange={(e) => handleFilterChange('date_to', e.target.value || undefined)}
                className="form-input"
                placeholder="Data final"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Collections table */}
      <div className="card">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Termo
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Tipo
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Documentos
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Duração
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Iniciado
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Ações
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center">
                    <div className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary-600"></div>
                      <span className="ml-2 text-gray-500">Carregando...</span>
                    </div>
                  </td>
                </tr>
              ) : collectionsData?.data.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-6 py-12 text-center">
                    <Clock className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                    <p className="text-gray-500">Nenhuma coleta encontrada</p>
                  </td>
                </tr>
              ) : (
                collectionsData?.data.map((collection) => (
                  <tr key={collection.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4">
                      <div className="flex items-center">
                        {getStatusIcon(collection.status)}
                        <span className={cn("ml-2 badge", getStatusBadgeClass(collection.status))}>
                          {getStatusLabel(collection.status)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm font-medium text-gray-900">
                        {collection.search_term}
                      </div>
                      {collection.sources_used?.length > 0 && (
                        <div className="text-xs text-gray-500">
                          Fontes: {collection.sources_used.join(', ')}
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      <span className="badge badge-secondary">
                        {collection.collection_type === 'automated' ? 'Automática' : 'Manual'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      <div>
                        <div className="font-medium">
                          {collection.records_collected.toLocaleString('pt-BR')} coletados
                        </div>
                        <div className="text-xs text-gray-500">
                          {collection.records_new} novos • {collection.records_updated} atualizados
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      {collection.execution_time_ms ? formatDuration(collection.execution_time_ms) : '—'}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900">
                      <div>
                        <div>{new Date(collection.started_at).toLocaleDateString('pt-BR')}</div>
                        <div className="text-xs text-gray-500">
                          {new Date(collection.started_at).toLocaleTimeString('pt-BR')}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-2">
                        {collection.status === 'failed' && (
                          <button
                            onClick={() => retryMutation.mutate(collection.id)}
                            disabled={retryMutation.isPending}
                            className="p-1 rounded hover:bg-gray-100 text-primary-600"
                            title="Tentar novamente"
                          >
                            <RotateCcw className="h-4 w-4" />
                          </button>
                        )}
                        {collection.status === 'running' && (
                          <button
                            onClick={() => cancelMutation.mutate(collection.id)}
                            disabled={cancelMutation.isPending}
                            className="p-1 rounded hover:bg-gray-100 text-error-600"
                            title="Cancelar"
                          >
                            <Pause className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {collectionsData && collectionsData.total_pages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-700">
                Mostrando {((filters.page! - 1) * filters.limit!) + 1} a{' '}
                {Math.min(filters.page! * filters.limit!, collectionsData.total)} de{' '}
                {collectionsData.total} resultados
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
                  disabled={filters.page === collectionsData.total_pages}
                  className="btn btn-outline btn-sm disabled:opacity-50"
                >
                  Próximo
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Manual Collection Modal */}
      {isManualModalOpen && (
        <ManualCollectionModal
          isOpen={isManualModalOpen}
          onClose={() => setIsManualModalOpen(false)}
          onSuccess={() => {
            queryClient.invalidateQueries({ queryKey: ['collections'] })
            setIsManualModalOpen(false)
          }}
        />
      )}
    </div>
  )
}

export default Collections