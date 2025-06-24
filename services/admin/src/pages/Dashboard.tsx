import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  BarChart3, 
  Search, 
  Download, 
  Activity,
  TrendingUp,
  AlertTriangle,
  CheckCircle,
  Clock
} from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts'
import { healthService } from '../services/healthService'
import { searchTermsService } from '../services/searchTermsService'
import { collectionsService } from '../services/collectionsService'

const Dashboard: React.FC = () => {
  const { data: healthStatus } = useQuery({
    queryKey: ['health'],
    queryFn: healthService.getHealth,
    refetchInterval: 30000,
  })

  const { data: metrics } = useQuery({
    queryKey: ['metrics'],
    queryFn: healthService.getMetrics,
    refetchInterval: 60000,
  })

  const { data: termsStats } = useQuery({
    queryKey: ['search-terms-stats'],
    queryFn: searchTermsService.getTermsStatistics,
  })

  const { data: recentCollections } = useQuery({
    queryKey: ['recent-collections'],
    queryFn: () => collectionsService.getCollections({ limit: 10, sort_by: 'started_at', sort_order: 'desc' }),
  })

  // Mock data for charts
  const collectionsData = [
    { date: '2024-06-20', collections: 12, documents: 450 },
    { date: '2024-06-21', collections: 15, documents: 520 },
    { date: '2024-06-22', collections: 18, documents: 680 },
    { date: '2024-06-23', collections: 14, documents: 490 },
    { date: '2024-06-24', collections: 16, documents: 590 },
  ]

  const sourcesData = [
    { source: 'LexML', documents: 1250 },
    { source: 'Câmara', documents: 890 },
    { source: 'Senado', documents: 670 },
    { source: 'ANTT', documents: 420 },
    { source: 'ANAC', documents: 310 },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600">Visão geral do sistema de coleta legislativa</p>
      </div>

      {/* Key metrics */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <BarChart3 className="h-6 w-6 text-primary-600" />
              </div>
              <div className="ml-3 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Total de Documentos</dt>
                  <dd className="text-lg font-semibold text-gray-900">
                    {metrics?.total_documents?.toLocaleString('pt-BR') || '—'}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Search className="h-6 w-6 text-success-600" />
              </div>
              <div className="ml-3 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Termos Ativos</dt>
                  <dd className="text-lg font-semibold text-gray-900">
                    {termsStats?.active_terms || '—'}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <Download className="h-6 w-6 text-warning-600" />
              </div>
              <div className="ml-3 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Coletas Hoje</dt>
                  <dd className="text-lg font-semibold text-gray-900">
                    {metrics?.collections_today || '—'}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-content">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <TrendingUp className="h-6 w-6 text-error-600" />
              </div>
              <div className="ml-3 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Taxa de Sucesso</dt>
                  <dd className="text-lg font-semibold text-gray-900">
                    {healthStatus?.metrics?.success_rate ? 
                      `${healthStatus.metrics.success_rate.toFixed(1)}%` : '—'}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Collections over time */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Coletas por Dia</h3>
            <p className="card-description">Evolução das coletas nos últimos 5 dias</p>
          </div>
          <div className="card-content">
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={collectionsData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis 
                  dataKey="date" 
                  stroke="#666"
                  fontSize={12}
                  tickFormatter={(value) => new Date(value).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' })}
                />
                <YAxis stroke="#666" fontSize={12} />
                <Tooltip 
                  labelFormatter={(value) => new Date(value).toLocaleDateString('pt-BR')}
                  formatter={(value, name) => [value, name === 'collections' ? 'Coletas' : 'Documentos']}
                />
                <Line type="monotone" dataKey="collections" stroke="#3b82f6" strokeWidth={2} dot={{ fill: '#3b82f6' }} />
                <Line type="monotone" dataKey="documents" stroke="#10b981" strokeWidth={2} dot={{ fill: '#10b981' }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Documents by source */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Documentos por Fonte</h3>
            <p className="card-description">Distribuição dos documentos coletados</p>
          </div>
          <div className="card-content">
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={sourcesData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="source" stroke="#666" fontSize={12} />
                <YAxis stroke="#666" fontSize={12} />
                <Tooltip formatter={(value) => [value, 'Documentos']} />
                <Bar dataKey="documents" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent activity and system status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent collections */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Coletas Recentes</h3>
            <p className="card-description">Últimas execuções do sistema</p>
          </div>
          <div className="card-content">
            <div className="space-y-3">
              {recentCollections?.data?.map((collection: any) => (
                <div key={collection.id} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                  <div className="flex-shrink-0">
                    {collection.status === 'completed' ? (
                      <CheckCircle className="h-5 w-5 text-success-600" />
                    ) : collection.status === 'failed' ? (
                      <AlertTriangle className="h-5 w-5 text-error-600" />
                    ) : (
                      <Clock className="h-5 w-5 text-warning-600" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {collection.search_term}
                    </p>
                    <p className="text-xs text-gray-500">
                      {collection.records_collected} documentos • {new Date(collection.started_at).toLocaleString('pt-BR')}
                    </p>
                  </div>
                  <div className="flex-shrink-0">
                    <span className={`badge ${
                      collection.status === 'completed' ? 'badge-success' :
                      collection.status === 'failed' ? 'badge-error' : 'badge-warning'
                    }`}>
                      {collection.status === 'completed' ? 'Concluído' :
                       collection.status === 'failed' ? 'Falhou' : 'Em andamento'}
                    </span>
                  </div>
                </div>
              )) || (
                <div className="text-center py-6 text-gray-500">
                  <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
                  <p>Nenhuma coleta recente</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* System alerts */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Alertas do Sistema</h3>
            <p className="card-description">Notificações e problemas recentes</p>
          </div>
          <div className="card-content">
            <div className="space-y-3">
              {healthStatus?.overall_status === 'healthy' ? (
                <div className="flex items-center space-x-3 p-3 bg-success-50 rounded-lg">
                  <CheckCircle className="h-5 w-5 text-success-600" />
                  <div>
                    <p className="text-sm font-medium text-success-900">Sistema Operacional</p>
                    <p className="text-xs text-success-700">Todos os componentes funcionando normalmente</p>
                  </div>
                </div>
              ) : (
                <div className="flex items-center space-x-3 p-3 bg-warning-50 rounded-lg">
                  <AlertTriangle className="h-5 w-5 text-warning-600" />
                  <div>
                    <p className="text-sm font-medium text-warning-900">Sistema Degradado</p>
                    <p className="text-xs text-warning-700">Alguns componentes com problemas</p>
                  </div>
                </div>
              )}
              
              <div className="flex items-center space-x-3 p-3 bg-blue-50 rounded-lg">
                <Activity className="h-5 w-5 text-blue-600" />
                <div>
                  <p className="text-sm font-medium text-blue-900">Coleta Automática Ativa</p>
                  <p className="text-xs text-blue-700">Próxima execução: {new Date(Date.now() + 24 * 60 * 60 * 1000).toLocaleDateString('pt-BR')}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard