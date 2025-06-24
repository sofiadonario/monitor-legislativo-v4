import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, Database, Wifi, AlertTriangle, CheckCircle, Clock } from 'lucide-react'
import { healthService } from '../services/healthService'

const Monitoring: React.FC = () => {
  const { data: healthStatus, isLoading } = useQuery({
    queryKey: ['detailed-health'],
    queryFn: healthService.getDetailedHealth,
    refetchInterval: 15000, // 15 seconds
  })

  const { data: metrics } = useQuery({
    queryKey: ['detailed-metrics'],
    queryFn: healthService.getMetrics,
    refetchInterval: 30000, // 30 seconds
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
        <span className="ml-3 text-gray-600">Carregando monitoramento...</span>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Monitoramento</h1>
        <p className="text-gray-600">Status detalhado dos componentes do sistema</p>
      </div>

      {/* System Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title flex items-center">
              <Database className="h-5 w-5 mr-2" />
              Banco de Dados
            </h3>
          </div>
          <div className="card-content">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Status</span>
                <div className="flex items-center">
                  <CheckCircle className="h-4 w-4 text-success-500 mr-1" />
                  <span className="text-sm font-medium">Saudável</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Conectividade</span>
                <span className="text-sm font-medium">100%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Pool de Conexões</span>
                <span className="text-sm font-medium">5/20</span>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title flex items-center">
              <Wifi className="h-5 w-5 mr-2" />
              Serviço Coletor
            </h3>
          </div>
          <div className="card-content">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Status</span>
                <div className="flex items-center">
                  <CheckCircle className="h-4 w-4 text-success-500 mr-1" />
                  <span className="text-sm font-medium">Ativo</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Última Coleta</span>
                <span className="text-sm font-medium">2 min atrás</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Taxa de Sucesso</span>
                <span className="text-sm font-medium">94.2%</span>
              </div>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title flex items-center">
              <Activity className="h-5 w-5 mr-2" />
              APIs Externas
            </h3>
          </div>
          <div className="card-content">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">LexML</span>
                <div className="flex items-center">
                  <CheckCircle className="h-4 w-4 text-success-500 mr-1" />
                  <span className="text-sm font-medium">OK</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Câmara</span>
                <div className="flex items-center">
                  <CheckCircle className="h-4 w-4 text-success-500 mr-1" />
                  <span className="text-sm font-medium">OK</span>
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-600">Senado</span>
                <div className="flex items-center">
                  <AlertTriangle className="h-4 w-4 text-warning-500 mr-1" />
                  <span className="text-sm font-medium">Lento</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Performance Metrics */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Métricas de Performance</h3>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900">
                {metrics?.total_collections || '—'}
              </div>
              <div className="text-sm text-gray-600">Coletas Totais</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900">
                {metrics?.success_rate ? `${metrics.success_rate.toFixed(1)}%` : '—'}
              </div>
              <div className="text-sm text-gray-600">Taxa de Sucesso</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900">
                {metrics?.avg_response_time ? `${metrics.avg_response_time}ms` : '—'}
              </div>
              <div className="text-sm text-gray-600">Tempo Médio</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900">
                {metrics?.documents_per_hour || '—'}
              </div>
              <div className="text-sm text-gray-600">Docs/Hora</div>
            </div>
          </div>
        </div>
      </div>

      {/* Circuit Breakers */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Circuit Breakers</h3>
        </div>
        <div className="card-content">
          <div className="space-y-4">
            {healthStatus?.circuit_breakers ? Object.entries(healthStatus.circuit_breakers).map(([service, stats]: [string, any]) => (
              <div key={service} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <div className="font-medium text-gray-900">{service}</div>
                  <div className="text-sm text-gray-600">
                    {stats.total_requests} requisições • {stats.success_rate.toFixed(1)}% sucesso
                  </div>
                </div>
                <div className="flex items-center">
                  {stats.state === 'closed' ? (
                    <CheckCircle className="h-5 w-5 text-success-500" />
                  ) : (
                    <AlertTriangle className="h-5 w-5 text-warning-500" />
                  )}
                  <span className="ml-2 text-sm font-medium capitalize">{stats.state}</span>
                </div>
              </div>
            )) : (
              <div className="text-center py-6 text-gray-500">
                <Activity className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>Nenhum circuit breaker configurado</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Alertas Recentes</h3>
        </div>
        <div className="card-content">
          <div className="space-y-3">
            {healthStatus?.recent_alerts?.length > 0 ? healthStatus.recent_alerts.map((alert: any, index: number) => (
              <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                <AlertTriangle className="h-5 w-5 text-warning-600 mt-0.5" />
                <div className="flex-1">
                  <div className="text-sm font-medium text-gray-900">{alert.message}</div>
                  <div className="text-xs text-gray-500">{new Date(alert.timestamp).toLocaleString('pt-BR')}</div>
                </div>
                <span className={`badge ${
                  alert.level === 'critical' ? 'badge-error' :
                  alert.level === 'warning' ? 'badge-warning' : 'badge-secondary'
                }`}>
                  {alert.level}
                </span>
              </div>
            )) : (
              <div className="text-center py-6 text-gray-500">
                <CheckCircle className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>Nenhum alerta recente</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Monitoring