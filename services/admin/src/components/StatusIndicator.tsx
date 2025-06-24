import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Database, Wifi, AlertTriangle, CheckCircle } from 'lucide-react'
import { cn } from '../utils/cn'
import { healthService } from '../services/healthService'

const StatusIndicator: React.FC = () => {
  const { data: healthStatus, isLoading } = useQuery({
    queryKey: ['health'],
    queryFn: healthService.getHealth,
    refetchInterval: 30000, // 30 seconds
  })

  if (isLoading) {
    return (
      <div className="space-y-2">
        <div className="flex items-center space-x-2">
          <div className="h-2 w-2 bg-gray-300 rounded-full animate-pulse"></div>
          <span className="text-xs text-gray-500">Verificando...</span>
        </div>
      </div>
    )
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return 'text-success-600 bg-success-50'
      case 'degraded': return 'text-warning-600 bg-warning-50'
      case 'unhealthy': return 'text-error-600 bg-error-50'
      default: return 'text-gray-600 bg-gray-50'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="h-3 w-3" />
      case 'degraded': return <AlertTriangle className="h-3 w-3" />
      case 'unhealthy': return <AlertTriangle className="h-3 w-3" />
      default: return <Database className="h-3 w-3" />
    }
  }

  const overall = healthStatus?.overall_status || 'unknown'
  const database = healthStatus?.components?.database?.status || 'unknown'
  const collector = healthStatus?.components?.collector?.status || 'unknown'

  return (
    <div className="space-y-2">
      <h3 className="text-xs font-medium text-gray-900 uppercase tracking-wide">Status do Sistema</h3>
      
      <div className="space-y-1.5">
        {/* Overall status */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className={cn(
              "flex items-center justify-center h-4 w-4 rounded-full",
              getStatusColor(overall)
            )}>
              {getStatusIcon(overall)}
            </div>
            <span className="text-xs text-gray-700">Geral</span>
          </div>
          <span className={cn(
            "text-xs px-1.5 py-0.5 rounded-full font-medium",
            getStatusColor(overall)
          )}>
            {overall === 'healthy' ? 'Saudável' : 
             overall === 'degraded' ? 'Degradado' : 
             overall === 'unhealthy' ? 'Instável' : 'Desconhecido'}
          </span>
        </div>

        {/* Database status */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Database className="h-3 w-3 text-gray-400" />
            <span className="text-xs text-gray-700">Banco</span>
          </div>
          <div className={cn(
            "h-2 w-2 rounded-full",
            database === 'healthy' ? 'bg-success-500' :
            database === 'degraded' ? 'bg-warning-500' :
            database === 'unhealthy' ? 'bg-error-500' : 'bg-gray-400'
          )}></div>
        </div>

        {/* Collector status */}
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Wifi className="h-3 w-3 text-gray-400" />
            <span className="text-xs text-gray-700">Coletor</span>
          </div>
          <div className={cn(
            "h-2 w-2 rounded-full",
            collector === 'healthy' ? 'bg-success-500' :
            collector === 'degraded' ? 'bg-warning-500' :
            collector === 'unhealthy' ? 'bg-error-500' : 'bg-gray-400'
          )}></div>
        </div>
      </div>

      {/* Last update */}
      <div className="pt-1 border-t border-gray-100">
        <p className="text-xs text-gray-500">
          Última verificação: {new Date().toLocaleTimeString('pt-BR', { 
            hour: '2-digit', 
            minute: '2-digit' 
          })}
        </p>
      </div>
    </div>
  )
}

export default StatusIndicator