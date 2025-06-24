import React, { useState } from 'react'
import { Save, RefreshCw, AlertTriangle, CheckCircle } from 'lucide-react'

const Settings: React.FC = () => {
  const [settings, setSettings] = useState({
    collection: {
      default_frequency: 'weekly',
      max_records_per_collection: 1000,
      concurrent_collections: 5,
      retry_attempts: 3,
      timeout_seconds: 60
    },
    notifications: {
      email_enabled: false,
      email_address: '',
      webhook_url: '',
      alert_threshold: 80
    },
    system: {
      auto_cleanup_days: 90,
      log_level: 'info',
      enable_metrics: true,
      cache_duration_minutes: 60
    }
  })

  const [isSaving, setIsSaving] = useState(false)
  const [lastSaved, setLastSaved] = useState<Date | null>(null)

  const handleSettingChange = (section: string, key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [section]: {
        ...prev[section as keyof typeof prev],
        [key]: value
      }
    }))
  }

  const handleSave = async () => {
    setIsSaving(true)
    try {
      // TODO: Implement API call to save settings
      await new Promise(resolve => setTimeout(resolve, 1000))
      setLastSaved(new Date())
    } catch (error) {
      console.error('Failed to save settings:', error)
    } finally {
      setIsSaving(false)
    }
  }

  const handleReset = () => {
    if (confirm('Tem certeza que deseja restaurar as configurações padrão?')) {
      // TODO: Reset to default settings
      setLastSaved(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Configurações</h1>
          <p className="text-gray-600">Gerencie as configurações do sistema de coleta</p>
        </div>
        <div className="flex space-x-3">
          <button 
            onClick={handleReset}
            className="btn btn-outline btn-sm"
          >
            <RefreshCw className="h-4 w-4 mr-1" />
            Restaurar Padrão
          </button>
          <button 
            onClick={handleSave}
            disabled={isSaving}
            className="btn btn-primary btn-sm"
          >
            {isSaving ? (
              <>Salvando...</>
            ) : (
              <>
                <Save className="h-4 w-4 mr-1" />
                Salvar Alterações
              </>
            )}
          </button>
        </div>
      </div>

      {lastSaved && (
        <div className="card border-success-200 bg-success-50">
          <div className="card-content">
            <div className="flex items-center">
              <CheckCircle className="h-5 w-5 text-success-600 mr-2" />
              <span className="text-sm text-success-800">
                Configurações salvas com sucesso em {lastSaved.toLocaleString('pt-BR')}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Collection Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Configurações de Coleta</h3>
          <p className="card-description">
            Configure os parâmetros padrão para as coletas automáticas
          </p>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="form-label">Frequência Padrão</label>
              <select
                value={settings.collection.default_frequency}
                onChange={(e) => handleSettingChange('collection', 'default_frequency', e.target.value)}
                className="form-select"
              >
                <option value="daily">Diário</option>
                <option value="weekly">Semanal</option>
                <option value="monthly">Mensal</option>
              </select>
            </div>

            <div>
              <label className="form-label">Máximo de Documentos por Coleta</label>
              <input
                type="number"
                value={settings.collection.max_records_per_collection}
                onChange={(e) => handleSettingChange('collection', 'max_records_per_collection', parseInt(e.target.value))}
                min="100"
                max="10000"
                className="form-input"
              />
            </div>

            <div>
              <label className="form-label">Coletas Simultâneas</label>
              <input
                type="number"
                value={settings.collection.concurrent_collections}
                onChange={(e) => handleSettingChange('collection', 'concurrent_collections', parseInt(e.target.value))}
                min="1"
                max="20"
                className="form-input"
              />
              <p className="text-xs text-gray-500 mt-1">
                Número máximo de coletas executadas simultaneamente
              </p>
            </div>

            <div>
              <label className="form-label">Tentativas de Retry</label>
              <input
                type="number"
                value={settings.collection.retry_attempts}
                onChange={(e) => handleSettingChange('collection', 'retry_attempts', parseInt(e.target.value))}
                min="1"
                max="10"
                className="form-input"
              />
            </div>

            <div>
              <label className="form-label">Timeout (segundos)</label>
              <input
                type="number"
                value={settings.collection.timeout_seconds}
                onChange={(e) => handleSettingChange('collection', 'timeout_seconds', parseInt(e.target.value))}
                min="30"
                max="300"
                className="form-input"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Notification Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Notificações e Alertas</h3>
          <p className="card-description">
            Configure como e quando receber notificações do sistema
          </p>
        </div>
        <div className="card-content">
          <div className="space-y-6">
            <div className="flex items-center space-x-3">
              <input
                type="checkbox"
                id="email_enabled"
                checked={settings.notifications.email_enabled}
                onChange={(e) => handleSettingChange('notifications', 'email_enabled', e.target.checked)}
                className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
              />
              <label htmlFor="email_enabled" className="text-sm font-medium text-gray-700">
                Habilitar notificações por email
              </label>
            </div>

            {settings.notifications.email_enabled && (
              <div>
                <label className="form-label">Endereço de Email</label>
                <input
                  type="email"
                  value={settings.notifications.email_address}
                  onChange={(e) => handleSettingChange('notifications', 'email_address', e.target.value)}
                  className="form-input"
                  placeholder="admin@exemplo.com"
                />
              </div>
            )}

            <div>
              <label className="form-label">Webhook URL (Opcional)</label>
              <input
                type="url"
                value={settings.notifications.webhook_url}
                onChange={(e) => handleSettingChange('notifications', 'webhook_url', e.target.value)}
                className="form-input"
                placeholder="https://hooks.slack.com/services/..."
              />
              <p className="text-xs text-gray-500 mt-1">
                URL para receber notificações via webhook (ex: Slack, Discord)
              </p>
            </div>

            <div>
              <label className="form-label">Limite para Alertas de Taxa de Sucesso (%)</label>
              <input
                type="number"
                value={settings.notifications.alert_threshold}
                onChange={(e) => handleSettingChange('notifications', 'alert_threshold', parseInt(e.target.value))}
                min="50"
                max="99"
                className="form-input"
              />
              <p className="text-xs text-gray-500 mt-1">
                Receber alerta quando a taxa de sucesso ficar abaixo deste valor
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* System Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Configurações do Sistema</h3>
          <p className="card-description">
            Configurações gerais de funcionamento do sistema
          </p>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="form-label">Limpeza Automática (dias)</label>
              <input
                type="number"
                value={settings.system.auto_cleanup_days}
                onChange={(e) => handleSettingChange('system', 'auto_cleanup_days', parseInt(e.target.value))}
                min="30"
                max="365"
                className="form-input"
              />
              <p className="text-xs text-gray-500 mt-1">
                Remover logs e dados antigos após este período
              </p>
            </div>

            <div>
              <label className="form-label">Nível de Log</label>
              <select
                value={settings.system.log_level}
                onChange={(e) => handleSettingChange('system', 'log_level', e.target.value)}
                className="form-select"
              >
                <option value="debug">Debug</option>
                <option value="info">Info</option>
                <option value="warning">Warning</option>
                <option value="error">Error</option>
              </select>
            </div>

            <div>
              <label className="form-label">Duração do Cache (minutos)</label>
              <input
                type="number"
                value={settings.system.cache_duration_minutes}
                onChange={(e) => handleSettingChange('system', 'cache_duration_minutes', parseInt(e.target.value))}
                min="5"
                max="1440"
                className="form-input"
              />
            </div>

            <div className="flex items-center space-x-3">
              <input
                type="checkbox"
                id="enable_metrics"
                checked={settings.system.enable_metrics}
                onChange={(e) => handleSettingChange('system', 'enable_metrics', e.target.checked)}
                className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
              />
              <label htmlFor="enable_metrics" className="text-sm font-medium text-gray-700">
                Habilitar coleta de métricas
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* Warning */}
      <div className="card border-warning-200 bg-warning-50">
        <div className="card-content">
          <div className="flex items-start">
            <AlertTriangle className="h-5 w-5 text-warning-600 mt-0.5 mr-3" />
            <div>
              <h4 className="text-sm font-medium text-warning-900">Atenção</h4>
              <p className="text-sm text-warning-800 mt-1">
                Algumas alterações podem afetar coletas em andamento. 
                É recomendado fazer alterações durante períodos de menor atividade.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Settings