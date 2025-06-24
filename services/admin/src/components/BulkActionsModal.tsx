import React, { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { X, Zap, Play, Pause, Trash2 } from 'lucide-react'
import { searchTermsService } from '../services/searchTermsService'

interface BulkActionsModalProps {
  selectedIds: number[]
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

const BulkActionsModal: React.FC<BulkActionsModalProps> = ({
  selectedIds,
  isOpen,
  onClose,
  onSuccess
}) => {
  const [selectedAction, setSelectedAction] = useState<string>('')
  const [updateData, setUpdateData] = useState<any>({})

  const bulkUpdateMutation = useMutation({
    mutationFn: (data: any) => searchTermsService.bulkUpdate(selectedIds, data),
    onSuccess: () => {
      onSuccess()
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!selectedAction) return

    let data: any = {}

    switch (selectedAction) {
      case 'activate':
        data = { active: true }
        break
      case 'deactivate':
        data = { active: false }
        break
      case 'change_frequency':
        data = { collection_frequency: updateData.frequency }
        break
      case 'change_category':
        data = { category: updateData.category }
        break
      case 'change_priority':
        data = { priority: parseInt(updateData.priority) }
        break
    }

    bulkUpdateMutation.mutate(data)
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="fixed inset-0 bg-black bg-opacity-25" onClick={onClose} />
        
        <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Ações em Lote</h2>
              <p className="text-sm text-gray-600">
                {selectedIds.length} termo(s) selecionado(s)
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-md text-gray-400 hover:text-gray-600 hover:bg-gray-100"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Content */}
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            <div>
              <label className="form-label">Ação</label>
              <select
                value={selectedAction}
                onChange={(e) => setSelectedAction(e.target.value)}
                className="form-select"
                required
              >
                <option value="">Selecione uma ação</option>
                <option value="activate">Ativar termos</option>
                <option value="deactivate">Desativar termos</option>
                <option value="change_frequency">Alterar frequência</option>
                <option value="change_category">Alterar categoria</option>
                <option value="change_priority">Alterar prioridade</option>
              </select>
            </div>

            {/* Conditional fields based on selected action */}
            {selectedAction === 'change_frequency' && (
              <div>
                <label className="form-label">Nova Frequência</label>
                <select
                  value={updateData.frequency || ''}
                  onChange={(e) => setUpdateData({ ...updateData, frequency: e.target.value })}
                  className="form-select"
                  required
                >
                  <option value="">Selecione</option>
                  <option value="daily">Diário</option>
                  <option value="weekly">Semanal</option>
                  <option value="monthly">Mensal</option>
                  <option value="custom">Personalizado</option>
                </select>
              </div>
            )}

            {selectedAction === 'change_category' && (
              <div>
                <label className="form-label">Nova Categoria</label>
                <input
                  type="text"
                  value={updateData.category || ''}
                  onChange={(e) => setUpdateData({ ...updateData, category: e.target.value })}
                  className="form-input"
                  placeholder="Ex: transporte"
                  required
                />
              </div>
            )}

            {selectedAction === 'change_priority' && (
              <div>
                <label className="form-label">Nova Prioridade</label>
                <select
                  value={updateData.priority || ''}
                  onChange={(e) => setUpdateData({ ...updateData, priority: e.target.value })}
                  className="form-select"
                  required
                >
                  <option value="">Selecione</option>
                  <option value="1">1 - Muito Alta</option>
                  <option value="2">2 - Alta</option>
                  <option value="3">3 - Média-Alta</option>
                  <option value="4">4 - Média</option>
                  <option value="5">5 - Normal</option>
                  <option value="6">6 - Baixa</option>
                  <option value="7">7 - Muito Baixa</option>
                </select>
              </div>
            )}

            <div className="flex items-center justify-end space-x-3 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="btn btn-outline"
              >
                Cancelar
              </button>
              <button
                type="submit"
                disabled={bulkUpdateMutation.isPending || !selectedAction}
                className="btn btn-primary"
              >
                {bulkUpdateMutation.isPending ? (
                  'Aplicando...'
                ) : (
                  <>
                    <Zap className="h-4 w-4 mr-1" />
                    Aplicar Ação
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

export default BulkActionsModal