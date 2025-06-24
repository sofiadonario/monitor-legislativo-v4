import React, { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { X, Play, CheckSquare, Square } from 'lucide-react'
import { collectionsService } from '../services/collectionsService'
import { searchTermsService } from '../services/searchTermsService'

interface ManualCollectionModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

const SOURCES = [
  { id: 'lexml', name: 'LexML Brasil', description: 'Base legal brasileira' },
  { id: 'camara', name: 'Câmara dos Deputados', description: 'Proposições da Câmara' },
  { id: 'senado', name: 'Senado Federal', description: 'Matérias do Senado' },
  { id: 'antt', name: 'ANTT', description: 'Transporte terrestre' },
  { id: 'anac', name: 'ANAC', description: 'Aviação civil' },
  { id: 'aneel', name: 'ANEEL', description: 'Energia elétrica' },
  { id: 'anatel', name: 'ANATEL', description: 'Telecomunicações' },
  { id: 'anvisa', name: 'ANVISA', description: 'Vigilância sanitária' },
  { id: 'ans', name: 'ANS', description: 'Saúde suplementar' },
  { id: 'ana', name: 'ANA', description: 'Águas' },
  { id: 'ancine', name: 'ANCINE', description: 'Cinema' },
  { id: 'anm', name: 'ANM', description: 'Mineração' },
  { id: 'anp', name: 'ANP', description: 'Petróleo' },
  { id: 'antaq', name: 'ANTAQ', description: 'Transporte aquaviário' },
  { id: 'cade', name: 'CADE', description: 'Defesa econômica' },
]

const ManualCollectionModal: React.FC<ManualCollectionModalProps> = ({
  isOpen,
  onClose,
  onSuccess
}) => {
  const [selectedTerms, setSelectedTerms] = useState<number[]>([])
  const [selectedSources, setSelectedSources] = useState<string[]>(['lexml'])
  const [maxRecords, setMaxRecords] = useState(100)

  const { data: searchTerms } = useQuery({
    queryKey: ['search-terms-active'],
    queryFn: () => searchTermsService.getSearchTerms({ 
      active: true, 
      per_page: 100,
      sort_by: 'term',
      sort_order: 'asc'
    }),
    enabled: isOpen,
  })

  const startCollectionMutation = useMutation({
    mutationFn: collectionsService.startManualCollection,
    onSuccess: () => {
      onSuccess()
    },
  })

  const handleTermToggle = (termId: number) => {
    setSelectedTerms(prev => 
      prev.includes(termId)
        ? prev.filter(id => id !== termId)
        : [...prev, termId]
    )
  }

  const handleSourceToggle = (sourceId: string) => {
    setSelectedSources(prev => 
      prev.includes(sourceId)
        ? prev.filter(id => id !== sourceId)
        : [...prev, sourceId]
    )
  }

  const handleSelectAllTerms = () => {
    if (selectedTerms.length === searchTerms?.data.length) {
      setSelectedTerms([])
    } else {
      setSelectedTerms(searchTerms?.data.map(term => term.id) || [])
    }
  }

  const handleSelectAllSources = () => {
    if (selectedSources.length === SOURCES.length) {
      setSelectedSources([])
    } else {
      setSelectedSources(SOURCES.map(source => source.id))
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (selectedTerms.length === 0 || selectedSources.length === 0) {
      alert('Selecione pelo menos um termo e uma fonte')
      return
    }

    startCollectionMutation.mutate({
      search_term_ids: selectedTerms,
      sources: selectedSources,
      max_records: maxRecords
    })
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="fixed inset-0 bg-black bg-opacity-25" onClick={onClose} />
        
        <div className="relative bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">Nova Coleta Manual</h2>
              <p className="text-sm text-gray-600">
                Execute uma coleta customizada para termos específicos
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
          <form onSubmit={handleSubmit} className="overflow-y-auto max-h-[calc(90vh-140px)]">
            <div className="p-6 space-y-6">
              {/* Terms selection */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium text-gray-900">
                    Termos de Busca ({selectedTerms.length} selecionados)
                  </h3>
                  <button
                    type="button"
                    onClick={handleSelectAllTerms}
                    className="text-sm text-primary-600 hover:text-primary-800"
                  >
                    {selectedTerms.length === searchTerms?.data.length ? 'Desmarcar todos' : 'Selecionar todos'}
                  </button>
                </div>
                <div className="max-h-40 overflow-y-auto border border-gray-200 rounded-lg">
                  {searchTerms?.data.map(term => (
                    <label
                      key={term.id}
                      className="flex items-center p-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-b-0"
                    >
                      <input
                        type="checkbox"
                        checked={selectedTerms.includes(term.id)}
                        onChange={() => handleTermToggle(term.id)}
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                      <div className="ml-3 flex-1">
                        <div className="text-sm font-medium text-gray-900">{term.term}</div>
                        <div className="text-xs text-gray-500">{term.category}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Sources selection */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-medium text-gray-900">
                    Fontes de Dados ({selectedSources.length} selecionadas)
                  </h3>
                  <button
                    type="button"
                    onClick={handleSelectAllSources}
                    className="text-sm text-primary-600 hover:text-primary-800"
                  >
                    {selectedSources.length === SOURCES.length ? 'Desmarcar todas' : 'Selecionar todas'}
                  </button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {SOURCES.map(source => (
                    <label
                      key={source.id}
                      className="flex items-center p-3 border border-gray-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 cursor-pointer transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={selectedSources.includes(source.id)}
                        onChange={() => handleSourceToggle(source.id)}
                        className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                      />
                      <div className="ml-3">
                        <div className="text-sm font-medium text-gray-900">{source.name}</div>
                        <div className="text-xs text-gray-500">{source.description}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Configuration */}
              <div>
                <h3 className="text-sm font-medium text-gray-900 mb-3">Configurações</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="form-label">Máximo de documentos por fonte</label>
                    <input
                      type="number"
                      value={maxRecords}
                      onChange={(e) => setMaxRecords(parseInt(e.target.value) || 100)}
                      min="1"
                      max="1000"
                      className="form-input"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Limite por fonte. Total pode ser maior.
                    </p>
                  </div>
                </div>
              </div>

              {/* Summary */}
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-900 mb-2">Resumo da Coleta</h3>
                <div className="text-sm text-gray-600 space-y-1">
                  <div>• {selectedTerms.length} termo(s) de busca</div>
                  <div>• {selectedSources.length} fonte(s) de dados</div>
                  <div>• Até {maxRecords * selectedSources.length} documentos no total</div>
                  <div>• Estimativa: {Math.ceil(selectedTerms.length * selectedSources.length / 5)} minutos</div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-200 bg-gray-50">
              <button
                type="button"
                onClick={onClose}
                className="btn btn-outline"
              >
                Cancelar
              </button>
              <button
                type="submit"
                disabled={startCollectionMutation.isPending || selectedTerms.length === 0 || selectedSources.length === 0}
                className="btn btn-primary"
              >
                {startCollectionMutation.isPending ? (
                  'Iniciando...'
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-1" />
                    Iniciar Coleta
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

export default ManualCollectionModal