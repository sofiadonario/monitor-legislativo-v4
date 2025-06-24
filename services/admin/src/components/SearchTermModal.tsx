import React, { useState, useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { useForm } from 'react-hook-form'
import { X, Save, Eye, TestTube, AlertCircle } from 'lucide-react'
import { searchTermsService, SearchTerm, CreateSearchTermRequest } from '../services/searchTermsService'
import { cn } from '../utils/cn'
import CQLQueryBuilder from './CQLQueryBuilder'

interface SearchTermModalProps {
  term?: SearchTerm | null
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

interface FormData extends CreateSearchTermRequest {
  preview_limit?: number
}

const SearchTermModal: React.FC<SearchTermModalProps> = ({ 
  term, 
  isOpen, 
  onClose, 
  onSuccess 
}) => {
  const [showCQLBuilder, setShowCQLBuilder] = useState(false)
  const [isValidCQL, setIsValidCQL] = useState(true)
  const [cqlError, setCQLError] = useState<string>()
  const [previewData, setPreviewData] = useState<any>(null)
  
  const isEditing = !!term

  const { register, handleSubmit, formState: { errors }, setValue, watch, reset } = useForm<FormData>({
    defaultValues: {
      term: '',
      category: 'transporte',
      cql_query: '',
      collection_frequency: 'weekly',
      priority: 5,
      active: true,
      preview_limit: 10
    }
  })

  const watchedCQLQuery = watch('cql_query')
  const watchedTerm = watch('term')

  // Get categories for dropdown
  const { data: categories } = useQuery({
    queryKey: ['search-terms-categories'],
    queryFn: searchTermsService.getCategories,
  })

  // Load term data when editing
  useEffect(() => {
    if (term) {
      reset({
        term: term.term,
        category: term.category,
        cql_query: term.cql_query || '',
        collection_frequency: term.collection_frequency,
        priority: term.priority,
        active: term.active,
        preview_limit: 10
      })
    } else {
      reset({
        term: '',
        category: 'transporte',
        cql_query: '',
        collection_frequency: 'weekly',
        priority: 5,
        active: true,
        preview_limit: 10
      })
    }
  }, [term, reset])

  // Create/Update mutation
  const saveMutation = useMutation({
    mutationFn: (data: CreateSearchTermRequest) => {
      if (isEditing) {
        return searchTermsService.updateSearchTerm({ ...data, id: term!.id })
      } else {
        return searchTermsService.createSearchTerm(data)
      }
    },
    onSuccess: () => {
      onSuccess()
    },
  })

  // Preview mutation
  const previewMutation = useMutation({
    mutationFn: ({ termId, limit }: { termId: number; limit: number }) => 
      searchTermsService.previewSearchResults(termId, limit),
    onSuccess: (data) => {
      setPreviewData(data)
    },
  })

  const onSubmit = (data: FormData) => {
    // Remove preview_limit from submission data
    const { preview_limit, ...submitData } = data
    
    if (!isValidCQL && submitData.cql_query) {
      return // Don't submit if CQL is invalid
    }

    saveMutation.mutate(submitData)
  }

  const handleCQLChange = (query: string) => {
    setValue('cql_query', query)
  }

  const handleCQLValidation = (valid: boolean, error?: string) => {
    setIsValidCQL(valid)
    setCQLError(error)
  }

  const handlePreview = () => {
    if (isEditing) {
      const limit = watch('preview_limit') || 10
      previewMutation.mutate({ termId: term!.id, limit })
    }
  }

  const generateCQLFromTerm = () => {
    const termValue = watchedTerm?.trim()
    if (termValue) {
      const generatedCQL = `dc.title any "${termValue}" OR dc.description any "${termValue}" OR dc.subject any "${termValue}"`
      setValue('cql_query', generatedCQL)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-screen items-center justify-center p-4">
        <div className="fixed inset-0 bg-black bg-opacity-25" onClick={onClose} />
        
        <div className="relative bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-gray-200">
            <div>
              <h2 className="text-lg font-semibold text-gray-900">
                {isEditing ? 'Editar Termo de Busca' : 'Novo Termo de Busca'}
              </h2>
              <p className="text-sm text-gray-600">
                {isEditing ? 'Modifique as configurações do termo' : 'Configure um novo termo para coleta automática'}
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
          <div className="overflow-y-auto max-h-[calc(90vh-140px)]">
            <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-6">
              {/* Basic Information */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="form-label">
                    Termo de Busca <span className="text-error-500">*</span>
                  </label>
                  <input
                    type="text"
                    {...register('term', { required: 'Termo é obrigatório' })}
                    className={cn('form-input', errors.term && 'border-error-500')}
                    placeholder="Ex: transporte público"
                  />
                  {errors.term && (
                    <p className="text-sm text-error-600 mt-1">{errors.term.message}</p>
                  )}
                </div>

                <div>
                  <label className="form-label">Categoria</label>
                  <select {...register('category')} className="form-select">
                    {categories?.map(category => (
                      <option key={category} value={category}>{category}</option>
                    ))}
                    <option value="outros">Outros</option>
                  </select>
                </div>

                <div>
                  <label className="form-label">Frequência de Coleta</label>
                  <select {...register('collection_frequency')} className="form-select">
                    <option value="daily">Diário</option>
                    <option value="weekly">Semanal</option>
                    <option value="monthly">Mensal</option>
                    <option value="custom">Personalizado</option>
                  </select>
                </div>

                <div>
                  <label className="form-label">Prioridade</label>
                  <select {...register('priority', { valueAsNumber: true })} className="form-select">
                    <option value={1}>1 - Muito Alta</option>
                    <option value={2}>2 - Alta</option>
                    <option value={3}>3 - Média-Alta</option>
                    <option value={4}>4 - Média</option>
                    <option value={5}>5 - Normal</option>
                    <option value={6}>6 - Baixa</option>
                    <option value={7}>7 - Muito Baixa</option>
                  </select>
                </div>
              </div>

              {/* Status */}
              <div className="flex items-center space-x-3">
                <input
                  type="checkbox"
                  id="active"
                  {...register('active')}
                  className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                />
                <label htmlFor="active" className="text-sm font-medium text-gray-700">
                  Termo ativo (será incluído nas coletas automáticas)
                </label>
              </div>

              {/* CQL Query Section */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <label className="form-label">Consulta CQL (Opcional)</label>
                    <p className="text-xs text-gray-600">
                      Defina uma consulta avançada para busca mais específica
                    </p>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      type="button"
                      onClick={generateCQLFromTerm}
                      className="btn btn-outline btn-sm"
                      disabled={!watchedTerm?.trim()}
                    >
                      <TestTube className="h-4 w-4 mr-1" />
                      Gerar CQL
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowCQLBuilder(!showCQLBuilder)}
                      className={cn(
                        "btn btn-sm",
                        showCQLBuilder ? "btn-primary" : "btn-outline"
                      )}
                    >
                      Construtor
                    </button>
                  </div>
                </div>

                {showCQLBuilder ? (
                  <CQLQueryBuilder
                    initialQuery={watchedCQLQuery}
                    onChange={handleCQLChange}
                    onValidationChange={handleCQLValidation}
                  />
                ) : (
                  <div>
                    <textarea
                      {...register('cql_query')}
                      className={cn(
                        'form-textarea h-24 font-mono text-sm',
                        !isValidCQL && 'border-error-500'
                      )}
                      placeholder="dc.title any &quot;termo&quot; OR dc.description any &quot;termo&quot;"
                    />
                    {!isValidCQL && cqlError && (
                      <div className="flex items-start space-x-2 mt-2 p-2 bg-error-50 rounded border border-error-200">
                        <AlertCircle className="h-4 w-4 text-error-600 mt-0.5 flex-shrink-0" />
                        <div>
                          <p className="text-sm text-error-800 font-medium">Consulta CQL inválida</p>
                          <p className="text-sm text-error-700">{cqlError}</p>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Preview Section (only for editing) */}
              {isEditing && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-medium text-gray-900">Prévia dos Resultados</h3>
                      <p className="text-xs text-gray-600">
                        Teste como o termo funcionará na coleta
                      </p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <input
                        type="number"
                        {...register('preview_limit', { min: 1, max: 50 })}
                        className="form-input w-20 text-sm"
                        min="1"
                        max="50"
                      />
                      <button
                        type="button"
                        onClick={handlePreview}
                        disabled={previewMutation.isPending}
                        className="btn btn-outline btn-sm"
                      >
                        {previewMutation.isPending ? (
                          <>Carregando...</>
                        ) : (
                          <>
                            <Eye className="h-4 w-4 mr-1" />
                            Prévia
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  {previewData && (
                    <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
                      <div className="text-sm text-gray-600 mb-3">
                        Encontrados {previewData.total_results} documentos. Mostrando os primeiros {previewData.documents?.length || 0}:
                      </div>
                      <div className="space-y-2 max-h-40 overflow-y-auto custom-scrollbar">
                        {previewData.documents?.map((doc: any, index: number) => (
                          <div key={index} className="bg-white p-3 rounded border border-gray-100">
                            <div className="font-medium text-sm text-gray-900 truncate">
                              {doc.title}
                            </div>
                            <div className="text-xs text-gray-500 mt-1">
                              {doc.document_type} • {doc.source_api} • {doc.document_date}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </form>
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
              onClick={handleSubmit(onSubmit)}
              disabled={saveMutation.isPending || (!isValidCQL && !!watchedCQLQuery)}
              className="btn btn-primary"
            >
              {saveMutation.isPending ? (
                'Salvando...'
              ) : (
                <>
                  <Save className="h-4 w-4 mr-1" />
                  {isEditing ? 'Atualizar' : 'Criar'} Termo
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default SearchTermModal