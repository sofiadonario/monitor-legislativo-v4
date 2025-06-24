import React, { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { 
  Plus, 
  X, 
  HelpCircle, 
  CheckCircle, 
  AlertTriangle,
  Code,
  Eye,
  RefreshCw
} from 'lucide-react'
import { searchTermsService } from '../services/searchTermsService'
import { cn } from '../utils/cn'

interface CQLCondition {
  id: string
  field: string
  operator: string
  value: string
  connector?: 'AND' | 'OR'
}

interface CQLQueryBuilderProps {
  initialQuery?: string
  onChange: (query: string) => void
  onValidationChange?: (isValid: boolean, error?: string) => void
}

const CQL_FIELDS = [
  { value: 'dc.title', label: 'Título', description: 'Título do documento' },
  { value: 'dc.description', label: 'Descrição', description: 'Descrição/ementa do documento' },
  { value: 'dc.subject', label: 'Assunto', description: 'Palavras-chave e assuntos' },
  { value: 'dc.creator', label: 'Autor', description: 'Autor ou órgão responsável' },
  { value: 'dc.date', label: 'Data', description: 'Data de publicação' },
  { value: 'dc.type', label: 'Tipo', description: 'Tipo de documento (lei, decreto, etc.)' },
  { value: 'dc.identifier', label: 'Identificador', description: 'URN ou identificador único' },
  { value: 'dc.publisher', label: 'Publicador', description: 'Órgão publicador' },
  { value: 'text', label: 'Texto Completo', description: 'Busca em todo o texto' }
]

const CQL_OPERATORS = [
  { value: '=', label: 'igual a', description: 'Correspondência exata' },
  { value: 'exact', label: 'exatamente', description: 'Correspondência exata de frase' },
  { value: 'any', label: 'contém qualquer', description: 'Contém qualquer uma das palavras' },
  { value: 'all', label: 'contém todas', description: 'Contém todas as palavras' },
  { value: '>', label: 'maior que', description: 'Para datas e números' },
  { value: '<', label: 'menor que', description: 'Para datas e números' },
  { value: '>=', label: 'maior ou igual', description: 'Para datas e números' },
  { value: '<=', label: 'menor ou igual', description: 'Para datas e números' }
]

const PREDEFINED_QUERIES = [
  {
    name: 'Legislação de Transporte',
    query: 'dc.subject any "transporte mobilidade trânsito" OR dc.title any "transporte mobilidade trânsito"'
  },
  {
    name: 'Decretos Recentes',
    query: 'dc.type = "decreto" AND dc.date >= "2024-01-01"'
  },
  {
    name: 'Leis Federais',
    query: 'dc.type = "lei" AND dc.publisher = "federal"'
  },
  {
    name: 'Regulamentação Ambiental',
    query: 'dc.subject any "meio ambiente sustentabilidade" OR dc.title any "ambiental"'
  }
]

const CQLQueryBuilder: React.FC<CQLQueryBuilderProps> = ({ 
  initialQuery = '', 
  onChange, 
  onValidationChange 
}) => {
  const [conditions, setConditions] = useState<CQLCondition[]>([])
  const [rawQuery, setRawQuery] = useState(initialQuery)
  const [showRawEditor, setShowRawEditor] = useState(false)
  const [validationResult, setValidationResult] = useState<{
    valid: boolean
    error?: string
    suggestions?: string[]
  } | null>(null)

  // Initialize conditions from initial query
  useEffect(() => {
    if (initialQuery && conditions.length === 0) {
      setRawQuery(initialQuery)
      // For now, start with empty conditions if there's an initial query
      // TODO: Parse existing CQL into conditions
    }
  }, [initialQuery])

  // Validate query
  const { refetch: validateQuery, isFetching: isValidating } = useQuery({
    queryKey: ['validate-cql', rawQuery],
    queryFn: () => searchTermsService.validateCQLQuery(rawQuery),
    enabled: false,
    onSuccess: (result) => {
      setValidationResult(result)
      onValidationChange?.(result.valid, result.error)
    },
    onError: () => {
      setValidationResult({ valid: false, error: 'Erro ao validar consulta' })
      onValidationChange?.(false, 'Erro ao validar consulta')
    }
  })

  const addCondition = () => {
    const newCondition: CQLCondition = {
      id: Math.random().toString(36).substr(2, 9),
      field: 'dc.title',
      operator: 'any',
      value: '',
      connector: conditions.length > 0 ? 'AND' : undefined
    }
    setConditions([...conditions, newCondition])
  }

  const removeCondition = (id: string) => {
    const newConditions = conditions.filter(c => c.id !== id)
    // Remove connector from first condition if it exists
    if (newConditions.length > 0 && newConditions[0].connector) {
      newConditions[0].connector = undefined
    }
    setConditions(newConditions)
    updateQuery(newConditions)
  }

  const updateCondition = (id: string, updates: Partial<CQLCondition>) => {
    const newConditions = conditions.map(c => 
      c.id === id ? { ...c, ...updates } : c
    )
    setConditions(newConditions)
    updateQuery(newConditions)
  }

  const updateQuery = (newConditions: CQLCondition[] = conditions) => {
    const query = buildCQLQuery(newConditions)
    setRawQuery(query)
    onChange(query)
  }

  const buildCQLQuery = (conditions: CQLCondition[]): string => {
    return conditions
      .filter(c => c.field && c.operator && c.value.trim())
      .map((condition, index) => {
        let part = ''
        
        if (index > 0 && condition.connector) {
          part += ` ${condition.connector} `
        }
        
        // Handle different operators
        let value = condition.value.trim()
        if (condition.operator === 'exact') {
          value = `"${value}"`
        } else if (condition.operator === 'any' || condition.operator === 'all') {
          // For 'any' and 'all', wrap multiple words in quotes
          value = `"${value}"`
        }
        
        part += `${condition.field} ${condition.operator} ${value}`
        
        return part
      })
      .join('')
  }

  const handleRawQueryChange = (query: string) => {
    setRawQuery(query)
    onChange(query)
  }

  const loadPredefinedQuery = (query: string) => {
    setRawQuery(query)
    onChange(query)
    // TODO: Parse query into conditions
  }

  const handleValidate = () => {
    if (rawQuery.trim()) {
      validateQuery()
    }
  }

  return (
    <div className="space-y-4">
      {/* Header with mode toggle */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium text-gray-900">Construtor de Consulta CQL</h3>
          <p className="text-sm text-gray-600">
            Construa consultas avançadas para busca no LexML
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setShowRawEditor(!showRawEditor)}
            className={cn(
              "btn btn-sm",
              showRawEditor ? "btn-primary" : "btn-outline"
            )}
          >
            <Code className="h-4 w-4 mr-1" />
            {showRawEditor ? 'Visual' : 'Código'}
          </button>
          <button
            onClick={handleValidate}
            disabled={isValidating || !rawQuery.trim()}
            className="btn btn-outline btn-sm"
          >
            {isValidating ? (
              <RefreshCw className="h-4 w-4 mr-1 animate-spin" />
            ) : (
              <CheckCircle className="h-4 w-4 mr-1" />
            )}
            Validar
          </button>
        </div>
      </div>

      {/* Predefined queries */}
      <div className="card">
        <div className="card-header">
          <h4 className="text-sm font-medium text-gray-900">Consultas Predefinidas</h4>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {PREDEFINED_QUERIES.map((preset) => (
              <button
                key={preset.name}
                onClick={() => loadPredefinedQuery(preset.query)}
                className="text-left p-3 border border-gray-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors"
              >
                <div className="font-medium text-sm text-gray-900">{preset.name}</div>
                <div className="text-xs text-gray-500 mt-1 truncate">{preset.query}</div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {showRawEditor ? (
        /* Raw CQL Editor */
        <div className="card">
          <div className="card-header">
            <h4 className="text-sm font-medium text-gray-900">Editor de Consulta CQL</h4>
          </div>
          <div className="card-content">
            <textarea
              value={rawQuery}
              onChange={(e) => handleRawQueryChange(e.target.value)}
              placeholder="Digite sua consulta CQL aqui..."
              className="form-textarea h-32 font-mono text-sm"
              rows={6}
            />
          </div>
        </div>
      ) : (
        /* Visual Query Builder */
        <div className="card">
          <div className="card-header">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium text-gray-900">Condições da Consulta</h4>
              <button
                onClick={addCondition}
                className="btn btn-primary btn-sm"
              >
                <Plus className="h-4 w-4 mr-1" />
                Adicionar Condição
              </button>
            </div>
          </div>
          <div className="card-content">
            {conditions.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <HelpCircle className="h-8 w-8 mx-auto mb-2 opacity-50" />
                <p>Adicione condições para construir sua consulta</p>
              </div>
            ) : (
              <div className="space-y-3">
                {conditions.map((condition, index) => (
                  <div key={condition.id} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                    {/* Connector */}
                    {index > 0 && (
                      <select
                        value={condition.connector || 'AND'}
                        onChange={(e) => updateCondition(condition.id, { 
                          connector: e.target.value as 'AND' | 'OR' 
                        })}
                        className="form-select w-20 text-sm"
                      >
                        <option value="AND">E</option>
                        <option value="OR">OU</option>
                      </select>
                    )}

                    {/* Field */}
                    <select
                      value={condition.field}
                      onChange={(e) => updateCondition(condition.id, { field: e.target.value })}
                      className="form-select flex-1"
                    >
                      {CQL_FIELDS.map(field => (
                        <option key={field.value} value={field.value}>
                          {field.label}
                        </option>
                      ))}
                    </select>

                    {/* Operator */}
                    <select
                      value={condition.operator}
                      onChange={(e) => updateCondition(condition.id, { operator: e.target.value })}
                      className="form-select flex-1"
                    >
                      {CQL_OPERATORS.map(op => (
                        <option key={op.value} value={op.value}>
                          {op.label}
                        </option>
                      ))}
                    </select>

                    {/* Value */}
                    <input
                      type="text"
                      value={condition.value}
                      onChange={(e) => updateCondition(condition.id, { value: e.target.value })}
                      placeholder="Valor..."
                      className="form-input flex-1"
                      onBlur={() => updateQuery()}
                    />

                    {/* Remove button */}
                    <button
                      onClick={() => removeCondition(condition.id)}
                      className="p-2 text-gray-400 hover:text-error-600 rounded"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Generated query preview */}
      <div className="card">
        <div className="card-header">
          <h4 className="text-sm font-medium text-gray-900">Consulta Gerada</h4>
        </div>
        <div className="card-content">
          <div className="bg-gray-50 p-3 rounded-lg">
            <code className="text-sm text-gray-800 break-all">
              {rawQuery || 'Nenhuma consulta definida'}
            </code>
          </div>
        </div>
      </div>

      {/* Validation result */}
      {validationResult && (
        <div className={cn(
          "card border-2",
          validationResult.valid ? "border-success-200 bg-success-50" : "border-error-200 bg-error-50"
        )}>
          <div className="card-content">
            <div className="flex items-start space-x-3">
              {validationResult.valid ? (
                <CheckCircle className="h-5 w-5 text-success-600 mt-0.5" />
              ) : (
                <AlertTriangle className="h-5 w-5 text-error-600 mt-0.5" />
              )}
              <div className="flex-1">
                <p className={cn(
                  "text-sm font-medium",
                  validationResult.valid ? "text-success-900" : "text-error-900"
                )}>
                  {validationResult.valid ? 'Consulta válida' : 'Consulta inválida'}
                </p>
                {validationResult.error && (
                  <p className="text-sm text-error-700 mt-1">{validationResult.error}</p>
                )}
                {validationResult.suggestions && validationResult.suggestions.length > 0 && (
                  <div className="mt-2">
                    <p className="text-sm text-error-700 font-medium">Sugestões:</p>
                    <ul className="list-disc list-inside text-sm text-error-600 mt-1">
                      {validationResult.suggestions.map((suggestion, index) => (
                        <li key={index}>{suggestion}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Help section */}
      <div className="card">
        <div className="card-header">
          <h4 className="text-sm font-medium text-gray-900">Ajuda - Sintaxe CQL</h4>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <h5 className="font-medium text-gray-900 mb-2">Operadores</h5>
              <ul className="space-y-1 text-gray-600">
                <li><code>any</code> - Contém qualquer palavra</li>
                <li><code>all</code> - Contém todas as palavras</li>
                <li><code>exact</code> - Correspondência exata</li>
                <li><code>=</code> - Igual a</li>
                <li><code>&gt;, &lt;, &gt;=, &lt;=</code> - Comparação numérica/data</li>
              </ul>
            </div>
            <div>
              <h5 className="font-medium text-gray-900 mb-2">Conectores</h5>
              <ul className="space-y-1 text-gray-600">
                <li><code>AND</code> - E lógico</li>
                <li><code>OR</code> - OU lógico</li>
                <li><code>NOT</code> - Negação</li>
                <li><code>()</code> - Agrupamento</li>
              </ul>
            </div>
          </div>
          <div className="mt-4 p-3 bg-blue-50 rounded-lg">
            <p className="text-sm text-blue-800">
              <strong>Exemplo:</strong> <code>dc.title any "transporte" AND dc.date &gt;= "2024-01-01"</code>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CQLQueryBuilder