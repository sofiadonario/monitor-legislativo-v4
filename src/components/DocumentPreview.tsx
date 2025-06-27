import React, { useState, useEffect } from 'react';
import { pdfGenerationService, DocumentContent, DocumentExportOptions, ExportResult } from '../services/pdfGenerationService';
import GlassCard from './GlassCard';
import '../styles/glassmorphism.css';

interface DocumentPreviewProps {
  document?: DocumentContent;
  onClose?: () => void;
  showExportOptions?: boolean;
  defaultFormat?: 'pdf' | 'html' | 'txt' | 'citation';
}

const DocumentPreview: React.FC<DocumentPreviewProps> = ({
  document,
  onClose,
  showExportOptions = true,
  defaultFormat = 'pdf'
}) => {
  const [exportOptions, setExportOptions] = useState<DocumentExportOptions>(
    pdfGenerationService.getDefaultOptions()
  );
  const [isExporting, setIsExporting] = useState(false);
  const [exportResult, setExportResult] = useState<ExportResult | null>(null);
  const [previewMode, setPreviewMode] = useState<'content' | 'formatted'>('content');
  const [showCitation, setShowCitation] = useState(false);

  useEffect(() => {
    setExportOptions(prev => ({
      ...prev,
      format: defaultFormat
    }));
  }, [defaultFormat]);

  const handleExport = async () => {
    if (!document) return;

    setIsExporting(true);
    setExportResult(null);

    try {
      const result = await pdfGenerationService.exportDocument(document, exportOptions);
      setExportResult(result);

      if (result.success && result.downloadUrl && result.filename) {
        pdfGenerationService.downloadFile(result.downloadUrl, result.filename);
      }
    } catch (error) {
      console.error('Export failed:', error);
      setExportResult({
        success: false,
        error: error instanceof Error ? error.message : 'Export failed',
        exportedAt: new Date(),
        format: exportOptions.format
      });
    } finally {
      setIsExporting(false);
    }
  };

  const updateExportOption = <K extends keyof DocumentExportOptions>(
    key: K,
    value: DocumentExportOptions[K]
  ) => {
    setExportOptions(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const generatePreviewCitation = () => {
    if (!document) return '';
    
    // Simplified citation generation for preview
    const { title, metadata } = document;
    const author = metadata.authors?.join(', ') || 'Autor não identificado';
    const date = metadata.date || new Date().getFullYear().toString();
    const source = metadata.source || 'Fonte não identificada';
    
    switch (exportOptions.citationStyle) {
      case 'apa':
        return `${author} (${date}). ${title}. ${source}.`;
      case 'chicago':
        return `${author}. "${title}." ${source}, ${date}.`;
      case 'vancouver':
        return `${author}. ${title}. ${source}; ${date}.`;
      default: // ABNT
        return `${author.toUpperCase()}. ${title}. ${source}, ${date}.`;
    }
  };

  const formatContent = (content: string): string => {
    return content
      .split('\n\n')
      .map(paragraph => paragraph.trim())
      .filter(paragraph => paragraph.length > 0)
      .join('\n\n');
  };

  if (!document) {
    return (
      <GlassCard variant="light" className="text-center p-8">
        <div className="text-gray-500">
          <div className="text-4xl mb-4">📄</div>
          <h3 className="text-lg font-semibold mb-2">Nenhum documento selecionado</h3>
          <p>Selecione um documento para visualizar e exportar</p>
        </div>
      </GlassCard>
    );
  }

  return (
    <div className="document-preview">
      <div className="flex flex-col lg:flex-row gap-4">
        {/* Main Preview Area */}
        <div className="flex-1">
          <GlassCard variant="light" className="h-full">
            {/* Preview Header */}
            <div className="flex justify-between items-start mb-4 border-b border-gray-200 pb-4">
              <div className="flex-1">
                <h2 className="text-xl font-semibold text-gray-800 mb-2">
                  {document.title}
                </h2>
                <div className="flex flex-wrap gap-2 text-sm text-gray-600">
                  {document.metadata.authors && (
                    <span className="glass-badge">
                      Autores: {document.metadata.authors.join(', ')}
                    </span>
                  )}
                  {document.metadata.date && (
                    <span className="glass-badge">
                      Data: {document.metadata.date}
                    </span>
                  )}
                  {document.metadata.documentType && (
                    <span className="glass-badge glass-badge-success">
                      {document.metadata.documentType}
                    </span>
                  )}
                </div>
              </div>
              
              {onClose && (
                <button
                  onClick={onClose}
                  className="glass-button ml-4"
                  title="Fechar visualização"
                >
                  ✕
                </button>
              )}
            </div>

            {/* Preview Mode Toggle */}
            <div className="flex gap-2 mb-4">
              <button
                onClick={() => setPreviewMode('content')}
                className={`glass-button ${previewMode === 'content' ? 'glass-button-primary' : ''}`}
              >
                Conteúdo
              </button>
              <button
                onClick={() => setPreviewMode('formatted')}
                className={`glass-button ${previewMode === 'formatted' ? 'glass-button-primary' : ''}`}
              >
                Visualização Formatada
              </button>
              <button
                onClick={() => setShowCitation(!showCitation)}
                className={`glass-button ${showCitation ? 'glass-button-primary' : ''}`}
              >
                Citação
              </button>
            </div>

            {/* Content Display */}
            <div className="preview-content" style={{ minHeight: '400px', maxHeight: '600px', overflowY: 'auto' }}>
              {previewMode === 'content' ? (
                <div className="prose max-w-none">
                  {/* Metadata */}
                  {exportOptions.includeMetadata && (
                    <div className="bg-gray-50 rounded-lg p-4 mb-6 border">
                      <h3 className="text-lg font-semibold mb-3 text-gray-800">Metadados</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                        {document.metadata.documentType && (
                          <div>
                            <span className="font-semibold">Tipo:</span> {document.metadata.documentType}
                          </div>
                        )}
                        {document.metadata.source && (
                          <div>
                            <span className="font-semibold">Fonte:</span> {document.metadata.source}
                          </div>
                        )}
                        {document.metadata.urn && (
                          <div>
                            <span className="font-semibold">URN:</span> {document.metadata.urn}
                          </div>
                        )}
                        {document.metadata.url && (
                          <div>
                            <span className="font-semibold">URL:</span> 
                            <a href={document.metadata.url} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline ml-1">
                              {document.metadata.url.length > 50 ? document.metadata.url.substring(0, 50) + '...' : document.metadata.url}
                            </a>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Main Content */}
                  <div className="whitespace-pre-wrap leading-relaxed text-gray-800">
                    {formatContent(document.content)}
                  </div>

                  {/* Analysis */}
                  {exportOptions.includeAnalysis && document.analysis && (
                    <div className="bg-green-50 rounded-lg p-4 mt-6 border border-green-200">
                      <h3 className="text-lg font-semibold mb-3 text-green-800">Análise</h3>
                      
                      {document.analysis.summary && (
                        <div className="mb-4">
                          <h4 className="font-semibold text-green-700 mb-2">Resumo</h4>
                          <p className="text-gray-700">{document.analysis.summary}</p>
                        </div>
                      )}

                      {document.analysis.keyPoints && document.analysis.keyPoints.length > 0 && (
                        <div className="mb-4">
                          <h4 className="font-semibold text-green-700 mb-2">Pontos Principais</h4>
                          <ul className="list-disc list-inside space-y-1 text-gray-700">
                            {document.analysis.keyPoints.map((point, index) => (
                              <li key={index}>{point}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {document.analysis.relatedDocuments && document.analysis.relatedDocuments.length > 0 && (
                        <div>
                          <h4 className="font-semibold text-green-700 mb-2">Documentos Relacionados</h4>
                          <ul className="list-disc list-inside space-y-1 text-gray-700">
                            {document.analysis.relatedDocuments.map((doc, index) => (
                              <li key={index}>{doc}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <div className="formatted-preview bg-white border rounded p-6" style={{ fontFamily: 'Times New Roman, serif' }}>
                  <div className="text-center mb-8 border-b-2 border-blue-600 pb-4">
                    <h1 className="text-2xl font-bold text-blue-600 mb-2">{document.title}</h1>
                    <p className="text-gray-600">Gerado pelo Monitor Legislativo v4</p>
                  </div>

                  {exportOptions.includeMetadata && (
                    <div className="bg-gray-50 border rounded p-4 mb-6">
                      <h3 className="font-bold text-blue-600 mb-3">Metadados do Documento</h3>
                      <div className="space-y-2 text-sm">
                        {Object.entries(document.metadata).map(([key, value]) => {
                          if (value && key !== 'url') {
                            const displayValue = Array.isArray(value) ? value.join(', ') : value;
                            return (
                              <div key={key} className="flex">
                                <span className="font-semibold min-w-28 capitalize">{key.replace(/([A-Z])/g, ' $1')}:</span>
                                <span className="flex-1 text-gray-700">{displayValue}</span>
                              </div>
                            );
                          }
                          return null;
                        })}
                      </div>
                    </div>
                  )}

                  <div className="leading-relaxed text-justify">
                    {formatContent(document.content).split('\n\n').map((paragraph, index) => (
                      <p key={index} className="mb-4 indent-5">{paragraph}</p>
                    ))}
                  </div>
                </div>
              )}

              {/* Citation Display */}
              {showCitation && (
                <div className="bg-blue-50 rounded-lg p-4 mt-6 border border-blue-200">
                  <h3 className="text-lg font-semibold mb-3 text-blue-800">Citação Acadêmica</h3>
                  <div className="bg-white rounded p-3 border italic text-gray-700">
                    {document.citation || generatePreviewCitation()}
                  </div>
                  <p className="text-sm text-blue-600 mt-2">
                    Formato: {exportOptions.citationStyle?.toUpperCase() || 'ABNT'}
                  </p>
                </div>
              )}
            </div>
          </GlassCard>
        </div>

        {/* Export Options Sidebar */}
        {showExportOptions && (
          <div className="lg:w-80">
            <GlassCard variant="academic" className="sticky top-4">
              <h3 className="text-lg font-semibold mb-4 text-gray-800">Opções de Exportação</h3>

              {/* Format Selection */}
              <div className="mb-4">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Formato
                </label>
                <select
                  value={exportOptions.format}
                  onChange={(e) => updateExportOption('format', e.target.value as any)}
                  className="glass-input"
                >
                  <option value="pdf">PDF</option>
                  <option value="html">HTML</option>
                  <option value="txt">Texto</option>
                  <option value="citation">Citação</option>
                </select>
              </div>

              {/* Citation Style */}
              {(exportOptions.format === 'pdf' || exportOptions.format === 'citation') && (
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Estilo de Citação
                  </label>
                  <select
                    value={exportOptions.citationStyle}
                    onChange={(e) => updateExportOption('citationStyle', e.target.value as any)}
                    className="glass-input"
                  >
                    <option value="abnt">ABNT</option>
                    <option value="apa">APA</option>
                    <option value="chicago">Chicago</option>
                    <option value="vancouver">Vancouver</option>
                  </select>
                </div>
              )}

              {/* Include Options */}
              <div className="mb-4 space-y-2">
                <label className="block text-sm font-medium text-gray-700">
                  Incluir no Export
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={exportOptions.includeMetadata}
                    onChange={(e) => updateExportOption('includeMetadata', e.target.checked)}
                    className="mr-2"
                  />
                  <span className="text-sm">Metadados</span>
                </label>

                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={exportOptions.includeCitation}
                    onChange={(e) => updateExportOption('includeCitation', e.target.checked)}
                    className="mr-2"
                  />
                  <span className="text-sm">Citação Acadêmica</span>
                </label>

                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={exportOptions.includeAnalysis}
                    onChange={(e) => updateExportOption('includeAnalysis', e.target.checked)}
                    className="mr-2"
                  />
                  <span className="text-sm">Análise (se disponível)</span>
                </label>
              </div>

              {/* Font Size */}
              {exportOptions.format === 'pdf' && (
                <div className="mb-4">
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Tamanho da Fonte
                  </label>
                  <input
                    type="range"
                    min="10"
                    max="16"
                    value={exportOptions.fontSize}
                    onChange={(e) => updateExportOption('fontSize', parseInt(e.target.value))}
                    className="w-full"
                  />
                  <div className="text-sm text-gray-600 text-center mt-1">
                    {exportOptions.fontSize}px
                  </div>
                </div>
              )}

              {/* Export Button */}
              <button
                onClick={handleExport}
                disabled={isExporting}
                className={`glass-button-primary w-full ${isExporting ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {isExporting ? (
                  <span className="flex items-center justify-center">
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Exportando...
                  </span>
                ) : (
                  `Exportar como ${exportOptions.format.toUpperCase()}`
                )}
              </button>

              {/* Export Result */}
              {exportResult && (
                <div className={`mt-4 p-3 rounded ${
                  exportResult.success 
                    ? 'bg-green-50 border border-green-200 text-green-800' 
                    : 'bg-red-50 border border-red-200 text-red-800'
                }`}>
                  <div className="text-sm">
                    {exportResult.success ? (
                      <>
                        <div className="font-semibold">✅ Export realizado com sucesso!</div>
                        {exportResult.filename && (
                          <div className="mt-1">Arquivo: {exportResult.filename}</div>
                        )}
                        {exportResult.fileSize && (
                          <div>Tamanho: {(exportResult.fileSize / 1024).toFixed(1)} KB</div>
                        )}
                      </>
                    ) : (
                      <>
                        <div className="font-semibold">❌ Erro no export</div>
                        <div className="mt-1">{exportResult.error}</div>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* Export Info */}
              <div className="mt-4 p-3 bg-gray-50 rounded text-xs text-gray-600">
                <p><strong>Dica:</strong> Use o formato PDF para citações acadêmicas e HTML para visualização web.</p>
                <p className="mt-1"><strong>Citações:</strong> Seguem as normas brasileiras (ABNT) por padrão.</p>
              </div>
            </GlassCard>
          </div>
        )}
      </div>
    </div>
  );
};

export default DocumentPreview;