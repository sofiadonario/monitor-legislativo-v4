import React, { useCallback, useState } from 'react';
import '../styles/components/ExportPanel.css';
import { ExportOptions, LegislativeDocument } from '../types';
import { exportToBibTeX } from '../utils/academicExports';
import { fetchJSON } from '../utils/cachedFetch';
import { exportToCSV, exportToHTML, exportToXML } from '../utils/exportHelpers';
import { cacheUtils, localCache } from '../utils/localCache';
import { exportMapToPNG, exportMapWithMetadata, isMapExportSupported } from '../utils/mapExport';

type ExportFormat = 'csv' | 'xml' | 'html' | 'bibtex' | 'png';

interface ExportPanelProps {
  isOpen: boolean;
  onClose: () => void;
  documents: LegislativeDocument[];
  id?: string;
}

const ExportPanel: React.FC<ExportPanelProps> = ({
  isOpen,
  onClose,
  documents,
  id
}) => {
  const [exportFormat, setExportFormat] = useState<ExportFormat>('csv');
  const [includeMap, setIncludeMap] = useState(false);
  const [includeMetadata, setIncludeMetadata] = useState(true);
  const [exportStatus, setExportStatus] = useState<'idle' | 'checking' | 'generating' | 'ready'>('idle');
  const [dateRange, setDateRange] = useState({
    from: '',
    to: ''
  });

  const generateCacheKey = useCallback((format: string, options: ExportOptions) => {
    const queryParams = {
      format,
      documents: documents.map(d => d.id).sort(),
      includeMap: options.includeMap,
      includeMetadata: options.includeMetadata,
      dateRange: options.dateRange
    };
    return cacheUtils.generateKey('export', queryParams);
  }, [documents]);

  const downloadFile = useCallback((content: string | Blob, filename: string) => {
    const blob = content instanceof Blob ? content : new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, []);

  const handleExport = async () => {
    const options: ExportOptions = {
      format: exportFormat,
      includeMap,
      includeMetadata,
      dateRange: dateRange.from || dateRange.to ? dateRange : undefined
    };

    try {
      // Generate cache key
      const cacheKey = generateCacheKey(exportFormat, options);
      
      // Check local cache first
      setExportStatus('checking');
      const cached = localCache.get<string>(cacheKey);
      
      if (cached) {
        console.log('Using cached export');
        const filename = `monitor-legislativo-${exportFormat}-${Date.now()}.${exportFormat}`;
        downloadFile(cached, filename);
        setExportStatus('ready');
        return;
      }

      // Check server cache
      try {
        const serverCached = await fetchJSON(`/api/v1/export/cached/${encodeURIComponent(cacheKey)}`);
        if (serverCached && serverCached.content) {
          console.log('Using server cached export');
          localCache.set(cacheKey, serverCached.content, 3600000); // Cache for 1 hour
          const filename = `monitor-legislativo-${exportFormat}-${Date.now()}.${exportFormat}`;
          downloadFile(serverCached.content, filename);
          setExportStatus('ready');
          return;
        }
      } catch (error) {
        console.log('No server cache available, generating fresh export');
      }

      // Generate new export
      setExportStatus('generating');
      let filteredDocuments = documents;
      
      // Apply date range filter if specified
      if (options.dateRange) {
        filteredDocuments = documents.filter(doc => {
          if (options.dateRange!.from && doc.date < options.dateRange!.from) return false;
          if (options.dateRange!.to && doc.date > options.dateRange!.to) return false;
          return true;
        });
      }

      let exportContent: string;
      let filename: string;

      switch (exportFormat) {
        case 'csv':
          exportToCSV(filteredDocuments, options);
          break;
        case 'xml':
          exportToXML(filteredDocuments, options);
          break;
        case 'html':
          exportToHTML(filteredDocuments, options);
          break;
        case 'bibtex':
          exportToBibTeX(filteredDocuments);
          break;
        case 'png':
          if (includeMetadata) {
            await exportMapWithMetadata(filteredDocuments, undefined, { 
              format: 'png',
              includeControls: false,
              includeLegend: true 
            });
          } else {
            await exportMapToPNG({ 
              format: 'png',
              includeControls: false,
              includeLegend: true 
            });
          }
          break;
      }
    } catch (error) {
      console.error('Export failed:', error);
      alert('Erro ao exportar dados. Tente novamente.');
    }
  };

  if (!isOpen) return null;

  return (
    <div id={id} className="export-panel-overlay" role="dialog" aria-modal="true" aria-labelledby="export-panel-title">
      <div className="export-panel">
        <div className="export-header">
          <h2 id="export-panel-title">Exportar Dados</h2>
          <button className="close-btn" onClick={onClose} aria-label="Fechar">
            ✕
          </button>
        </div>
        
        <div className="export-content">
          <div className="export-summary">
            <p><strong>{documents.length}</strong> documentos selecionados para exportação</p>
          </div>
          
          {/* Format Selection */}
          <div className="export-section">
            <h3>Formato de Exportação</h3>
            <div className="format-options">
              <label className="radio-option">
                <input
                  type="radio"
                  name="format"
                  value="csv"
                  checked={exportFormat === 'csv'}
                  onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
                />
                <span className="format-label">
                  <strong>CSV</strong> - Dados tabulares para análise
                </span>
              </label>
              
              <label className="radio-option">
                <input
                  type="radio"
                  name="format"
                  value="xml"
                  checked={exportFormat === 'xml'}
                  onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
                />
                <span className="format-label">
                  <strong>XML</strong> - Dados estruturados para sistemas
                </span>
              </label>
              
              <label className="radio-option">
                <input
                  type="radio"
                  name="format"
                  value="html"
                  checked={exportFormat === 'html'}
                  onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
                />
                <span className="format-label">
                  <strong>HTML</strong> - Relatório formatado para leitura
                </span>
              </label>
              
              <label className="radio-option">
                <input
                  type="radio"
                  name="format"
                  value="bibtex"
                  checked={exportFormat === 'bibtex'}
                  onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
                />
                <span className="format-label">
                  <strong>BibTeX</strong> - Referências bibliográficas para LaTeX
                </span>
              </label>
              
              <label className="radio-option">
                <input
                  type="radio"
                  name="format"
                  value="png"
                  checked={exportFormat === 'png'}
                  disabled={!isMapExportSupported()}
                  onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
                />
                <span className="format-label">
                  <strong>PNG</strong> - Imagem do mapa atual
                  {!isMapExportSupported() && <em> (não suportado neste navegador)</em>}
                </span>
              </label>
            </div>
          </div>
          
          {/* Export Options */}
          <div className="export-section">
            <h3>Opções de Exportação</h3>
            
            <label className="checkbox-option">
              <input
                type="checkbox"
                checked={includeMetadata}
                onChange={(e) => setIncludeMetadata(e.target.checked)}
              />
              Incluir metadados (fonte, citação, URL)
            </label>
            
            {exportFormat !== 'png' && (
              <label className="checkbox-option">
                <input
                  type="checkbox"
                  checked={includeMap}
                  onChange={(e) => setIncludeMap(e.target.checked)}
                />
                Incluir informações geográficas
              </label>
            )}
          </div>
          
          {/* Date Range Filter */}
          <div className="export-section">
            <h3>Filtro de Data (Opcional)</h3>
            <div className="date-range">
              <div className="date-input-group">
                <label>Data inicial:</label>
                <input
                  type="date"
                  value={dateRange.from}
                  onChange={(e) => setDateRange({ ...dateRange, from: e.target.value })}
                  aria-label="Data inicial"
                />
              </div>
              <div className="date-input-group">
                <label>Data final:</label>
                <input
                  type="date"
                  value={dateRange.to}
                  onChange={(e) => setDateRange({ ...dateRange, to: e.target.value })}
                  aria-label="Data final"
                />
              </div>
            </div>
          </div>
          
          {/* Academic Citation Info */}
          <div className="export-section citation-info">
            <h3>Informações para Citação Acadêmica</h3>
            <p className="citation-note">
              Os dados exportados incluem informações completas de citação para uso acadêmico. 
              Recomenda-se sempre verificar a fonte original dos documentos.
            </p>
            <div className="suggested-citation">
              <strong>Citação sugerida para esta pesquisa:</strong>
              <p className="citation-text">
                Mapa Legislativo Acadêmico. Dados legislativos georeferenciados do Brasil. 
                Exportado em {new Date().toLocaleDateString('pt-BR')}. 
                Disponível em: [URL da aplicação].
              </p>
            </div>
          </div>
        </div>
        
        <div className="export-actions">
          <button className="cancel-btn" onClick={onClose}>
            Cancelar
          </button>
          <button 
            className="export-confirm-btn" 
            onClick={handleExport}
            disabled={documents.length === 0 || exportStatus === 'generating'}
          >
            {exportStatus === 'checking' && '🔍 Verificando cache...'}
            {exportStatus === 'generating' && '⏳ Gerando exportação...'}
            {exportStatus === 'ready' && '✅ Pronto!'}
            {exportStatus === 'idle' && `Exportar ${exportFormat === 'png' ? 'Imagem PNG' : exportFormat.toUpperCase()}`}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ExportPanel;