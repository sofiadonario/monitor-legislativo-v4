/**
 * GISExportPanel Component
 * User interface for exporting geographic data in various formats
 */
import React, { useState, useMemo } from 'react';
import { DocumentLocation, StateData, Municipality } from '../types';
import { DocumentCluster, RegionalStatistics, SpatialHotspot } from '../services/spatialAnalysisService';
import { gisExportService, ExportOptions } from '../services/gisExportService';

interface GISExportPanelProps {
  documents: DocumentLocation[];
  clusters?: DocumentCluster[];
  hotspots?: SpatialHotspot[];
  regionalStats?: RegionalStatistics[];
  states?: StateData[];
  municipalities?: Municipality[];
  onExportComplete?: (format: string, filename: string) => void;
}

type ExportType = 'documents' | 'clusters' | 'hotspots' | 'boundaries' | 'statistics';
type ExportFormat = 'geojson' | 'kml' | 'csv' | 'excel';

export const GISExportPanel: React.FC<GISExportPanelProps> = ({
  documents,
  clusters = [],
  hotspots = [],
  regionalStats = [],
  states = [],
  municipalities = [],
  onExportComplete
}) => {
  const [selectedType, setSelectedType] = useState<ExportType>('documents');
  const [selectedFormat, setSelectedFormat] = useState<ExportFormat>('geojson');
  const [includeMetadata, setIncludeMetadata] = useState(true);
  const [coordinateSystem, setCoordinateSystem] = useState<'WGS84' | 'SIRGAS2000'>('WGS84');
  const [precision, setPrecision] = useState(6);
  const [isExporting, setIsExporting] = useState(false);

  // Export summary information
  const exportSummary = useMemo(() => {
    return gisExportService.getExportSummary(documents, clusters, hotspots);
  }, [documents, clusters, hotspots]);

  // Available formats by export type
  const availableFormats = useMemo(() => {
    switch (selectedType) {
      case 'documents':
      case 'clusters':
      case 'hotspots':
      case 'boundaries':
        return ['geojson', 'kml', 'csv'];
      case 'statistics':
        return ['csv', 'excel'];
      default:
        return ['geojson'];
    }
  }, [selectedType]);

  // Export type configurations
  const exportConfigs = {
    documents: {
      title: 'Legislative Documents',
      description: 'Point locations of legislative documents with metadata',
      icon: '📄',
      count: documents.length
    },
    clusters: {
      title: 'Document Clusters',
      description: 'Spatial clusters of documents with statistics',
      icon: '🔗',
      count: clusters.length
    },
    hotspots: {
      title: 'Spatial Hotspots',
      description: 'Statistical hotspots and coldspots',
      icon: '🔥',
      count: hotspots.length
    },
    boundaries: {
      title: 'Administrative Boundaries',
      description: 'State and municipality boundaries',
      icon: '🗺️',
      count: states.length + municipalities.length
    },
    statistics: {
      title: 'Regional Statistics',
      description: 'Statistical analysis by state and region',
      icon: '📊',
      count: regionalStats.length
    }
  };

  const handleExport = async () => {
    if (isExporting) return;

    setIsExporting(true);

    try {
      const options: ExportOptions = {
        format: selectedFormat,
        includeMetadata,
        coordinateSystem,
        precision,
        timestamp: true
      };

      let content: any;
      let filename: string;
      let mimeType: string;

      switch (selectedType) {
        case 'documents':
          if (selectedFormat === 'geojson') {
            content = gisExportService.exportDocumentsToGeoJSON(documents, options);
            mimeType = 'application/json';
          } else if (selectedFormat === 'kml') {
            content = gisExportService.exportDocumentsToKML(documents, options);
            mimeType = 'application/vnd.google-earth.kml+xml';
          } else if (selectedFormat === 'csv') {
            content = gisExportService.exportDocumentsToCSV(documents, options);
            mimeType = 'text/csv';
          }
          filename = gisExportService.generateFilename('legislative_documents', selectedFormat);
          break;

        case 'clusters':
          if (selectedFormat === 'geojson') {
            content = gisExportService.exportClustersToGeoJSON(clusters, options);
            mimeType = 'application/json';
          } else if (selectedFormat === 'csv') {
            content = exportClustersToCSV(clusters, options);
            mimeType = 'text/csv';
          }
          filename = gisExportService.generateFilename('document_clusters', selectedFormat);
          break;

        case 'hotspots':
          if (selectedFormat === 'geojson') {
            content = gisExportService.exportHotspotsToGeoJSON(hotspots, options);
            mimeType = 'application/json';
          } else if (selectedFormat === 'csv') {
            content = exportHotspotsToCSV(hotspots, options);
            mimeType = 'text/csv';
          }
          filename = gisExportService.generateFilename('spatial_hotspots', selectedFormat);
          break;

        case 'boundaries':
          if (selectedFormat === 'geojson') {
            content = gisExportService.exportBoundariesToGeoJSON(states, municipalities, options);
            mimeType = 'application/json';
          } else if (selectedFormat === 'csv') {
            content = exportBoundariesToCSV(states, municipalities, options);
            mimeType = 'text/csv';
          }
          filename = gisExportService.generateFilename('administrative_boundaries', selectedFormat);
          break;

        case 'statistics':
          content = gisExportService.exportRegionalStatisticsToCSV(regionalStats, options);
          mimeType = 'text/csv';
          filename = gisExportService.generateFilename('regional_statistics', 'csv');
          break;

        default:
          throw new Error('Invalid export type');
      }

      if (content) {
        gisExportService.downloadFile(content, filename, mimeType);
        
        if (onExportComplete) {
          onExportComplete(selectedFormat, filename);
        }
      }

    } catch (error) {
      console.error('Export failed:', error);
      alert('Export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  const exportClustersToCSV = (clusters: DocumentCluster[], options: ExportOptions): string => {
    const headers = [
      'clusterId',
      'documentCount',
      'centerLatitude',
      'centerLongitude',
      'radius',
      'density',
      'dominantType',
      'weight'
    ];

    if (options.includeMetadata) {
      headers.push('exportDate');
    }

    const rows = clusters.map(cluster => {
      const row = [
        cluster.id,
        cluster.documents.length,
        cluster.center.lat,
        cluster.center.lng,
        cluster.radius,
        cluster.density,
        cluster.dominantType,
        cluster.weight
      ];

      if (options.includeMetadata) {
        row.push(new Date().toISOString());
      }

      return row.join(',');
    });

    return [headers.join(','), ...rows].join('\n');
  };

  const exportHotspotsToCSV = (hotspots: SpatialHotspot[], options: ExportOptions): string => {
    const headers = [
      'hotspotId',
      'type',
      'centerLatitude',
      'centerLongitude',
      'documentCount',
      'radius',
      'significance',
      'zScore',
      'pValue'
    ];

    if (options.includeMetadata) {
      headers.push('exportDate');
    }

    const rows = hotspots.map(hotspot => {
      const row = [
        hotspot.id,
        hotspot.type,
        hotspot.center.lat,
        hotspot.center.lng,
        hotspot.documentCount,
        hotspot.radius,
        hotspot.significance,
        hotspot.zScore,
        hotspot.pValue
      ];

      if (options.includeMetadata) {
        row.push(new Date().toISOString());
      }

      return row.join(',');
    });

    return [headers.join(','), ...rows].join('\n');
  };

  const exportBoundariesToCSV = (states: StateData[], municipalities: Municipality[], options: ExportOptions): string => {
    const headers = [
      'type',
      'id',
      'name',
      'stateId',
      'region',
      'population',
      'area',
      'centerLatitude',
      'centerLongitude'
    ];

    if (options.includeMetadata) {
      headers.push('exportDate');
    }

    const stateRows = states.map(state => {
      const row = [
        'state',
        state.id,
        state.name,
        state.id,
        state.region,
        state.population || '',
        state.area || '',
        state.coordinates[0],
        state.coordinates[1]
      ];

      if (options.includeMetadata) {
        row.push(new Date().toISOString());
      }

      return row.join(',');
    });

    const municipalityRows = municipalities.map(muni => {
      const row = [
        'municipality',
        muni.id,
        muni.name,
        muni.stateId,
        '',
        muni.population || '',
        muni.area || '',
        muni.coordinates.lat,
        muni.coordinates.lng
      ];

      if (options.includeMetadata) {
        row.push(new Date().toISOString());
      }

      return row.join(',');
    });

    return [headers.join(','), ...stateRows, ...municipalityRows].join('\n');
  };

  return (
    <div className="gis-export-panel">
      <div className="export-panel__header">
        <h3>🌍 GIS Data Export</h3>
        <p>Export geographic data in various formats for use in GIS applications</p>
      </div>

      {/* Export Summary */}
      <div className="export-summary">
        <h4>Data Summary</h4>
        <div className="summary-grid">
          <div className="summary-item">
            <span className="summary-value">{exportSummary.documentCount.toLocaleString()}</span>
            <span className="summary-label">Documents</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{exportSummary.uniqueStates}</span>
            <span className="summary-label">States</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{exportSummary.uniqueMunicipalities}</span>
            <span className="summary-label">Municipalities</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{Math.round(exportSummary.avgConfidence * 100)}%</span>
            <span className="summary-label">Avg Confidence</span>
          </div>
        </div>
      </div>

      {/* Export Type Selection */}
      <div className="export-type-selection">
        <h4>Export Data Type</h4>
        <div className="type-grid">
          {Object.entries(exportConfigs).map(([type, config]) => (
            <div
              key={type}
              className={`type-card ${selectedType === type ? 'selected' : ''} ${config.count === 0 ? 'disabled' : ''}`}
              onClick={() => config.count > 0 && setSelectedType(type as ExportType)}
            >
              <div className="type-card__icon">{config.icon}</div>
              <div className="type-card__title">{config.title}</div>
              <div className="type-card__count">{config.count.toLocaleString()} items</div>
              <div className="type-card__description">{config.description}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Format and Options */}
      <div className="export-options">
        <h4>Export Options</h4>
        
        <div className="options-grid">
          <div className="option-group">
            <label htmlFor="export-format">Format:</label>
            <select
              id="export-format"
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value as ExportFormat)}
            >
              {availableFormats.map(format => (
                <option key={format} value={format}>
                  {format.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          {selectedFormat !== 'csv' && (
            <div className="option-group">
              <label htmlFor="coordinate-system">Coordinate System:</label>
              <select
                id="coordinate-system"
                value={coordinateSystem}
                onChange={(e) => setCoordinateSystem(e.target.value as 'WGS84' | 'SIRGAS2000')}
              >
                <option value="WGS84">WGS84 (Global)</option>
                <option value="SIRGAS2000">SIRGAS2000 (Brazil)</option>
              </select>
            </div>
          )}

          <div className="option-group">
            <label htmlFor="precision">Coordinate Precision:</label>
            <select
              id="precision"
              value={precision}
              onChange={(e) => setPrecision(parseInt(e.target.value))}
            >
              <option value={4}>4 decimal places (~11m)</option>
              <option value={5}>5 decimal places (~1m)</option>
              <option value={6}>6 decimal places (~0.1m)</option>
              <option value={7}>7 decimal places (~1cm)</option>
            </select>
          </div>

          <div className="option-group checkbox-group">
            <label>
              <input
                type="checkbox"
                checked={includeMetadata}
                onChange={(e) => setIncludeMetadata(e.target.checked)}
              />
              Include metadata and timestamps
            </label>
          </div>
        </div>
      </div>

      {/* Format Information */}
      <div className="format-info">
        <h4>Format Information</h4>
        <div className="format-descriptions">
          <div className="format-desc">
            <strong>GeoJSON:</strong> Standard format for web mapping and GIS applications. 
            Compatible with QGIS, ArcGIS, and web mapping libraries.
          </div>
          <div className="format-desc">
            <strong>KML:</strong> Google Earth format for 3D visualization and sharing.
            Best for presentations and public viewing.
          </div>
          <div className="format-desc">
            <strong>CSV:</strong> Tabular format for statistical analysis.
            Compatible with Excel, R, Python, and database systems.
          </div>
        </div>
      </div>

      {/* Export Button */}
      <div className="export-action">
        <button
          className="export-btn"
          onClick={handleExport}
          disabled={isExporting || exportConfigs[selectedType].count === 0}
        >
          {isExporting ? (
            <>
              <span className="export-spinner">⏳</span>
              Exporting...
            </>
          ) : (
            <>
              <span className="export-icon">📥</span>
              Export {selectedFormat.toUpperCase()}
            </>
          )}
        </button>
        
        {exportConfigs[selectedType].count === 0 && (
          <p className="export-warning">
            No data available for selected export type
          </p>
        )}
      </div>
    </div>
  );
};

// CSS styles (to be injected)
const exportStyles = `
.gis-export-panel {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.export-panel__header h3 {
  color: #2d3748;
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0 0 0.5rem 0;
}

.export-panel__header p {
  color: #718096;
  font-size: 0.875rem;
  margin: 0 0 1.5rem 0;
}

.export-summary {
  background: #f7fafc;
  border-radius: 6px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}

.export-summary h4 {
  color: #2d3748;
  font-size: 1rem;
  margin: 0 0 1rem 0;
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 1rem;
}

.summary-item {
  text-align: center;
}

.summary-value {
  display: block;
  font-size: 1.5rem;
  font-weight: 700;
  color: #2d3748;
  line-height: 1;
}

.summary-label {
  font-size: 0.75rem;
  color: #718096;
  margin-top: 0.25rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.export-type-selection h4,
.export-options h4,
.format-info h4 {
  color: #2d3748;
  font-size: 1rem;
  margin: 0 0 1rem 0;
}

.type-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.type-card {
  background: #f7fafc;
  border: 2px solid #e2e8f0;
  border-radius: 6px;
  padding: 1rem;
  cursor: pointer;
  transition: all 0.2s;
  text-align: center;
}

.type-card:hover:not(.disabled) {
  border-color: #cbd5e0;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.type-card.selected {
  border-color: #4299e1;
  background: #ebf8ff;
}

.type-card.disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.type-card__icon {
  font-size: 2rem;
  margin-bottom: 0.5rem;
}

.type-card__title {
  font-weight: 600;
  color: #2d3748;
  margin-bottom: 0.25rem;
}

.type-card__count {
  font-size: 0.875rem;
  color: #4a5568;
  margin-bottom: 0.5rem;
}

.type-card__description {
  font-size: 0.75rem;
  color: #718096;
  line-height: 1.3;
}

.options-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.option-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.option-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #4a5568;
}

.option-group select {
  padding: 0.5rem;
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  font-size: 0.875rem;
  background: #ffffff;
}

.checkbox-group {
  flex-direction: row;
  align-items: center;
}

.checkbox-group label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}

.format-info {
  background: #f0fff4;
  border-left: 4px solid #48bb78;
  border-radius: 4px;
  padding: 1rem;
  margin-bottom: 1.5rem;
}

.format-descriptions {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.format-desc {
  font-size: 0.875rem;
  line-height: 1.4;
  color: #2d3748;
}

.export-action {
  text-align: center;
  border-top: 1px solid #e2e8f0;
  padding-top: 1.5rem;
}

.export-btn {
  background-color: #4299e1;
  color: #ffffff;
  border: none;
  padding: 0.75rem 2rem;
  border-radius: 6px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
}

.export-btn:hover:not(:disabled) {
  background-color: #3182ce;
  transform: translateY(-1px);
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.export-btn:disabled {
  background-color: #a0aec0;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}

.export-spinner {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.export-warning {
  color: #e53e3e;
  font-size: 0.875rem;
  margin-top: 0.5rem;
  font-style: italic;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = exportStyles;
  document.head.appendChild(styleElement);
}