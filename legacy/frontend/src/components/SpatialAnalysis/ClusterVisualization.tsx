/**
 * ClusterVisualization Component
 * Displays document clusters with statistics and interactive analysis
 */
import React, { useState, useMemo } from 'react';
import { DocumentCluster, spatialAnalysisService } from '../../services/spatialAnalysisService';
import { DocumentLocation } from '../../types';

interface ClusterVisualizationProps {
  documents: DocumentLocation[];
  maxDistance?: number;
  minPoints?: number;
  onClusterSelect?: (cluster: DocumentCluster) => void;
  selectedCluster?: string;
}

export const ClusterVisualization: React.FC<ClusterVisualizationProps> = ({
  documents,
  maxDistance = 50,
  minPoints = 3,
  onClusterSelect,
  selectedCluster
}) => {
  const [showStatistics, setShowStatistics] = useState(true);

  // Calculate clusters
  const clusters = useMemo(() => {
    return spatialAnalysisService.clusterDocuments(documents, maxDistance, minPoints);
  }, [documents, maxDistance, minPoints]);

  // Calculate cluster statistics
  const statistics = useMemo(() => {
    const totalClustered = clusters.reduce((sum, cluster) => sum + cluster.documents.length, 0);
    const avgClusterSize = clusters.length > 0 ? totalClustered / clusters.length : 0;
    const avgDensity = clusters.length > 0 
      ? clusters.reduce((sum, cluster) => sum + cluster.density, 0) / clusters.length 
      : 0;
    
    const typeDistribution = clusters.reduce((acc, cluster) => {
      acc[cluster.dominantType] = (acc[cluster.dominantType] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalClusters: clusters.length,
      totalClustered,
      unclustered: documents.length - totalClustered,
      clusteringRate: documents.length > 0 ? totalClustered / documents.length : 0,
      avgClusterSize,
      avgDensity,
      typeDistribution
    };
  }, [clusters, documents.length]);

  const handleClusterClick = (cluster: DocumentCluster) => {
    if (onClusterSelect) {
      onClusterSelect(cluster);
    }
  };

  return (
    <div className="cluster-visualization">
      <div className="cluster-visualization__header">
        <h3>Document Clustering Analysis</h3>
        <div className="cluster-visualization__controls">
          <button 
            onClick={() => setShowStatistics(!showStatistics)}
            className="toggle-stats-btn"
          >
            {showStatistics ? 'Hide' : 'Show'} Statistics
          </button>
        </div>
      </div>

      {showStatistics && (
        <div className="cluster-stats">
          <div className="cluster-stats__grid">
            <div className="stat-card">
              <div className="stat-card__value">{statistics.totalClusters}</div>
              <div className="stat-card__label">Total Clusters</div>
            </div>
            <div className="stat-card">
              <div className="stat-card__value">{statistics.totalClustered}</div>
              <div className="stat-card__label">Clustered Documents</div>
            </div>
            <div className="stat-card">
              <div className="stat-card__value">{statistics.unclustered}</div>
              <div className="stat-card__label">Isolated Documents</div>
            </div>
            <div className="stat-card">
              <div className="stat-card__value">{Math.round(statistics.clusteringRate * 100)}%</div>
              <div className="stat-card__label">Clustering Rate</div>
            </div>
          </div>

          <div className="cluster-metrics">
            <div className="metric">
              <strong>Average Cluster Size:</strong> {statistics.avgClusterSize.toFixed(1)} documents
            </div>
            <div className="metric">
              <strong>Average Density:</strong> {statistics.avgDensity.toFixed(3)} docs/km²
            </div>
          </div>

          <div className="type-distribution">
            <h4>Dominant Document Types in Clusters</h4>
            <div className="type-bars">
              {Object.entries(statistics.typeDistribution).map(([type, count]) => (
                <div key={type} className="type-bar">
                  <div className="type-bar__label">{type.toUpperCase()}</div>
                  <div className="type-bar__track">
                    <div 
                      className="type-bar__fill"
                      style={{ 
                        width: `${(count / statistics.totalClusters) * 100}%`,
                        backgroundColor: getTypeColor(type)
                      }}
                    />
                  </div>
                  <div className="type-bar__count">{count}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="cluster-list">
        <h4>Document Clusters ({clusters.length})</h4>
        <div className="cluster-list__container">
          {clusters.length === 0 ? (
            <div className="no-clusters">
              <p>No clusters found with current parameters.</p>
              <p>Try reducing the minimum points or increasing the search distance.</p>
            </div>
          ) : (
            clusters.map((cluster, index) => (
              <div 
                key={cluster.id}
                className={`cluster-item ${selectedCluster === cluster.id ? 'selected' : ''}`}
                onClick={() => handleClusterClick(cluster)}
              >
                <div className="cluster-item__header">
                  <div className="cluster-item__title">
                    Cluster {index + 1}
                  </div>
                  <div className="cluster-item__type" style={{ backgroundColor: getTypeColor(cluster.dominantType) }}>
                    {cluster.dominantType.toUpperCase()}
                  </div>
                </div>
                
                <div className="cluster-item__stats">
                  <div className="cluster-stat">
                    <span className="stat-label">Documents:</span>
                    <span className="stat-value">{cluster.documents.length}</span>
                  </div>
                  <div className="cluster-stat">
                    <span className="stat-label">Radius:</span>
                    <span className="stat-value">{cluster.radius.toFixed(1)} km</span>
                  </div>
                  <div className="cluster-stat">
                    <span className="stat-label">Density:</span>
                    <span className="stat-value">{cluster.density.toFixed(3)}</span>
                  </div>
                  <div className="cluster-stat">
                    <span className="stat-label">Weight:</span>
                    <span className="stat-value">{cluster.weight.toFixed(2)}</span>
                  </div>
                </div>

                <div className="cluster-item__location">
                  📍 {cluster.center.lat.toFixed(4)}, {cluster.center.lng.toFixed(4)}
                </div>

                <div className="cluster-item__documents">
                  <details>
                    <summary>Documents in this cluster ({cluster.documents.length})</summary>
                    <div className="document-list">
                      {cluster.documents.slice(0, 5).map(doc => (
                        <div key={doc.urn} className="document-item">
                          <div className="document-title">{doc.title}</div>
                          <div className="document-meta">
                            {doc.municipality}, {doc.state} | {doc.type} | {Math.round(doc.confidence * 100)}%
                          </div>
                        </div>
                      ))}
                      {cluster.documents.length > 5 && (
                        <div className="more-documents">
                          +{cluster.documents.length - 5} more documents
                        </div>
                      )}
                    </div>
                  </details>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

const getTypeColor = (type: string): string => {
  const colors: Record<string, string> = {
    lei: '#4299e1',
    decreto: '#48bb78',
    portaria: '#ed8936',
    resolucao: '#9f7aea',
    instrucao_normativa: '#38b2ac',
    projeto_lei: '#f56565',
    medida_provisoria: '#d69e2e'
  };
  return colors[type] || '#718096';
};

// CSS styles (to be injected)
const clusterStyles = `
.cluster-visualization {
  background: #ffffff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem;
  margin-bottom: 1rem;
}

.cluster-visualization__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
}

.cluster-visualization__header h3 {
  color: #2d3748;
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
}

.toggle-stats-btn {
  background-color: #f7fafc;
  border: 1px solid #e2e8f0;
  color: #4a5568;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.toggle-stats-btn:hover {
  background-color: #edf2f7;
  border-color: #cbd5e0;
}

.cluster-stats {
  background: #f7fafc;
  border-radius: 6px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}

.cluster-stats__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.stat-card {
  background: #ffffff;
  border-radius: 6px;
  padding: 1rem;
  text-align: center;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.stat-card__value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #2d3748;
  line-height: 1;
}

.stat-card__label {
  font-size: 0.875rem;
  color: #718096;
  margin-top: 0.5rem;
}

.cluster-metrics {
  margin-bottom: 1.5rem;
}

.metric {
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
  color: #4a5568;
}

.type-distribution h4 {
  color: #2d3748;
  font-size: 1rem;
  margin-bottom: 1rem;
}

.type-bars {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.type-bar {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.type-bar__label {
  min-width: 120px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #4a5568;
}

.type-bar__track {
  flex: 1;
  height: 8px;
  background-color: #e2e8f0;
  border-radius: 4px;
  overflow: hidden;
}

.type-bar__fill {
  height: 100%;
  transition: width 0.3s ease;
}

.type-bar__count {
  min-width: 30px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #4a5568;
  text-align: right;
}

.cluster-list h4 {
  color: #2d3748;
  font-size: 1.125rem;
  margin-bottom: 1rem;
}

.cluster-list__container {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  max-height: 600px;
  overflow-y: auto;
}

.no-clusters {
  text-align: center;
  padding: 2rem;
  color: #718096;
}

.cluster-item {
  background: #f7fafc;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  padding: 1rem;
  cursor: pointer;
  transition: all 0.2s;
}

.cluster-item:hover {
  border-color: #cbd5e0;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.cluster-item.selected {
  border-color: #4299e1;
  box-shadow: 0 0 0 2px rgba(66, 153, 225, 0.2);
}

.cluster-item__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.cluster-item__title {
  font-weight: 600;
  color: #2d3748;
}

.cluster-item__type {
  color: #ffffff;
  padding: 0.25rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: 600;
}

.cluster-item__stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 0.5rem;
  margin-bottom: 0.75rem;
}

.cluster-stat {
  display: flex;
  justify-content: space-between;
  font-size: 0.875rem;
}

.stat-label {
  color: #718096;
}

.stat-value {
  font-weight: 500;
  color: #2d3748;
}

.cluster-item__location {
  font-family: monospace;
  font-size: 0.875rem;
  color: #4a5568;
  margin-bottom: 0.75rem;
}

.cluster-item__documents details {
  font-size: 0.875rem;
}

.cluster-item__documents summary {
  cursor: pointer;
  font-weight: 500;
  color: #4a5568;
  margin-bottom: 0.5rem;
}

.document-list {
  background: #ffffff;
  border-radius: 4px;
  padding: 0.75rem;
  margin-top: 0.5rem;
}

.document-item {
  padding: 0.5rem 0;
  border-bottom: 1px solid #f1f5f9;
}

.document-item:last-child {
  border-bottom: none;
}

.document-title {
  font-weight: 500;
  color: #2d3748;
  line-height: 1.3;
  margin-bottom: 0.25rem;
}

.document-meta {
  font-size: 0.75rem;
  color: #718096;
}

.more-documents {
  padding: 0.5rem 0;
  color: #4a5568;
  font-style: italic;
  text-align: center;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = clusterStyles;
  document.head.appendChild(styleElement);
}