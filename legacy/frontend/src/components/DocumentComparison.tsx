import React, { useState, useMemo } from 'react';
import { LegislativeDocument } from '../types';
import '../styles/components/DocumentComparison.css';

interface DocumentComparisonProps {
  documents: LegislativeDocument[];
  selectedDocuments?: string[];
  onClose: () => void;
}

interface ComparisonData {
  similarities: string[];
  differences: Array<{
    field: string;
    doc1: string;
    doc2: string;
  }>;
  score: number;
}

export const DocumentComparison: React.FC<DocumentComparisonProps> = ({
  documents,
  selectedDocuments = [],
  onClose
}) => {
  const [selectedDoc1, setSelectedDoc1] = useState<string>(selectedDocuments[0] || '');
  const [selectedDoc2, setSelectedDoc2] = useState<string>(selectedDocuments[1] || '');
  const [comparisonMode, setComparisonMode] = useState<'side-by-side' | 'unified'>('side-by-side');

  // Get document objects
  const doc1 = documents.find(doc => doc.id === selectedDoc1);
  const doc2 = documents.find(doc => doc.id === selectedDoc2);

  // Calculate comparison data
  const comparisonData = useMemo((): ComparisonData | null => {
    if (!doc1 || !doc2) return null;

    const similarities: string[] = [];
    const differences: Array<{ field: string; doc1: string; doc2: string }> = [];
    let matchingFields = 0;
    const totalFields = 7; // Number of comparable fields

    // Compare document type
    if (doc1.type === doc2.type) {
      similarities.push(`Both are ${doc1.type} documents`);
      matchingFields++;
    } else {
      differences.push({
        field: 'Document Type',
        doc1: doc1.type,
        doc2: doc2.type
      });
    }

    // Compare state
    if (doc1.state === doc2.state) {
      similarities.push(`Both from ${doc1.state || 'unknown state'}`);
      matchingFields++;
    } else {
      differences.push({
        field: 'State',
        doc1: doc1.state || 'Unknown',
        doc2: doc2.state || 'Unknown'
      });
    }

    // Compare municipality
    if (doc1.municipality === doc2.municipality) {
      if (doc1.municipality) {
        similarities.push(`Both from ${doc1.municipality}`);
      }
      matchingFields++;
    } else {
      differences.push({
        field: 'Municipality',
        doc1: doc1.municipality || 'Not specified',
        doc2: doc2.municipality || 'Not specified'
      });
    }

    // Compare keywords
    const commonKeywords = doc1.keywords.filter(k => doc2.keywords.includes(k));
    if (commonKeywords.length > 0) {
      similarities.push(`Common keywords: ${commonKeywords.join(', ')}`);
      matchingFields += 0.5;
    }

    const uniqueDoc1Keywords = doc1.keywords.filter(k => !doc2.keywords.includes(k));
    const uniqueDoc2Keywords = doc2.keywords.filter(k => !doc1.keywords.includes(k));
    
    if (uniqueDoc1Keywords.length > 0 || uniqueDoc2Keywords.length > 0) {
      differences.push({
        field: 'Unique Keywords',
        doc1: uniqueDoc1Keywords.join(', ') || 'None',
        doc2: uniqueDoc2Keywords.join(', ') || 'None'
      });
    }

    // Compare dates (year)
    const date1 = typeof doc1.date === 'string' ? new Date(doc1.date) : doc1.date;
    const date2 = typeof doc2.date === 'string' ? new Date(doc2.date) : doc2.date;
    
    if (date1.getFullYear() === date2.getFullYear()) {
      similarities.push(`Both from ${date1.getFullYear()}`);
      matchingFields++;
    } else {
      differences.push({
        field: 'Year',
        doc1: date1.getFullYear().toString(),
        doc2: date2.getFullYear().toString()
      });
    }

    // Compare author/chamber
    if (doc1.author === doc2.author && doc1.author) {
      similarities.push(`Same author: ${doc1.author}`);
      matchingFields++;
    } else {
      differences.push({
        field: 'Author',
        doc1: doc1.author || 'Not specified',
        doc2: doc2.author || 'Not specified'
      });
    }

    // Text similarity (basic keyword overlap)
    const text1 = `${doc1.title} ${doc1.summary}`.toLowerCase();
    const text2 = `${doc2.title} ${doc2.summary}`.toLowerCase();
    const words1 = new Set(text1.split(/\s+/).filter(word => word.length > 3));
    const words2 = new Set(text2.split(/\s+/).filter(word => word.length > 3));
    
    const commonWords = [...words1].filter(word => words2.has(word));
    const totalWords = new Set([...words1, ...words2]).size;
    const textSimilarity = commonWords.length / totalWords;
    
    if (textSimilarity > 0.3) {
      similarities.push(`High text similarity (${Math.round(textSimilarity * 100)}%)`);
      matchingFields += textSimilarity;
    }

    const score = Math.round((matchingFields / totalFields) * 100);

    return { similarities, differences, score };
  }, [doc1, doc2]);

  // Format date for display
  const formatDate = (date: Date | string) => {
    const d = typeof date === 'string' ? new Date(date) : date;
    return d.toLocaleDateString('pt-BR');
  };

  // Generate export data
  const exportComparison = () => {
    if (!doc1 || !doc2 || !comparisonData) return;

    const exportData = {
      comparison_date: new Date().toISOString(),
      documents: {
        document_1: {
          id: doc1.id,
          title: doc1.title,
          type: doc1.type,
          date: doc1.date,
          state: doc1.state,
          municipality: doc1.municipality,
          keywords: doc1.keywords,
          author: doc1.author
        },
        document_2: {
          id: doc2.id,
          title: doc2.title,
          type: doc2.type,
          date: doc2.date,
          state: doc2.state,
          municipality: doc2.municipality,
          keywords: doc2.keywords,
          author: doc2.author
        }
      },
      analysis: {
        similarity_score: comparisonData.score,
        similarities: comparisonData.similarities,
        differences: comparisonData.differences
      }
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `comparison-${doc1.id}-${doc2.id}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!doc1 || !doc2) {
    return (
      <div className="document-comparison">
        <div className="comparison-header">
          <h3>Document Comparison</h3>
          <button className="close-button" onClick={onClose}>×</button>
        </div>
        
        <div className="document-selector">
          <h4>Select Documents to Compare</h4>
          <div className="selector-grid">
            <div className="selector-column">
              <label>First Document:</label>
              <select 
                value={selectedDoc1} 
                onChange={(e) => setSelectedDoc1(e.target.value)}
              >
                <option value="">Select document...</option>
                {documents.map(doc => (
                  <option key={doc.id} value={doc.id}>
                    {doc.title.substring(0, 50)}...
                  </option>
                ))}
              </select>
            </div>
            
            <div className="selector-column">
              <label>Second Document:</label>
              <select 
                value={selectedDoc2} 
                onChange={(e) => setSelectedDoc2(e.target.value)}
              >
                <option value="">Select document...</option>
                {documents.filter(doc => doc.id !== selectedDoc1).map(doc => (
                  <option key={doc.id} value={doc.id}>
                    {doc.title.substring(0, 50)}...
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="document-comparison">
      <div className="comparison-header">
        <h3>Document Comparison</h3>
        <div className="header-actions">
          <div className="view-toggle">
            <button
              className={comparisonMode === 'side-by-side' ? 'active' : ''}
              onClick={() => setComparisonMode('side-by-side')}
            >
              Side by Side
            </button>
            <button
              className={comparisonMode === 'unified' ? 'active' : ''}
              onClick={() => setComparisonMode('unified')}
            >
              Unified View
            </button>
          </div>
          <button className="export-button" onClick={exportComparison}>
            📥 Export
          </button>
          <button className="close-button" onClick={onClose}>×</button>
        </div>
      </div>

      {/* Similarity Score */}
      {comparisonData && (
        <div className="similarity-score">
          <div className="score-circle">
            <span className="score-value">{comparisonData.score}%</span>
            <span className="score-label">Similarity</span>
          </div>
          <div className="score-details">
            <p>{comparisonData.similarities.length} similarities found</p>
            <p>{comparisonData.differences.length} differences noted</p>
          </div>
        </div>
      )}

      {/* Document Selector (minimized when comparing) */}
      <div className="document-selector minimized">
        <select 
          value={selectedDoc1} 
          onChange={(e) => setSelectedDoc1(e.target.value)}
        >
          {documents.map(doc => (
            <option key={doc.id} value={doc.id}>
              {doc.title.substring(0, 30)}...
            </option>
          ))}
        </select>
        <span>vs</span>
        <select 
          value={selectedDoc2} 
          onChange={(e) => setSelectedDoc2(e.target.value)}
        >
          {documents.filter(doc => doc.id !== selectedDoc1).map(doc => (
            <option key={doc.id} value={doc.id}>
              {doc.title.substring(0, 30)}...
            </option>
          ))}
        </select>
      </div>

      {/* Comparison Content */}
      <div className={`comparison-content ${comparisonMode}`}>
        {comparisonMode === 'side-by-side' ? (
          <div className="side-by-side-view">
            <div className="document-column">
              <h4>Document A</h4>
              <div className="document-details">
                <h5>{doc1.title}</h5>
                <div className="detail-item">
                  <span className="label">Type:</span>
                  <span className="value">{doc1.type}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Date:</span>
                  <span className="value">{formatDate(doc1.date)}</span>
                </div>
                <div className="detail-item">
                  <span className="label">State:</span>
                  <span className="value">{doc1.state || 'Not specified'}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Municipality:</span>
                  <span className="value">{doc1.municipality || 'Not specified'}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Author:</span>
                  <span className="value">{doc1.author || 'Not specified'}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Keywords:</span>
                  <span className="value">{doc1.keywords.join(', ')}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Summary:</span>
                  <span className="value">{doc1.summary}</span>
                </div>
              </div>
            </div>

            <div className="document-column">
              <h4>Document B</h4>
              <div className="document-details">
                <h5>{doc2.title}</h5>
                <div className="detail-item">
                  <span className="label">Type:</span>
                  <span className="value">{doc2.type}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Date:</span>
                  <span className="value">{formatDate(doc2.date)}</span>
                </div>
                <div className="detail-item">
                  <span className="label">State:</span>
                  <span className="value">{doc2.state || 'Not specified'}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Municipality:</span>
                  <span className="value">{doc2.municipality || 'Not specified'}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Author:</span>
                  <span className="value">{doc2.author || 'Not specified'}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Keywords:</span>
                  <span className="value">{doc2.keywords.join(', ')}</span>
                </div>
                <div className="detail-item">
                  <span className="label">Summary:</span>
                  <span className="value">{doc2.summary}</span>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="unified-view">
            {/* Similarities Section */}
            <div className="analysis-section">
              <h4>✅ Similarities ({comparisonData?.similarities.length || 0})</h4>
              <ul className="similarity-list">
                {comparisonData?.similarities.map((similarity, index) => (
                  <li key={index}>{similarity}</li>
                )) || []}
              </ul>
            </div>

            {/* Differences Section */}
            <div className="analysis-section">
              <h4>❌ Differences ({comparisonData?.differences.length || 0})</h4>
              <div className="differences-table">
                {comparisonData?.differences.map((diff, index) => (
                  <div key={index} className="difference-row">
                    <div className="field-name">{diff.field}</div>
                    <div className="field-comparison">
                      <div className="field-value doc-a">
                        <span className="doc-label">A:</span>
                        {diff.doc1}
                      </div>
                      <div className="field-value doc-b">
                        <span className="doc-label">B:</span>
                        {diff.doc2}
                      </div>
                    </div>
                  </div>
                )) || []}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};