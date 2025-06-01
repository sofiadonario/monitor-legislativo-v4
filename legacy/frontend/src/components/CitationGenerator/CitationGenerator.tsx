/**
 * CitationGenerator Component
 * Generate academic citations in multiple formats for legislative documents
 */
import React, { useState, useEffect } from 'react';
import { Citation, CitationFormat } from '../../types';
import { documentAnalysisService } from '../../services/documentAnalysisService';
import './CitationGenerator.css';

interface CitationGeneratorProps {
  urn: string;
  urns?: string[];
  defaultFormat?: CitationFormat;
  showAllFormats?: boolean;
  onCitationGenerated?: (citation: Citation) => void;
}

export const CitationGenerator: React.FC<CitationGeneratorProps> = ({
  urn,
  urns,
  defaultFormat = 'ABNT',
  showAllFormats = true,
  onCitationGenerated
}) => {
  const [citations, setCitations] = useState<Record<CitationFormat, Citation | null>>({
    ABNT: null,
    APA: null,
    Chicago: null,
    Vancouver: null,
    MLA: null,
    IEEE: null
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedFormat, setSelectedFormat] = useState<CitationFormat>(defaultFormat);
  const [availableFormats, setAvailableFormats] = useState<CitationFormat[]>([]);
  const [copyStatus, setCopyStatus] = useState<Record<CitationFormat, boolean>>({
    ABNT: false,
    APA: false,
    Chicago: false,
    Vancouver: false,
    MLA: false,
    IEEE: false
  });
  const [batchMode, setBatchMode] = useState(false);

  useEffect(() => {
    loadAvailableFormats();
  }, []);

  useEffect(() => {
    if (urn || (urns && urns.length > 0)) {
      if (showAllFormats) {
        generateAllCitations();
      } else {
        generateSingleCitation(selectedFormat);
      }
    }
  }, [urn, urns, selectedFormat, showAllFormats]);

  const loadAvailableFormats = async () => {
    try {
      const formats = await documentAnalysisService.getCitationStyles();
      setAvailableFormats(formats);
    } catch (error) {
      console.warn('Failed to load citation styles, using defaults');
      setAvailableFormats(['ABNT', 'APA', 'Chicago', 'Vancouver', 'MLA', 'IEEE']);
    }
  };

  const generateAllCitations = async () => {
    if (!urn && (!urns || urns.length === 0)) return;

    setLoading(true);
    setError(null);

    try {
      const targetUrns = urns && urns.length > 0 ? urns : [urn];
      const isBatch = targetUrns.length > 1;
      setBatchMode(isBatch);

      const citationPromises = availableFormats.map(async format => {
        try {
          if (isBatch) {
            const batchCitations = await documentAnalysisService.generateBatchCitations(targetUrns, format);
            // For display, we'll show the first citation as primary
            return { format, citation: batchCitations[0] || null };
          } else {
            const citation = await documentAnalysisService.generateCitation(targetUrns[0], format);
            return { format, citation };
          }
        } catch (error) {
          console.warn(`Failed to generate ${format} citation:`, error);
          return { format, citation: null };
        }
      });

      const results = await Promise.all(citationPromises);
      const newCitations = { ...citations };
      
      results.forEach(({ format, citation }) => {
        newCitations[format] = citation;
      });

      setCitations(newCitations);

      // Notify parent component
      if (onCitationGenerated && newCitations[selectedFormat]) {
        onCitationGenerated(newCitations[selectedFormat]!);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate citations');
    } finally {
      setLoading(false);
    }
  };

  const generateSingleCitation = async (format: CitationFormat) => {
    if (!urn && (!urns || urns.length === 0)) return;

    setLoading(true);
    setError(null);

    try {
      const targetUrns = urns && urns.length > 0 ? urns : [urn];
      const isBatch = targetUrns.length > 1;
      setBatchMode(isBatch);

      let citation: Citation | null = null;

      if (isBatch) {
        const batchCitations = await documentAnalysisService.generateBatchCitations(targetUrns, format);
        citation = batchCitations[0] || null;
      } else {
        citation = await documentAnalysisService.generateCitation(targetUrns[0], format);
      }

      setCitations(prev => ({ ...prev, [format]: citation }));

      if (onCitationGenerated && citation) {
        onCitationGenerated(citation);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate citation');
    } finally {
      setLoading(false);
    }
  };

  const handleFormatChange = (format: CitationFormat) => {
    setSelectedFormat(format);
    if (!showAllFormats && !citations[format]) {
      generateSingleCitation(format);
    }
  };

  const copyToClipboard = async (format: CitationFormat, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyStatus(prev => ({ ...prev, [format]: true }));
      setTimeout(() => {
        setCopyStatus(prev => ({ ...prev, [format]: false }));
      }, 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const downloadCitation = (format: CitationFormat, citation: Citation) => {
    let content = citation.text;
    let filename = `citation.txt`;
    let mimeType = 'text/plain';

    // Handle special formats
    if (citation.bibtex && (format === 'IEEE' || format === 'Chicago')) {
      content = citation.bibtex;
      filename = `citation.bib`;
      mimeType = 'application/x-bibtex';
    } else if (citation.ris && format === 'APA') {
      content = citation.ris;
      filename = `citation.ris`;
      mimeType = 'application/x-research-info-systems';
    } else if (citation.endnote && format === 'MLA') {
      content = citation.endnote;
      filename = `citation.enw`;
      mimeType = 'application/x-endnote-refer';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const exportAllCitations = () => {
    const allCitations = availableFormats
      .map(format => {
        const citation = citations[format];
        if (!citation) return null;
        return `\n=== ${format} ===\n${citation.text}\n`;
      })
      .filter(Boolean)
      .join('\n');

    if (allCitations) {
      const blob = new Blob([allCitations], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'all-citations.txt';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
  };

  const getFormatDescription = (format: CitationFormat) => {
    const descriptions = {
      ABNT: 'Associação Brasileira de Normas Técnicas - Brazilian standard for academic citations',
      APA: 'American Psychological Association - Widely used in social sciences',
      Chicago: 'Chicago Manual of Style - Common in history and literature',
      Vancouver: 'Vancouver System - Standard for medical and scientific publications',
      MLA: 'Modern Language Association - Used in humanities and language studies',
      IEEE: 'Institute of Electrical and Electronics Engineers - Standard for technical publications'
    };
    return descriptions[format];
  };

  if (loading) {
    return (
      <div className="citation-generator__loading">
        <div className="citation-generator__spinner"></div>
        <p>Generating citations...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="citation-generator__error">
        <h3>Error Generating Citations</h3>
        <p>{error}</p>
        <button onClick={() => showAllFormats ? generateAllCitations() : generateSingleCitation(selectedFormat)}>
          Try Again
        </button>
      </div>
    );
  }

  return (
    <div className="citation-generator">
      <div className="citation-generator__header">
        <h3>Citation Generator</h3>
        {batchMode && (
          <p className="citation-generator__batch-notice">
            Generating citations for {urns?.length || 1} documents
          </p>
        )}
      </div>

      <div className="citation-generator__controls">
        {!showAllFormats && (
          <div className="citation-generator__format-selector">
            <label htmlFor="citation-format">Citation Format:</label>
            <select
              id="citation-format"
              value={selectedFormat}
              onChange={(e) => handleFormatChange(e.target.value as CitationFormat)}
              className="citation-generator__select"
            >
              {availableFormats.map(format => (
                <option key={format} value={format}>
                  {format}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="citation-generator__actions">
          <button
            onClick={() => showAllFormats ? generateAllCitations() : generateSingleCitation(selectedFormat)}
            className="citation-generator__refresh-btn"
            disabled={loading}
          >
            🔄 Refresh
          </button>
          {showAllFormats && (
            <button
              onClick={exportAllCitations}
              className="citation-generator__export-btn"
              disabled={Object.values(citations).every(c => !c)}
            >
              📥 Export All
            </button>
          )}
        </div>
      </div>

      <div className="citation-generator__content">
        {showAllFormats ? (
          <div className="citation-generator__all-formats">
            {availableFormats.map(format => {
              const citation = citations[format];
              return (
                <div key={format} className="citation-generator__format-section">
                  <div className="citation-generator__format-header">
                    <h4 className="citation-generator__format-title">
                      {format}
                      <span className="citation-generator__format-description">
                        {getFormatDescription(format)}
                      </span>
                    </h4>
                    {citation && (
                      <div className="citation-generator__format-actions">
                        <button
                          onClick={() => copyToClipboard(format, citation.text)}
                          className={`citation-generator__copy-btn ${copyStatus[format] ? 'copied' : ''}`}
                          title="Copy to clipboard"
                        >
                          {copyStatus[format] ? '✓' : '📋'}
                        </button>
                        <button
                          onClick={() => downloadCitation(format, citation)}
                          className="citation-generator__download-btn"
                          title="Download citation"
                        >
                          📥
                        </button>
                      </div>
                    )}
                  </div>
                  
                  <div className="citation-generator__citation-container">
                    {citation ? (
                      <>
                        <div className="citation-generator__citation-text">
                          {citation.text}
                        </div>
                        
                        {citation.metadata && (
                          <div className="citation-generator__metadata">
                            <h5>Citation Metadata:</h5>
                            <div className="citation-generator__metadata-grid">
                              {citation.metadata.authors.length > 0 && (
                                <div className="citation-generator__metadata-item">
                                  <strong>Authors:</strong> {citation.metadata.authors.join(', ')}
                                </div>
                              )}
                              <div className="citation-generator__metadata-item">
                                <strong>Title:</strong> {citation.metadata.title}
                              </div>
                              <div className="citation-generator__metadata-item">
                                <strong>Publisher:</strong> {citation.metadata.publisher}
                              </div>
                              <div className="citation-generator__metadata-item">
                                <strong>Publication Date:</strong> {citation.metadata.publicationDate}
                              </div>
                              <div className="citation-generator__metadata-item">
                                <strong>Access Date:</strong> {new Date(citation.metadata.accessDate).toLocaleDateString('pt-BR')}
                              </div>
                              {citation.metadata.doi && (
                                <div className="citation-generator__metadata-item">
                                  <strong>DOI:</strong> {citation.metadata.doi}
                                </div>
                              )}
                              {citation.metadata.url && (
                                <div className="citation-generator__metadata-item">
                                  <strong>URL:</strong> 
                                  <a href={citation.metadata.url} target="_blank" rel="noopener noreferrer">
                                    {citation.metadata.url}
                                  </a>
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {(citation.bibtex || citation.ris || citation.endnote) && (
                          <div className="citation-generator__additional-formats">
                            <h5>Additional Export Formats:</h5>
                            <div className="citation-generator__export-formats">
                              {citation.bibtex && (
                                <details className="citation-generator__export-detail">
                                  <summary>BibTeX</summary>
                                  <pre className="citation-generator__export-content">
                                    {citation.bibtex}
                                  </pre>
                                  <button
                                    onClick={() => copyToClipboard(format, citation.bibtex!)}
                                    className="citation-generator__copy-small-btn"
                                  >
                                    Copy BibTeX
                                  </button>
                                </details>
                              )}
                              {citation.ris && (
                                <details className="citation-generator__export-detail">
                                  <summary>RIS</summary>
                                  <pre className="citation-generator__export-content">
                                    {citation.ris}
                                  </pre>
                                  <button
                                    onClick={() => copyToClipboard(format, citation.ris!)}
                                    className="citation-generator__copy-small-btn"
                                  >
                                    Copy RIS
                                  </button>
                                </details>
                              )}
                              {citation.endnote && (
                                <details className="citation-generator__export-detail">
                                  <summary>EndNote</summary>
                                  <pre className="citation-generator__export-content">
                                    {citation.endnote}
                                  </pre>
                                  <button
                                    onClick={() => copyToClipboard(format, citation.endnote!)}
                                    className="citation-generator__copy-small-btn"
                                  >
                                    Copy EndNote
                                  </button>
                                </details>
                              )}
                            </div>
                          </div>
                        )}
                      </>
                    ) : (
                      <div className="citation-generator__no-citation">
                        <p>Citation not available for this format</p>
                        <button
                          onClick={() => generateSingleCitation(format)}
                          className="citation-generator__retry-btn"
                        >
                          Retry Generation
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="citation-generator__single-format">
            {citations[selectedFormat] && (
              <div className="citation-generator__single-citation">
                <div className="citation-generator__single-header">
                  <h4>{selectedFormat} Citation</h4>
                  <div className="citation-generator__single-actions">
                    <button
                      onClick={() => copyToClipboard(selectedFormat, citations[selectedFormat]!.text)}
                      className={`citation-generator__copy-btn ${copyStatus[selectedFormat] ? 'copied' : ''}`}
                    >
                      {copyStatus[selectedFormat] ? '✓ Copied' : '📋 Copy'}
                    </button>
                    <button
                      onClick={() => downloadCitation(selectedFormat, citations[selectedFormat]!)}
                      className="citation-generator__download-btn"
                    >
                      📥 Download
                    </button>
                  </div>
                </div>
                
                <div className="citation-generator__citation-text citation-generator__citation-text--large">
                  {citations[selectedFormat]!.text}
                </div>
                
                <div className="citation-generator__format-info">
                  <p>{getFormatDescription(selectedFormat)}</p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};