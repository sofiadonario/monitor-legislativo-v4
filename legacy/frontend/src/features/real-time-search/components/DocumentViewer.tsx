/**
 * Document Viewer Component
 * Displays full document content with government source verification
 */

import React, { useState, useEffect } from 'react';
import { LexMLDocument, DocumentContentResponse, LexMLSearchResponse } from '../types/lexml-api.types';
import { lexmlAPI } from '../services/LexMLAPIService';

interface DocumentViewerProps {
  document: LexMLDocument;
  onClose: () => void;
  className?: string;
}

interface CitationFormat {
  id: string;
  name: string;
  format: (doc: LexMLDocument) => string;
}

const citationFormats: CitationFormat[] = [
  {
    id: 'abnt',
    name: 'ABNT',
    format: (doc) => {
      const date = new Date(doc.metadata.date);
      const year = date.getFullYear();
      const formattedDate = date.toLocaleDateString('pt-BR');
      
      if (doc.metadata.tipoDocumento === 'Lei') {
        return `${doc.metadata.localidade.toUpperCase()}. Lei nº [número], de ${formattedDate}. ${doc.metadata.title}. Disponível em: ${doc.metadata.identifier}. Acesso em: ${new Date().toLocaleDateString('pt-BR')}.`;
      }
      
      return `${doc.metadata.localidade.toUpperCase()}. ${doc.metadata.tipoDocumento} [número], de ${formattedDate}. ${doc.metadata.title}. Disponível em: ${doc.metadata.identifier}. Acesso em: ${new Date().toLocaleDateString('pt-BR')}.`;
    }
  },
  {
    id: 'apa',
    name: 'APA',
    format: (doc) => {
      const year = new Date(doc.metadata.date).getFullYear();
      return `${doc.metadata.autoridade} (${year}). ${doc.metadata.title}. Retrieved from ${doc.metadata.identifier}`;
    }
  },
  {
    id: 'chicago',
    name: 'Chicago',
    format: (doc) => {
      const date = new Date(doc.metadata.date);
      const formattedDate = date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
      });
      return `"${doc.metadata.title}," ${doc.metadata.tipoDocumento}, ${formattedDate}, ${doc.metadata.identifier}.`;
    }
  }
];

export const DocumentViewer: React.FC<DocumentViewerProps> = ({
  document,
  onClose,
  className = ''
}) => {
  const [content, setContent] = useState<DocumentContentResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCitation, setSelectedCitation] = useState<string>('abnt');
  const [showCitationCopied, setShowCitationCopied] = useState(false);
  const [crossReferences, setCrossReferences] = useState<any>(null);
  const [relatedDocuments, setRelatedDocuments] = useState<LexMLSearchResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'content' | 'references' | 'related'>('content');

  // Load document content, cross-references, and related documents
  useEffect(() => {
    const loadDocumentData = async () => {
      setLoading(true);
      setError(null);
      
      try {
        // Load main content
        const contentResult = await lexmlAPI.getDocumentContent(document.metadata.urn);
        setContent(contentResult);
        
        // Load cross-references (don't block main content)
        lexmlAPI.findCrossReferences(document.metadata.urn)
          .then(refs => setCrossReferences(refs))
          .catch(err => console.warn('Cross-references failed:', err));
        
        // Load related documents (don't block main content)
        lexmlAPI.getRelatedDocuments(document.metadata.urn, 10)
          .then(related => setRelatedDocuments(related))
          .catch(err => console.warn('Related documents failed:', err));
          
      } catch (err) {
        console.error('Error loading document content:', err);
        setError('Failed to load document content');
      } finally {
        setLoading(false);
      }
    };

    loadDocumentData();
  }, [document.metadata.urn]);

  // Copy citation to clipboard
  const copyCitation = async (format: CitationFormat) => {
    const citation = format.format(document);
    
    try {
      await navigator.clipboard.writeText(citation);
      setShowCitationCopied(true);
      setTimeout(() => setShowCitationCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy citation:', err);
    }
  };

  // Format date for display
  const formatDate = (dateString: string): string => {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('pt-BR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    } catch {
      return dateString;
    }
  };

  // Get document type color
  const getDocumentTypeColor = (type: string): string => {
    const colors: Record<string, string> = {
      'Lei': 'bg-blue-100 text-blue-800 border-blue-200',
      'Decreto': 'bg-green-100 text-green-800 border-green-200',
      'Portaria': 'bg-yellow-100 text-yellow-800 border-yellow-200',
      'Resolução': 'bg-purple-100 text-purple-800 border-purple-200',
      'Medida Provisória': 'bg-red-100 text-red-800 border-red-200'
    };
    return colors[type] || 'bg-gray-100 text-gray-800 border-gray-200';
  };

  // Verify government source
  const isGovernmentSource = (url: string): boolean => {
    const govDomains = [
      'planalto.gov.br',
      'camara.leg.br',
      'senado.leg.br',
      'in.gov.br',
      'lexml.gov.br',
      '.gov.br'
    ];
    return govDomains.some(domain => url.includes(domain));
  };

  return (
    <div className={`fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50 ${className}`}>
      <div className="bg-white rounded-lg max-w-5xl w-full max-h-[95vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4">
          <div className="flex items-start justify-between">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-2">
                <span className={`px-3 py-1 text-sm font-medium rounded-full border ${getDocumentTypeColor(document.metadata.tipoDocumento)}`}>
                  {document.metadata.tipoDocumento}
                </span>
                <span className="text-sm text-gray-600">
                  📍 {document.metadata.localidade} | 🏛️ {document.metadata.autoridade}
                </span>
                {isGovernmentSource(document.metadata.identifier) && (
                  <span className="bg-green-100 text-green-800 px-2 py-1 text-xs rounded-full border border-green-200">
                    ✅ Official Government Source
                  </span>
                )}
              </div>
              <h2 className="text-xl font-semibold text-gray-900 mb-1">
                {document.metadata.title}
              </h2>
              <p className="text-sm text-gray-600">
                📅 {formatDate(document.metadata.date)} | 🔗 {document.metadata.urn}
              </p>
            </div>
            <button
              onClick={onClose}
              className="ml-4 text-gray-400 hover:text-gray-600 transition-colors"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          {/* Tab Navigation */}
          <div className="border-b border-gray-200 bg-gray-50 px-6 py-2">
            <div className="flex gap-4">
              <button
                onClick={() => setActiveTab('content')}
                className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                  activeTab === 'content' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }`}
              >
                📄 Content
              </button>
              <button
                onClick={() => setActiveTab('references')}
                className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                  activeTab === 'references' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }`}
              >
                🔗 References {crossReferences?.references?.length ? `(${crossReferences.references.length})` : ''}
              </button>
              <button
                onClick={() => setActiveTab('related')}
                className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                  activeTab === 'related' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }`}
              >
                📚 Related {relatedDocuments?.documents?.length ? `(${relatedDocuments.documents.length})` : ''}
              </button>
            </div>
          </div>
          
          <div className="p-6 space-y-6">
            {activeTab === 'content' && (
              <>
                {/* Data Source Information */}
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <span className={`text-lg ${document.data_source === 'live-api' ? '🔴' : document.data_source === 'cached-api' ? '🟡' : '⚫'}`}></span>
                <span className="font-medium text-blue-900">
                  Data Source: {
                    document.data_source === 'live-api' ? 'Live LexML API' :
                    document.data_source === 'cached-api' ? 'Cached API Data' :
                    'CSV Fallback Dataset'
                  }
                </span>
              </div>
              <p className="text-sm text-blue-800">
                {document.data_source === 'csv-fallback' 
                  ? 'This document is from the transport legislation dataset. Full content may be limited.'
                  : 'This document data is sourced from LexML Brasil, the official Brazilian legal database.'
                }
              </p>
            </div>

            {/* Document Description */}
            {document.metadata.description && (
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-2">Description</h3>
                <p className="text-gray-700 leading-relaxed">
                  {document.metadata.description}
                </p>
              </div>
            )}

            {/* Subject Tags */}
            {document.metadata.subject.length > 0 && (
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-3">Subjects & Keywords</h3>
                <div className="flex flex-wrap gap-2">
                  {document.metadata.subject.map((subject, index) => (
                    <span
                      key={index}
                      className="bg-gray-100 text-gray-800 px-3 py-1 text-sm rounded-full border border-gray-200"
                    >
                      {subject}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Document Content */}
            <div>
              <h3 className="text-lg font-medium text-gray-900 mb-3">Document Content</h3>
              
              {loading && (
                <div className="flex items-center justify-center py-8">
                  <div className="flex items-center gap-3">
                    <div className="animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                    <span className="text-gray-600">Loading document content...</span>
                  </div>
                </div>
              )}

              {error && (
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <div className="flex items-center gap-2">
                    <span className="text-red-500">❌</span>
                    <span className="text-red-800 font-medium">Error Loading Content</span>
                  </div>
                  <p className="text-red-700 mt-1">{error}</p>
                </div>
              )}

              {content && !loading && !error && (
                <div className="space-y-4">
                  {content.full_text_url ? (
                    <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-green-500">🌐</span>
                        <span className="text-green-800 font-medium">Full Document Available</span>
                      </div>
                      <p className="text-green-700 mb-3">
                        The complete document text is available at the official government source.
                      </p>
                      <a
                        href={content.full_text_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="
                          inline-flex items-center gap-2 px-4 py-2 
                          bg-green-600 text-white rounded-lg 
                          hover:bg-green-700 transition-colors
                        "
                      >
                        📄 View Full Document
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                      </a>
                    </div>
                  ) : content.note ? (
                    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-yellow-500">ℹ️</span>
                        <span className="text-yellow-800 font-medium">Limited Content</span>
                      </div>
                      <p className="text-yellow-700">{content.note}</p>
                    </div>
                  ) : (
                    <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                      <p className="text-gray-600">
                        Document metadata loaded. Full text content retrieval capabilities 
                        are being enhanced. Please use the official source link below.
                      </p>
                    </div>
                  )}

                  {/* Document Metadata Details */}
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                    <h4 className="font-medium text-gray-900 mb-3">Document Metadata</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <strong>URN:</strong>
                        <code className="block mt-1 p-2 bg-white border rounded font-mono text-xs break-all">
                          {document.metadata.urn}
                        </code>
                      </div>
                      <div>
                        <strong>Data Source:</strong>
                        <span className="block mt-1 text-gray-600">
                          {content.data_source === 'api' ? 'Live LexML API' : 'Fallback Dataset'}
                        </span>
                      </div>
                      <div>
                        <strong>Retrieved:</strong>
                        <span className="block mt-1 text-gray-600">
                          {new Date(content.retrieved_at).toLocaleString('pt-BR')}
                        </span>
                      </div>
                      <div>
                        <strong>Cached:</strong>
                        <span className="block mt-1 text-gray-600">
                          {content.cached ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Citation Generator */}
            <div>
              <h3 className="text-lg font-medium text-gray-900 mb-3">Academic Citations</h3>
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-3">
                  <label className="text-sm font-medium text-gray-700">Format:</label>
                  <select
                    value={selectedCitation}
                    onChange={(e) => setSelectedCitation(e.target.value)}
                    className="text-sm border border-gray-300 rounded px-2 py-1"
                  >
                    {citationFormats.map(format => (
                      <option key={format.id} value={format.id}>
                        {format.name}
                      </option>
                    ))}
                  </select>
                </div>
                
                {citationFormats.map(format => (
                  selectedCitation === format.id && (
                    <div key={format.id} className="space-y-2">
                      <div className="bg-white border border-gray-300 rounded p-3">
                        <code className="text-sm text-gray-800 break-words">
                          {format.format(document)}
                        </code>
                      </div>
                      <button
                        onClick={() => copyCitation(format)}
                        className="
                          px-3 py-1 text-sm bg-blue-600 text-white rounded
                          hover:bg-blue-700 transition-colors
                          flex items-center gap-1
                        "
                      >
                        📋 Copy Citation
                      </button>
                    </div>
                  )
                ))}
                
                {showCitationCopied && (
                  <div className="mt-2 text-sm text-green-600">
                    ✅ Citation copied to clipboard!
                  </div>
                )}
              </div>
            </div>
              </>
            )}

            {activeTab === 'references' && (
              <div className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900">Legal Cross-References</h3>
                
                {crossReferences === null ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="flex items-center gap-3">
                      <div className="animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                      <span className="text-gray-600">Analyzing document for cross-references...</span>
                    </div>
                  </div>
                ) : crossReferences.references.length === 0 ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-6 text-center">
                    <span className="text-gray-500 text-lg">📋</span>
                    <p className="text-gray-600 mt-2">No cross-references found in this document.</p>
                    <p className="text-sm text-gray-500 mt-1">
                      Cross-references include citations to other laws, decrees, articles, and legal provisions.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* References by Type */}
                    {['law', 'decree', 'article', 'paragraph'].map(refType => {
                      const refs = crossReferences.references.filter((ref: any) => ref.type === refType);
                      if (refs.length === 0) return null;
                      
                      return (
                        <div key={refType} className="bg-white border border-gray-200 rounded-lg p-4">
                          <h4 className="font-medium text-gray-900 mb-3 capitalize">
                            {refType === 'law' ? '⚖️ Laws' : 
                             refType === 'decree' ? '📜 Decrees' :
                             refType === 'article' ? '📄 Articles' : '📝 Paragraphs'} ({refs.length})
                          </h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {refs.map((ref: any, index: number) => (
                              <div key={index} className="bg-gray-50 border border-gray-200 rounded p-3">
                                <div className="font-mono text-sm text-blue-700">{ref.text}</div>
                                {ref.description && (
                                  <div className="text-xs text-gray-600 mt-1">{ref.description}</div>
                                )}
                                {ref.url && (
                                  <a
                                    href={ref.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs text-blue-600 hover:underline mt-1 inline-block"
                                  >
                                    View Document →
                                  </a>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'related' && (
              <div className="space-y-4">
                <h3 className="text-lg font-medium text-gray-900">Related Documents</h3>
                
                {relatedDocuments === null ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="flex items-center gap-3">
                      <div className="animate-spin h-6 w-6 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                      <span className="text-gray-600">Finding related documents...</span>
                    </div>
                  </div>
                ) : relatedDocuments.documents.length === 0 ? (
                  <div className="bg-gray-50 border border-gray-200 rounded-lg p-6 text-center">
                    <span className="text-gray-500 text-lg">📚</span>
                    <p className="text-gray-600 mt-2">No related documents found.</p>
                    <p className="text-sm text-gray-500 mt-1">
                      Related documents are found based on similar subjects, document types, and content.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <p className="text-sm text-gray-600">
                      Found {relatedDocuments.total_found} related documents (showing top {relatedDocuments.documents.length})
                    </p>
                    
                    {relatedDocuments.documents.map((relatedDoc, index) => (
                      <div key={index} className="bg-white border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors">
                        <div className="flex items-start justify-between">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-2">
                              <span className={`px-2 py-1 text-xs rounded-full ${
                                relatedDoc.metadata.tipoDocumento === 'Lei' ? 'bg-blue-100 text-blue-800' :
                                relatedDoc.metadata.tipoDocumento === 'Decreto' ? 'bg-green-100 text-green-800' :
                                'bg-gray-100 text-gray-800'
                              }`}>
                                {relatedDoc.metadata.tipoDocumento}
                              </span>
                              <span className="text-xs text-gray-500">
                                {relatedDoc.metadata.localidade} | {relatedDoc.metadata.autoridade}
                              </span>
                            </div>
                            
                            <h4 className="font-medium text-gray-900 mb-1 line-clamp-2">
                              {relatedDoc.metadata.title}
                            </h4>
                            
                            {relatedDoc.metadata.description && (
                              <p className="text-sm text-gray-600 line-clamp-2 mb-2">
                                {relatedDoc.metadata.description}
                              </p>
                            )}
                            
                            <div className="text-xs text-gray-500">
                              📅 {new Date(relatedDoc.metadata.date).toLocaleDateString('pt-BR')}
                            </div>
                          </div>
                          
                          <div className="ml-4 flex flex-col gap-1">
                            <button
                              onClick={() => window.open(relatedDoc.metadata.identifier, '_blank')}
                              className="text-xs text-blue-600 hover:text-blue-800"
                            >
                              View →
                            </button>
                          </div>
                        </div>
                        
                        {relatedDoc.metadata.subject.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {relatedDoc.metadata.subject.slice(0, 3).map((subject, subIndex) => (
                              <span
                                key={subIndex}
                                className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded"
                              >
                                {subject}
                              </span>
                            ))}
                            {relatedDoc.metadata.subject.length > 3 && (
                              <span className="px-2 py-1 text-xs text-gray-500">
                                +{relatedDoc.metadata.subject.length - 3} more
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="border-t border-gray-200 px-6 py-4 bg-gray-50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <a
                href={document.metadata.identifier}
                target="_blank"
                rel="noopener noreferrer"
                className="
                  px-4 py-2 bg-blue-600 text-white rounded-lg
                  hover:bg-blue-700 transition-colors
                  flex items-center gap-2
                "
              >
                🌐 Official Source
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
              </a>
              
              <button className="
                px-4 py-2 bg-gray-100 text-gray-700 rounded-lg
                hover:bg-gray-200 transition-colors
                flex items-center gap-2
              ">
                📄 Export PDF
              </button>
            </div>
            
            <button
              onClick={onClose}
              className="
                px-4 py-2 bg-gray-600 text-white rounded-lg
                hover:bg-gray-700 transition-colors
              "
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DocumentViewer;