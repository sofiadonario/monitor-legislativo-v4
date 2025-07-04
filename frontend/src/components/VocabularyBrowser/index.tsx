/**
 * VocabularyBrowser Component
 * Interactive SKOS vocabulary browser with concept hierarchy navigation
 */
import React, { useState, useEffect, useCallback } from 'react';
import { vocabularyService } from '../../services/vocabularyService';
import { ConceptSchemeOverview, Concept, ConceptHierarchy } from '../../types';
import { LoadingSpinner } from '../LoadingSpinner';
import { VocabularyTree } from './VocabularyTree';
import { ConceptCard } from './ConceptCard';
import { VocabularySearch } from './VocabularySearch';
import './VocabularyBrowser.css';

interface VocabularyBrowserProps {
  onConceptSelect?: (concept: Concept) => void;
  selectedConceptUri?: string;
  className?: string;
}

export const VocabularyBrowser: React.FC<VocabularyBrowserProps> = ({
  onConceptSelect,
  selectedConceptUri,
  className = ''
}) => {
  const [schemes, setSchemes] = useState<ConceptSchemeOverview[]>([]);
  const [selectedScheme, setSelectedScheme] = useState<string>('');
  const [selectedConcept, setSelectedConcept] = useState<ConceptHierarchy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Load available concept schemes on mount
  useEffect(() => {
    const loadSchemes = async () => {
      try {
        setLoading(true);
        setError(null);
        const schemesData = await vocabularyService.getAllConceptSchemes();
        setSchemes(schemesData);
        
        // Auto-select first scheme if available
        if (schemesData.length > 0) {
          setSelectedScheme(schemesData[0].scheme);
        }
      } catch (err) {
        setError(`Failed to load vocabulary schemes: ${err}`);
      } finally {
        setLoading(false);
      }
    };

    loadSchemes();
  }, []);

  // Load concept hierarchy when a concept URI is provided
  useEffect(() => {
    if (selectedConceptUri) {
      loadConceptHierarchy(selectedConceptUri);
    }
  }, [selectedConceptUri]);

  const loadConceptHierarchy = useCallback(async (conceptUri: string) => {
    try {
      setLoading(true);
      setError(null);
      const hierarchy = await vocabularyService.getConceptHierarchy(conceptUri);
      setSelectedConcept(hierarchy);
      
      if (hierarchy && onConceptSelect) {
        onConceptSelect(hierarchy.concept);
      }
    } catch (err) {
      setError(`Failed to load concept hierarchy: ${err}`);
    } finally {
      setLoading(false);
    }
  }, [onConceptSelect]);

  const handleConceptSelect = (concept: Concept) => {
    loadConceptHierarchy(concept.uri);
  };

  const handleSchemeChange = (scheme: string) => {
    setSelectedScheme(scheme);
    setSelectedConcept(null);
    setSearchQuery('');
  };

  const handleSearchResults = (results: any[]) => {
    // Clear current selection when showing search results
    setSelectedConcept(null);
  };

  if (loading && schemes.length === 0) {
    return (
      <div className={`vocabulary-browser ${className}`}>
        <div className="vocabulary-browser__loading">
          <LoadingSpinner size="medium" />
          <p>Loading vocabulary schemes...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`vocabulary-browser ${className}`}>
        <div className="vocabulary-browser__error">
          <h3>Vocabulary Loading Error</h3>
          <p>{error}</p>
          <button 
            onClick={() => window.location.reload()}
            className="vocabulary-browser__retry-btn"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`vocabulary-browser ${className}`}>
      <div className="vocabulary-browser__header">
        <h2>Vocabulary Browser</h2>
        <p>Explore controlled vocabularies and concept relationships</p>
      </div>

      <div className="vocabulary-browser__controls">
        {/* Scheme Selector */}
        <div className="vocabulary-browser__scheme-selector">
          <label htmlFor="scheme-select">Concept Scheme:</label>
          <select
            id="scheme-select"
            value={selectedScheme}
            onChange={(e) => handleSchemeChange(e.target.value)}
            className="vocabulary-browser__scheme-select"
          >
            <option value="">Select a scheme...</option>
            {schemes.map((scheme) => (
              <option key={scheme.scheme} value={scheme.scheme}>
                {scheme.scheme} ({scheme.totalConcepts} concepts)
              </option>
            ))}
          </select>
        </div>

        {/* Vocabulary Search */}
        {selectedScheme && (
          <VocabularySearch
            conceptScheme={selectedScheme}
            onConceptSelect={handleConceptSelect}
            onSearchResults={handleSearchResults}
            searchQuery={searchQuery}
            onSearchQueryChange={setSearchQuery}
          />
        )}
      </div>

      {selectedScheme && (
        <div className="vocabulary-browser__content">
          <div className="vocabulary-browser__left-panel">
            {/* Tree View */}
            <div className="vocabulary-browser__tree-section">
              <h3>Concept Hierarchy</h3>
              {searchQuery ? (
                <div className="vocabulary-browser__search-info">
                  <p>Search results for "{searchQuery}"</p>
                  <button 
                    onClick={() => setSearchQuery('')}
                    className="vocabulary-browser__clear-search"
                  >
                    Show full hierarchy
                  </button>
                </div>
              ) : (
                <VocabularyTree
                  conceptScheme={selectedScheme}
                  selectedConceptUri={selectedConcept?.concept.uri}
                  onConceptSelect={handleConceptSelect}
                />
              )}
            </div>
          </div>

          <div className="vocabulary-browser__right-panel">
            {/* Concept Details */}
            {selectedConcept ? (
              <ConceptCard 
                hierarchy={selectedConcept}
                onConceptSelect={handleConceptSelect}
              />
            ) : (
              <div className="vocabulary-browser__no-selection">
                <h3>No Concept Selected</h3>
                <p>Select a concept from the tree or search results to view details.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {!selectedScheme && (
        <div className="vocabulary-browser__no-scheme">
          <h3>Select a Concept Scheme</h3>
          <p>Choose a vocabulary scheme to begin exploring concepts.</p>
          {schemes.length > 0 && (
            <div className="vocabulary-browser__scheme-list">
              {schemes.map((scheme) => (
                <div key={scheme.scheme} className="vocabulary-browser__scheme-card">
                  <h4>{scheme.scheme}</h4>
                  <p>{scheme.totalConcepts} concepts, {scheme.maxDepth} levels deep</p>
                  <button 
                    onClick={() => handleSchemeChange(scheme.scheme)}
                    className="vocabulary-browser__select-scheme-btn"
                  >
                    Explore
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};