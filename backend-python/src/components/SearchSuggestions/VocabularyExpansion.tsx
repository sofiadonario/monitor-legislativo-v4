/**
 * VocabularyExpansion Component
 * Display vocabulary-based query expansion with term relationships
 */
import React from 'react';
import { QueryExpansion } from '../../types';

interface VocabularyExpansionProps {
  expansion: QueryExpansion;
  onTermSelect: (term: string) => void;
  onClose: () => void;
}

export const VocabularyExpansion: React.FC<VocabularyExpansionProps> = ({
  expansion,
  onTermSelect,
  onClose
}) => {
  const renderTermGroup = (title: string, terms: string[], color: string) => {
    if (terms.length === 0) return null;

    return (
      <div className="vocabulary-expansion__group">
        <h4 className="vocabulary-expansion__group-title" style={{ color }}>
          {title} ({terms.length})
        </h4>
        <div className="vocabulary-expansion__terms">
          {terms.map((term, index) => (
            <button
              key={index}
              onClick={() => onTermSelect(term)}
              className="vocabulary-expansion__term"
              style={{ borderColor: color }}
            >
              {term}
            </button>
          ))}
        </div>
      </div>
    );
  };

  const hasExpansions = expansion.narrower.length > 0 || 
                      expansion.broader.length > 0 || 
                      expansion.related.length > 0 || 
                      expansion.synonyms.length > 0;

  if (!hasExpansions) return null;

  return (
    <div className="vocabulary-expansion">
      <div className="vocabulary-expansion__header">
        <h3>Vocabulary Expansion</h3>
        <p>Discover related terms to expand your search</p>
        <button 
          onClick={onClose}
          className="vocabulary-expansion__close"
        >
          ×
        </button>
      </div>

      <div className="vocabulary-expansion__content">
        {expansion.original.length > 0 && (
          <div className="vocabulary-expansion__original">
            <h4>Original Terms</h4>
            <div className="vocabulary-expansion__original-terms">
              {expansion.original.map((term, index) => (
                <span key={index} className="vocabulary-expansion__original-term">
                  {term}
                </span>
              ))}
            </div>
          </div>
        )}

        <div className="vocabulary-expansion__groups">
          {renderTermGroup(
            'More Specific', 
            expansion.narrower, 
            'var(--green-600, #16a34a)'
          )}
          
          {renderTermGroup(
            'More General', 
            expansion.broader, 
            'var(--blue-600, #2563eb)'
          )}
          
          {renderTermGroup(
            'Related Terms', 
            expansion.related, 
            'var(--purple-600, #9333ea)'
          )}
          
          {renderTermGroup(
            'Synonyms', 
            expansion.synonyms, 
            'var(--orange-600, #ea580c)'
          )}
        </div>

        <div className="vocabulary-expansion__actions">
          <button
            onClick={() => {
              const allTerms = [
                ...expansion.original,
                ...expansion.narrower,
                ...expansion.broader,
                ...expansion.related,
                ...expansion.synonyms
              ];
              const expandedQuery = allTerms.slice(0, 10).join(' OR ');
              onTermSelect(expandedQuery);
            }}
            className="vocabulary-expansion__expand-all"
          >
            Use All Terms
          </button>
        </div>
      </div>
    </div>
  );
};