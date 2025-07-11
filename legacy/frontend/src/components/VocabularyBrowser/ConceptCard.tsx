/**
 * ConceptCard Component
 * Displays detailed concept information and relationships
 */
import React from 'react';
import { ConceptHierarchy, Concept } from '../../types';

interface ConceptCardProps {
  hierarchy: ConceptHierarchy;
  onConceptSelect: (concept: Concept) => void;
}

export const ConceptCard: React.FC<ConceptCardProps> = ({
  hierarchy,
  onConceptSelect
}) => {
  const { concept, path, children, parent, siblings, depth, isRoot, isLeaf } = hierarchy;

  const renderConceptLink = (targetConcept: Concept, className: string = '') => (
    <button
      key={targetConcept.uri}
      className={`concept-card__link ${className}`}
      onClick={() => onConceptSelect(targetConcept)}
      title={targetConcept.definition.pt || targetConcept.definition.en || ''}
    >
      {targetConcept.prefLabel.pt || targetConcept.prefLabel.en || targetConcept.uri}
      {targetConcept.notation && (
        <span className="concept-card__notation">({targetConcept.notation})</span>
      )}
    </button>
  );

  const renderLabels = (labels: Record<string, string>, title: string) => {
    const entries = Object.entries(labels);
    if (entries.length === 0) return null;

    return (
      <div className="concept-card__labels">
        <h4>{title}</h4>
        {entries.map(([lang, label]) => (
          <div key={lang} className="concept-card__label">
            <span className="concept-card__lang">{lang}:</span>
            <span className="concept-card__text">{label}</span>
          </div>
        ))}
      </div>
    );
  };

  const renderAltLabels = (altLabels: Record<string, string[]>) => {
    const entries = Object.entries(altLabels);
    if (entries.length === 0) return null;

    return (
      <div className="concept-card__alt-labels">
        <h4>Alternative Labels</h4>
        {entries.map(([lang, labels]) => (
          <div key={lang} className="concept-card__alt-label-group">
            <span className="concept-card__lang">{lang}:</span>
            <div className="concept-card__alt-labels-list">
              {labels.map((label, index) => (
                <span key={index} className="concept-card__alt-label">
                  {label}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="concept-card">
      <div className="concept-card__header">
        <h3 className="concept-card__title">
          {concept.prefLabel.pt || concept.prefLabel.en || concept.uri}
        </h3>
        {concept.notation && (
          <span className="concept-card__main-notation">{concept.notation}</span>
        )}
        <div className="concept-card__meta">
          <span className="concept-card__scheme">{concept.conceptScheme}</span>
          <span className="concept-card__depth">Level: {depth}</span>
          {isRoot && <span className="concept-card__badge root">Root</span>}
          {isLeaf && <span className="concept-card__badge leaf">Leaf</span>}
        </div>
      </div>

      <div className="concept-card__content">
        {/* Preferred Labels */}
        {renderLabels(concept.prefLabel, 'Preferred Labels')}

        {/* Alternative Labels */}
        {renderAltLabels(concept.altLabels)}

        {/* Definitions */}
        {renderLabels(concept.definition, 'Definitions')}

        {/* Breadcrumb Path */}
        {path.length > 0 && (
          <div className="concept-card__path">
            <h4>Concept Path</h4>
            <div className="concept-card__breadcrumb">
              {path.map((pathUri, index) => (
                <React.Fragment key={pathUri}>
                  <span className="concept-card__path-item">{pathUri}</span>
                  {index < path.length - 1 && (
                    <span className="concept-card__path-separator">→</span>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        )}

        {/* Parent Concept */}
        {parent && (
          <div className="concept-card__parent">
            <h4>Parent Concept</h4>
            {renderConceptLink(parent, 'parent')}
          </div>
        )}

        {/* Child Concepts */}
        {children.length > 0 && (
          <div className="concept-card__children">
            <h4>Child Concepts ({children.length})</h4>
            <div className="concept-card__links-grid">
              {children.map(child => renderConceptLink(child, 'child'))}
            </div>
          </div>
        )}

        {/* Sibling Concepts */}
        {siblings.length > 0 && (
          <div className="concept-card__siblings">
            <h4>Sibling Concepts ({siblings.length})</h4>
            <div className="concept-card__links-grid">
              {siblings.slice(0, 10).map(sibling => renderConceptLink(sibling, 'sibling'))}
              {siblings.length > 10 && (
                <span className="concept-card__more">
                  +{siblings.length - 10} more...
                </span>
              )}
            </div>
          </div>
        )}

        {/* Related Concepts */}
        {concept.related.length > 0 && (
          <div className="concept-card__related">
            <h4>Related Concepts ({concept.related.length})</h4>
            <div className="concept-card__related-list">
              {concept.related.slice(0, 5).map((relatedUri, index) => (
                <div key={relatedUri} className="concept-card__related-item">
                  <a 
                    href={relatedUri} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="concept-card__external-link"
                  >
                    {relatedUri}
                  </a>
                </div>
              ))}
              {concept.related.length > 5 && (
                <span className="concept-card__more">
                  +{concept.related.length - 5} more...
                </span>
              )}
            </div>
          </div>
        )}

        {/* Concept URI */}
        <div className="concept-card__uri">
          <h4>Concept URI</h4>
          <a 
            href={concept.uri} 
            target="_blank" 
            rel="noopener noreferrer"
            className="concept-card__uri-link"
          >
            {concept.uri}
          </a>
        </div>
      </div>
    </div>
  );
};