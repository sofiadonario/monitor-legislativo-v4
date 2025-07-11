/**
 * VocabularyTree Component
 * Hierarchical tree view for concept navigation
 */
import React, { useState, useEffect } from 'react';
import { vocabularyService } from '../../services/vocabularyService';
import { Concept, ConceptHierarchy } from '../../types';
import { LoadingSpinner } from '../LoadingSpinner';

interface VocabularyTreeProps {
  conceptScheme: string;
  selectedConceptUri?: string;
  onConceptSelect: (concept: Concept) => void;
}

interface TreeNode {
  concept: Concept;
  children: TreeNode[];
  isExpanded: boolean;
  isLoaded: boolean;
  level: number;
}

export const VocabularyTree: React.FC<VocabularyTreeProps> = ({
  conceptScheme,
  selectedConceptUri,
  onConceptSelect
}) => {
  const [rootNodes, setRootNodes] = useState<TreeNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadRootConcepts();
  }, [conceptScheme]);

  const loadRootConcepts = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const schemeOverview = await vocabularyService.getConceptSchemeOverview(conceptScheme);
      
      if (schemeOverview && schemeOverview.rootConcepts) {
        const rootTreeNodes: TreeNode[] = [];
        
        for (const rootInfo of schemeOverview.rootConcepts) {
          const hierarchy = await vocabularyService.getConceptHierarchy(rootInfo.uri);
          if (hierarchy) {
            rootTreeNodes.push({
              concept: hierarchy.concept,
              children: [],
              isExpanded: false,
              isLoaded: false,
              level: 0
            });
          }
        }
        
        setRootNodes(rootTreeNodes);
      }
    } catch (err) {
      setError(`Failed to load root concepts: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const loadChildConcepts = async (parentNode: TreeNode) => {
    try {
      const narrowerConcepts = await vocabularyService.getNarrowerConcepts(parentNode.concept.uri, false);
      
      const childNodes: TreeNode[] = narrowerConcepts.map(concept => ({
        concept,
        children: [],
        isExpanded: false,
        isLoaded: false,
        level: parentNode.level + 1
      }));

      return childNodes;
    } catch (err) {
      console.error('Error loading child concepts:', err);
      return [];
    }
  };

  const toggleNodeExpansion = async (nodeIndex: number, parentNodes?: TreeNode[]) => {
    const updateNodeExpansion = async (nodes: TreeNode[], index: number): Promise<TreeNode[]> => {
      const newNodes = [...nodes];
      const node = newNodes[index];
      
      if (!node.isExpanded && !node.isLoaded) {
        // Load children if not loaded yet
        const children = await loadChildConcepts(node);
        node.children = children;
        node.isLoaded = true;
      }
      
      node.isExpanded = !node.isExpanded;
      return newNodes;
    };

    if (parentNodes) {
      // Update nested node
      const updatedParents = await updateNodeExpansion(parentNodes, nodeIndex);
      setRootNodes(prev => updateNestedNodes(prev, updatedParents));
    } else {
      // Update root node
      const updatedRoots = await updateNodeExpansion(rootNodes, nodeIndex);
      setRootNodes(updatedRoots);
    }
  };

  const updateNestedNodes = (nodes: TreeNode[], updates: TreeNode[]): TreeNode[] => {
    // Helper function to recursively update nested nodes
    return nodes.map(node => {
      const updatedNode = updates.find(u => u.concept.uri === node.concept.uri);
      if (updatedNode) {
        return updatedNode;
      }
      if (node.children.length > 0) {
        return {
          ...node,
          children: updateNestedNodes(node.children, updates)
        };
      }
      return node;
    });
  };

  const renderTreeNode = (node: TreeNode, index: number, parentNodes?: TreeNode[]) => {
    const isSelected = selectedConceptUri === node.concept.uri;
    const hasChildren = node.concept.narrower.length > 0;
    
    return (
      <div key={node.concept.uri} className="vocabulary-tree__node">
        <div 
          className={`vocabulary-tree__node-content ${isSelected ? 'selected' : ''}`}
          style={{ paddingLeft: `${node.level * 20}px` }}
        >
          {hasChildren && (
            <button
              className={`vocabulary-tree__expand-btn ${node.isExpanded ? 'expanded' : ''}`}
              onClick={() => toggleNodeExpansion(index, parentNodes)}
              aria-label={node.isExpanded ? 'Collapse' : 'Expand'}
            >
              {node.isExpanded ? '▼' : '▶'}
            </button>
          )}
          
          <button
            className="vocabulary-tree__concept-btn"
            onClick={() => onConceptSelect(node.concept)}
            title={node.concept.definition.pt || node.concept.definition.en || ''}
          >
            <span className="vocabulary-tree__concept-label">
              {node.concept.prefLabel.pt || node.concept.prefLabel.en || node.concept.uri}
            </span>
            {node.concept.notation && (
              <span className="vocabulary-tree__concept-notation">
                ({node.concept.notation})
              </span>
            )}
          </button>
        </div>
        
        {node.isExpanded && node.children.length > 0 && (
          <div className="vocabulary-tree__children">
            {node.children.map((child, childIndex) => 
              renderTreeNode(child, childIndex, node.children)
            )}
          </div>
        )}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="vocabulary-tree__loading">
        <LoadingSpinner size="small" />
        <p>Loading concept hierarchy...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="vocabulary-tree__error">
        <p>Error loading tree: {error}</p>
        <button onClick={loadRootConcepts}>Retry</button>
      </div>
    );
  }

  if (rootNodes.length === 0) {
    return (
      <div className="vocabulary-tree__empty">
        <p>No concepts found in this scheme.</p>
      </div>
    );
  }

  return (
    <div className="vocabulary-tree">
      <div className="vocabulary-tree__nodes">
        {rootNodes.map((node, index) => renderTreeNode(node, index))}
      </div>
    </div>
  );
};