import React, { useState, useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { knowledgeGraphService } from '../services/knowledgeGraphService';

interface Node {
  id: string;
  name: string;
  type: string;
  size: number;
  centrality: number;
  metadata: any;
}

interface Edge {
  source: string;
  target: string;
  weight: number;
  type: string;
  confidence: number;
  metadata: any;
}

interface GraphData {
  nodes: Node[];
  edges: Edge[];
  statistics: any;
}

interface KnowledgeGraphViewerProps {
  query?: string;
  maxDocuments?: number;
  height?: number;
  width?: number;
}

const KnowledgeGraphViewer: React.FC<KnowledgeGraphViewerProps> = ({
  query = '',
  maxDocuments = 50,
  height = 600,
  width = 800
}) => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState<string>('');
  
  const svgRef = useRef<SVGSVGElement>(null);
  const simulationRef = useRef<d3.Simulation<Node, Edge> | null>(null);

  const nodeColors = {
    organization: '#ff6b6b',
    legal_concept: '#4ecdc4',
    geographic_location: '#45b7d1',
    person: '#96ceb4',
    legal_reference: '#feca57',
    default: '#95a5a6'
  };

  const buildGraph = async (searchQuery: string) => {
    if (!searchQuery.trim()) {
      setError('Please enter a search query');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await knowledgeGraphService.buildKnowledgeGraph(searchQuery, maxDocuments);
      setGraphData(response.data);
    } catch (err) {
      setError('Failed to build knowledge graph. Please try again.');
      console.error('Error building graph:', err);
    } finally {
      setLoading(false);
    }
  };

  const renderGraph = (data: GraphData) => {
    if (!svgRef.current || !data.nodes.length) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const g = svg.append('g');

    // Add zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Create simulation
    const simulation = d3.forceSimulation<Node>(data.nodes)
      .force('link', d3.forceLink<Node, Edge>(data.edges)
        .id(d => d.id)
        .distance(d => 100 / Math.sqrt(d.weight)))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => Math.sqrt(d.size) + 5));

    simulationRef.current = simulation;

    // Create arrow markers for directed edges
    svg.append('defs').selectAll('marker')
      .data(['arrow'])
      .enter().append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 15)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#999');

    // Create links
    const link = g.append('g')
      .attr('class', 'links')
      .selectAll('line')
      .data(data.edges)
      .enter().append('line')
      .attr('stroke', '#999')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', d => Math.sqrt(d.weight) * 2)
      .attr('marker-end', 'url(#arrow)');

    // Create nodes
    const node = g.append('g')
      .attr('class', 'nodes')
      .selectAll('circle')
      .data(data.nodes)
      .enter().append('circle')
      .attr('r', d => Math.sqrt(d.size))
      .attr('fill', d => nodeColors[d.type as keyof typeof nodeColors] || nodeColors.default)
      .attr('stroke', '#fff')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .call(d3.drag<SVGCircleElement, Node>()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));

    // Add labels
    const label = g.append('g')
      .attr('class', 'labels')
      .selectAll('text')
      .data(data.nodes)
      .enter().append('text')
      .text(d => d.name.length > 20 ? d.name.substring(0, 20) + '...' : d.name)
      .attr('font-size', '10px')
      .attr('font-family', 'Arial, sans-serif')
      .attr('fill', '#333')
      .attr('text-anchor', 'middle')
      .attr('dy', '.35em')
      .style('pointer-events', 'none');

    // Add node click handler
    node.on('click', (event, d) => {
      event.stopPropagation();
      setSelectedNode(d);
    });

    // Add hover effects
    node.on('mouseover', (event, d) => {
      // Highlight connected nodes
      const connectedNodeIds = new Set();
      data.edges.forEach(edge => {
        if (edge.source === d.id) connectedNodeIds.add(edge.target);
        if (edge.target === d.id) connectedNodeIds.add(edge.source);
      });

      node.style('opacity', n => connectedNodeIds.has(n.id) || n.id === d.id ? 1 : 0.3);
      link.style('opacity', l => l.source === d.id || l.target === d.id ? 1 : 0.1);
      label.style('opacity', n => connectedNodeIds.has(n.id) || n.id === d.id ? 1 : 0.3);
    });

    node.on('mouseout', () => {
      node.style('opacity', 1);
      link.style('opacity', 0.6);
      label.style('opacity', 1);
    });

    // Update positions on simulation tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => (d.source as any).x)
        .attr('y1', d => (d.source as any).y)
        .attr('x2', d => (d.target as any).x)
        .attr('y2', d => (d.target as any).y);

      node
        .attr('cx', d => (d as any).x)
        .attr('cy', d => (d as any).y);

      label
        .attr('x', d => (d as any).x)
        .attr('y', d => (d as any).y + Math.sqrt(d.size) + 15);
    });

    function dragstarted(event: any, d: Node) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      (d as any).fx = (d as any).x;
      (d as any).fy = (d as any).y;
    }

    function dragged(event: any, d: Node) {
      (d as any).fx = event.x;
      (d as any).fy = event.y;
    }

    function dragended(event: any, d: Node) {
      if (!event.active) simulation.alphaTarget(0);
      (d as any).fx = null;
      (d as any).fy = null;
    }
  };

  useEffect(() => {
    if (graphData) {
      renderGraph(graphData);
    }
  }, [graphData, width, height]);

  useEffect(() => {
    if (query) {
      buildGraph(query);
    }
  }, [query, maxDocuments]);

  const filteredNodes = graphData?.nodes.filter(node => {
    const matchesSearch = !searchTerm || 
      node.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = !filterType || node.type === filterType;
    return matchesSearch && matchesType;
  }) || [];

  const nodeTypes = [...new Set(graphData?.nodes.map(n => n.type) || [])];

  return (
    <div className="knowledge-graph-viewer">
      <div className="graph-controls">
        <div className="search-controls">
          <input
            type="text"
            placeholder="Search for documents..."
            value={query}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          <button 
            onClick={() => buildGraph(query)}
            disabled={loading}
            className="build-button"
          >
            {loading ? 'Building...' : 'Build Graph'}
          </button>
        </div>

        {graphData && (
          <div className="graph-filters">
            <input
              type="text"
              placeholder="Filter nodes..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="filter-input"
            />
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="type-filter"
            >
              <option value="">All Types</option>
              {nodeTypes.map(type => (
                <option key={type} value={type}>
                  {type.replace('_', ' ').toUpperCase()}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {error && (
        <div className="error-message">
          {error}
        </div>
      )}

      <div className="graph-container">
        <div className="graph-main">
          <svg
            ref={svgRef}
            width={width}
            height={height}
            style={{ border: '1px solid #ddd', borderRadius: '4px' }}
          />
        </div>

        {graphData && (
          <div className="graph-sidebar">
            <div className="graph-statistics">
              <h3>Graph Statistics</h3>
              <div className="stat-item">
                <strong>Nodes:</strong> {graphData.statistics.nodes}
              </div>
              <div className="stat-item">
                <strong>Edges:</strong> {graphData.statistics.edges}
              </div>
              <div className="stat-item">
                <strong>Density:</strong> {graphData.statistics.density?.toFixed(3)}
              </div>
              <div className="stat-item">
                <strong>Components:</strong> {graphData.statistics.connected_components}
              </div>
            </div>

            <div className="node-types-legend">
              <h4>Node Types</h4>
              {Object.entries(nodeColors).filter(([key]) => key !== 'default').map(([type, color]) => (
                <div key={type} className="legend-item">
                  <div 
                    className="legend-color" 
                    style={{ backgroundColor: color }}
                  />
                  <span>{type.replace('_', ' ').toUpperCase()}</span>
                </div>
              ))}
            </div>

            {selectedNode && (
              <div className="selected-node-info">
                <h4>Selected Node</h4>
                <div className="node-detail">
                  <strong>Name:</strong> {selectedNode.name}
                </div>
                <div className="node-detail">
                  <strong>Type:</strong> {selectedNode.type.replace('_', ' ').toUpperCase()}
                </div>
                <div className="node-detail">
                  <strong>Centrality:</strong> {selectedNode.centrality.toFixed(3)}
                </div>
                <div className="node-detail">
                  <strong>Documents:</strong> {selectedNode.metadata.document_count || 1}
                </div>
              </div>
            )}

            {filteredNodes.length > 0 && searchTerm && (
              <div className="filtered-nodes">
                <h4>Matching Nodes ({filteredNodes.length})</h4>
                <div className="node-list">
                  {filteredNodes.slice(0, 10).map(node => (
                    <div 
                      key={node.id} 
                      className="node-item"
                      onClick={() => setSelectedNode(node)}
                      style={{ cursor: 'pointer' }}
                    >
                      <div 
                        className="node-color-indicator"
                        style={{ 
                          backgroundColor: nodeColors[node.type as keyof typeof nodeColors] || nodeColors.default 
                        }}
                      />
                      <span className="node-name">{node.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <style jsx>{`
        .knowledge-graph-viewer {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        .graph-controls {
          display: flex;
          flex-direction: column;
          gap: 1rem;
          padding: 1rem;
          background: #f8f9fa;
          border-radius: 8px;
        }

        .search-controls {
          display: flex;
          gap: 1rem;
          align-items: center;
        }

        .search-input {
          flex: 1;
          padding: 0.5rem;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 1rem;
        }

        .build-button {
          padding: 0.5rem 1rem;
          background: #007bff;
          color: white;
          border: none;
          border-radius: 4px;
          cursor: pointer;
          font-size: 1rem;
        }

        .build-button:disabled {
          background: #6c757d;
          cursor: not-allowed;
        }

        .graph-filters {
          display: flex;
          gap: 1rem;
        }

        .filter-input, .type-filter {
          padding: 0.5rem;
          border: 1px solid #ddd;
          border-radius: 4px;
        }

        .error-message {
          padding: 1rem;
          background: #f8d7da;
          color: #721c24;
          border-radius: 4px;
          border: 1px solid #f5c6cb;
        }

        .graph-container {
          display: flex;
          gap: 1rem;
        }

        .graph-main {
          flex: 1;
        }

        .graph-sidebar {
          width: 300px;
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        .graph-statistics, .node-types-legend, .selected-node-info, .filtered-nodes {
          padding: 1rem;
          background: #f8f9fa;
          border-radius: 8px;
          border: 1px solid #dee2e6;
        }

        .stat-item {
          display: flex;
          justify-content: space-between;
          padding: 0.25rem 0;
        }

        .legend-item {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.25rem 0;
        }

        .legend-color {
          width: 12px;
          height: 12px;
          border-radius: 50%;
        }

        .node-detail {
          padding: 0.25rem 0;
        }

        .node-list {
          max-height: 200px;
          overflow-y: auto;
        }

        .node-item {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.5rem;
          border-radius: 4px;
          transition: background-color 0.2s;
        }

        .node-item:hover {
          background: rgba(0, 123, 255, 0.1);
        }

        .node-color-indicator {
          width: 8px;
          height: 8px;
          border-radius: 50%;
        }

        .node-name {
          font-size: 0.9rem;
        }
      `}</style>
    </div>
  );
};

export default KnowledgeGraphViewer;