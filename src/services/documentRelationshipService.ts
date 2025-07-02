/**
 * Document Relationship Service
 * Advanced service for mapping relationships and citations between legislative documents
 */
import { LegislativeDocument, DocumentType } from '../types';

export interface DocumentRelationship {
  id: string;
  sourceDocument: LegislativeDocument;
  targetDocument: LegislativeDocument;
  relationshipType: RelationshipType;
  confidence: number;
  evidence: RelationshipEvidence[];
  direction: 'bidirectional' | 'source_to_target' | 'target_to_source';
  strength: 'weak' | 'moderate' | 'strong';
  temporal: TemporalRelationship;
  legal: LegalRelationship;
  semantic: SemanticRelationship;
  discoveredAt: Date;
  verifiedAt?: Date;
  verifiedBy?: string;
}

export type RelationshipType = 
  | 'amends' | 'repeals' | 'references' | 'implements' | 'supersedes'
  | 'complements' | 'conflicts' | 'consolidates' | 'interprets' | 'applies'
  | 'precedent' | 'successor' | 'related' | 'derivative' | 'parallel';

export interface RelationshipEvidence {
  type: 'explicit_citation' | 'implicit_reference' | 'semantic_similarity' | 'structural_pattern' | 'temporal_sequence';
  text: string;
  location: {
    document: 'source' | 'target';
    position: { start: number; end: number; section?: string };
  };
  confidence: number;
  extractedAt: Date;
  context: string;
}

export interface TemporalRelationship {
  chronologicalOrder: 'before' | 'after' | 'concurrent' | 'unknown';
  timeDifference: number; // days
  effectiveOrder: 'before' | 'after' | 'concurrent' | 'unknown';
  publicationGap: number; // days
  temporalOverlap: boolean;
}

export interface LegalRelationship {
  hierarchical: 'superior' | 'subordinate' | 'equal' | 'unknown';
  jurisdiction: 'same' | 'different' | 'overlapping';
  authority: 'same' | 'different' | 'related';
  legalEffect: 'modifying' | 'nullifying' | 'supplementing' | 'clarifying' | 'neutral';
  bindingEffect: 'binding' | 'persuasive' | 'informational' | 'conflicting';
}

export interface SemanticRelationship {
  topicSimilarity: number;
  conceptualOverlap: number;
  keywordSimilarity: number;
  intentAlignment: number;
  scopeRelation: 'broader' | 'narrower' | 'equivalent' | 'intersecting' | 'disjoint';
  sharedConcepts: string[];
  distinctiveConcepts: {
    source: string[];
    target: string[];
  };
}

export interface DocumentNetwork {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  clusters: DocumentCluster[];
  metrics: NetworkMetrics;
  timeline: NetworkTimeline;
}

export interface NetworkNode {
  id: string;
  document: LegislativeDocument;
  position: { x: number; y: number };
  size: number;
  importance: number;
  centrality: {
    degree: number;
    betweenness: number;
    closeness: number;
    eigenvector: number;
  };
  cluster: string;
  metadata: {
    inDegree: number;
    outDegree: number;
    citationCount: number;
    referencedBy: number;
    documentAge: number;
    influence: number;
  };
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  relationship: DocumentRelationship;
  weight: number;
  style: {
    color: string;
    width: number;
    type: 'solid' | 'dashed' | 'dotted';
  };
}

export interface DocumentCluster {
  id: string;
  label: string;
  documents: LegislativeDocument[];
  centroid: LegislativeDocument;
  cohesion: number;
  separation: number;
  topics: string[];
  timespan: { start: Date; end: Date };
  authority: string;
  regulatory: {
    framework: string;
    domain: string;
    complexity: number;
  };
}

export interface NetworkMetrics {
  totalNodes: number;
  totalEdges: number;
  density: number;
  averagePathLength: number;
  clusteringCoefficient: number;
  modularity: number;
  components: number;
  diameter: number;
  centralNodes: Array<{ nodeId: string; score: number; type: string }>;
  influentialDocuments: Array<{ document: LegislativeDocument; influence: number }>;
}

export interface NetworkTimeline {
  events: Array<{
    date: Date;
    type: 'creation' | 'amendment' | 'repeal' | 'reference' | 'implementation';
    documents: string[];
    description: string;
    impact: 'low' | 'medium' | 'high';
  }>;
  evolutionPhases: Array<{
    period: { start: Date; end: Date };
    characteristics: string[];
    dominantAuthorities: string[];
    keyDocuments: string[];
    regulatoryFocus: string[];
  }>;
}

export interface CitationAnalysis {
  documentId: string;
  citations: {
    outgoing: Citation[];
    incoming: Citation[];
    selfCitations: Citation[];
  };
  metrics: {
    citationCount: number;
    referencedByCount: number;
    citationDiversity: number;
    temporalCitationPattern: Array<{ year: number; count: number }>;
    authorityCitationPattern: Record<string, number>;
    typeCitationPattern: Record<DocumentType, number>;
  };
  impact: {
    hIndex: number;
    citationVelocity: number;
    influenceScore: number;
    networkCentrality: number;
  };
  quality: {
    citationAccuracy: number;
    contextualRelevance: number;
    completeness: number;
  };
}

export interface Citation {
  id: string;
  sourceDocument: string;
  targetDocument: string;
  citationType: 'direct' | 'indirect' | 'implicit' | 'structural';
  citationContext: string;
  citationPurpose: 'support' | 'contradict' | 'clarify' | 'extend' | 'implement' | 'reference';
  location: {
    section: string;
    position: { start: number; end: number };
    context: string;
  };
  extractedText: string;
  confidence: number;
  validated: boolean;
  metadata: {
    extractedAt: Date;
    method: 'pattern_matching' | 'nlp_extraction' | 'manual_annotation';
    validator?: string;
  };
}

export interface RelationshipPattern {
  patternId: string;
  description: string;
  regex: RegExp;
  relationshipType: RelationshipType;
  confidence: number;
  examples: string[];
  contexts: string[];
  language: 'pt-BR';
}

export class DocumentRelationshipService {
  private static instance: DocumentRelationshipService;
  private relationships: Map<string, DocumentRelationship> = new Map();
  private citationIndex: Map<string, CitationAnalysis> = new Map();
  private relationshipPatterns: RelationshipPattern[] = [];

  private constructor() {
    this.initializePatterns();
  }

  public static getInstance(): DocumentRelationshipService {
    if (!DocumentRelationshipService.instance) {
      DocumentRelationshipService.instance = new DocumentRelationshipService();
    }
    return DocumentRelationshipService.instance;
  }

  /**
   * Discover relationships between documents
   */
  public async discoverRelationships(
    documents: LegislativeDocument[],
    options: {
      includeSemanticAnalysis?: boolean;
      includeCitationAnalysis?: boolean;
      confidenceThreshold?: number;
      maxRelationships?: number;
      focusDocuments?: string[];
    } = {}
  ): Promise<DocumentRelationship[]> {
    const {
      includeSemanticAnalysis = true,
      includeCitationAnalysis = true,
      confidenceThreshold = 0.6,
      maxRelationships = 1000,
      focusDocuments
    } = options;

    const relationships: DocumentRelationship[] = [];
    const documentsToAnalyze = focusDocuments 
      ? documents.filter(doc => focusDocuments.includes(doc.id))
      : documents;

    // Discover explicit relationships through citation analysis
    if (includeCitationAnalysis) {
      const citationRelationships = await this.discoverCitationRelationships(documentsToAnalyze, documents);
      relationships.push(...citationRelationships);
    }

    // Discover implicit relationships through pattern matching
    const patternRelationships = await this.discoverPatternRelationships(documentsToAnalyze, documents);
    relationships.push(...patternRelationships);

    // Discover semantic relationships
    if (includeSemanticAnalysis) {
      const semanticRelationships = await this.discoverSemanticRelationships(documentsToAnalyze, documents);
      relationships.push(...semanticRelationships);
    }

    // Discover temporal relationships
    const temporalRelationships = await this.discoverTemporalRelationships(documentsToAnalyze);
    relationships.push(...temporalRelationships);

    // Filter by confidence and deduplicate
    const filteredRelationships = this.deduplicateRelationships(
      relationships.filter(rel => rel.confidence >= confidenceThreshold)
    ).slice(0, maxRelationships);

    // Store relationships
    filteredRelationships.forEach(rel => {
      this.relationships.set(rel.id, rel);
    });

    return filteredRelationships;
  }

  /**
   * Build document network from relationships
   */
  public buildDocumentNetwork(
    documents: LegislativeDocument[],
    relationships: DocumentRelationship[],
    options: {
      layoutAlgorithm?: 'force' | 'hierarchical' | 'circular' | 'temporal';
      clusteringMethod?: 'topic' | 'authority' | 'temporal' | 'regulatory';
      includeMetrics?: boolean;
    } = {}
  ): DocumentNetwork {
    const {
      layoutAlgorithm = 'force',
      clusteringMethod = 'topic',
      includeMetrics = true
    } = options;

    // Create nodes
    const nodes = documents.map(doc => this.createNetworkNode(doc, relationships));

    // Create edges
    const edges = relationships.map(rel => this.createNetworkEdge(rel));

    // Apply layout
    this.applyLayout(nodes, edges, layoutAlgorithm);

    // Create clusters
    const clusters = this.createClusters(documents, relationships, clusteringMethod);

    // Calculate metrics
    const metrics = includeMetrics ? this.calculateNetworkMetrics(nodes, edges) : this.getEmptyMetrics();

    // Build timeline
    const timeline = this.buildNetworkTimeline(documents, relationships);

    return {
      nodes,
      edges,
      clusters,
      metrics,
      timeline
    };
  }

  /**
   * Analyze citations for a specific document
   */
  public async analyzeCitations(
    document: LegislativeDocument,
    corpus: LegislativeDocument[]
  ): Promise<CitationAnalysis> {
    const documentId = document.id;
    
    // Check cache
    if (this.citationIndex.has(documentId)) {
      return this.citationIndex.get(documentId)!;
    }

    // Extract outgoing citations
    const outgoingCitations = await this.extractCitations(document, corpus);
    
    // Find incoming citations
    const incomingCitations = await this.findIncomingCitations(document, corpus);
    
    // Identify self-citations
    const selfCitations = outgoingCitations.filter(citation => 
      citation.targetDocument === documentId
    );

    // Calculate metrics
    const metrics = this.calculateCitationMetrics(outgoingCitations, incomingCitations, selfCitations);
    
    // Calculate impact metrics
    const impact = this.calculateImpactMetrics(document, incomingCitations, corpus);
    
    // Assess quality
    const quality = this.assessCitationQuality(outgoingCitations, incomingCitations);

    const analysis: CitationAnalysis = {
      documentId,
      citations: {
        outgoing: outgoingCitations,
        incoming: incomingCitations,
        selfCitations
      },
      metrics,
      impact,
      quality
    };

    this.citationIndex.set(documentId, analysis);
    return analysis;
  }

  /**
   * Find related documents based on various criteria
   */
  public findRelatedDocuments(
    document: LegislativeDocument,
    corpus: LegislativeDocument[],
    options: {
      relationshipTypes?: RelationshipType[];
      maxResults?: number;
      minConfidence?: number;
      includeSemanticSimilarity?: boolean;
    } = {}
  ): Array<{ document: LegislativeDocument; relationship: DocumentRelationship; score: number }> {
    const {
      relationshipTypes,
      maxResults = 10,
      minConfidence = 0.5,
      includeSemanticSimilarity = true
    } = options;

    const related: Array<{ document: LegislativeDocument; relationship: DocumentRelationship; score: number }> = [];

    // Find direct relationships
    for (const relationship of this.relationships.values()) {
      if (relationship.sourceDocument.id === document.id || relationship.targetDocument.id === document.id) {
        if (relationshipTypes && !relationshipTypes.includes(relationship.relationshipType)) continue;
        if (relationship.confidence < minConfidence) continue;

        const relatedDoc = relationship.sourceDocument.id === document.id 
          ? relationship.targetDocument 
          : relationship.sourceDocument;

        related.push({
          document: relatedDoc,
          relationship,
          score: relationship.confidence * relationship.strength === 'strong' ? 1.0 : 
                 relationship.strength === 'moderate' ? 0.7 : 0.4
        });
      }
    }

    // Add semantic similarity if requested
    if (includeSemanticSimilarity) {
      const semanticMatches = this.findSemanticallySimilarDocuments(document, corpus, maxResults);
      for (const match of semanticMatches) {
        if (!related.find(r => r.document.id === match.document.id)) {
          related.push({
            document: match.document,
            relationship: match.relationship,
            score: match.similarity
          });
        }
      }
    }

    return related
      .sort((a, b) => b.score - a.score)
      .slice(0, maxResults);
  }

  /**
   * Export relationship network in various formats
   */
  public exportNetwork(
    network: DocumentNetwork,
    format: 'graphml' | 'gexf' | 'json' | 'csv' | 'cytoscape'
  ): string {
    switch (format) {
      case 'graphml':
        return this.exportToGraphML(network);
      case 'gexf':
        return this.exportToGEXF(network);
      case 'json':
        return this.exportToJSON(network);
      case 'csv':
        return this.exportToCSV(network);
      case 'cytoscape':
        return this.exportToCytoscape(network);
      default:
        return this.exportToJSON(network);
    }
  }

  // Private helper methods

  private initializePatterns(): void {
    this.relationshipPatterns = [
      {
        patternId: 'amends_pattern',
        description: 'Amendment pattern',
        regex: /altera\s+(?:a\s+)?lei\s+n[ºo°]?\s*(\d+)/gi,
        relationshipType: 'amends',
        confidence: 0.9,
        examples: ['altera a Lei nº 9.503', 'altera Lei 12.587'],
        contexts: ['alteração', 'modificação', 'emenda'],
        language: 'pt-BR'
      },
      {
        patternId: 'repeals_pattern',
        description: 'Repeal pattern',
        regex: /revoga\s+(?:a\s+)?(?:lei|decreto|portaria)\s+n[ºo°]?\s*(\d+)/gi,
        relationshipType: 'repeals',
        confidence: 0.95,
        examples: ['revoga a Lei nº 8.000', 'revoga Decreto 5.000'],
        contexts: ['revogação', 'ab-rogação', 'derrogação'],
        language: 'pt-BR'
      },
      {
        patternId: 'implements_pattern',
        description: 'Implementation pattern',
        regex: /regulamenta\s+(?:a\s+)?(?:lei|decreto)\s+n[ºo°]?\s*(\d+)/gi,
        relationshipType: 'implements',
        confidence: 0.85,
        examples: ['regulamenta a Lei nº 10.000', 'regulamenta Decreto 3.000'],
        contexts: ['regulamentação', 'implementação', 'execução'],
        language: 'pt-BR'
      },
      {
        patternId: 'references_pattern',
        description: 'Reference pattern',
        regex: /(?:nos\s+termos|conforme|de\s+acordo\s+com)\s+(?:a\s+)?(?:lei|decreto|portaria)\s+n[ºo°]?\s*(\d+)/gi,
        relationshipType: 'references',
        confidence: 0.7,
        examples: ['nos termos da Lei nº 9.000', 'conforme Decreto 4.000'],
        contexts: ['referência', 'citação', 'menção'],
        language: 'pt-BR'
      },
      {
        patternId: 'supersedes_pattern',
        description: 'Supersession pattern',
        regex: /substitui\s+(?:a\s+)?(?:lei|decreto|portaria)\s+n[ºo°]?\s*(\d+)/gi,
        relationshipType: 'supersedes',
        confidence: 0.9,
        examples: ['substitui a Lei nº 7.000', 'substitui Decreto 2.000'],
        contexts: ['substituição', 'sucessão', 'renovação'],
        language: 'pt-BR'
      }
    ];
  }

  private async discoverCitationRelationships(
    sourceDocuments: LegislativeDocument[],
    allDocuments: LegislativeDocument[]
  ): Promise<DocumentRelationship[]> {
    const relationships: DocumentRelationship[] = [];

    for (const sourceDoc of sourceDocuments) {
      const citations = await this.extractCitations(sourceDoc, allDocuments);
      
      for (const citation of citations) {
        const targetDoc = allDocuments.find(doc => doc.id === citation.targetDocument);
        if (!targetDoc) continue;

        const relationship = await this.createRelationshipFromCitation(sourceDoc, targetDoc, citation);
        relationships.push(relationship);
      }
    }

    return relationships;
  }

  private async discoverPatternRelationships(
    sourceDocuments: LegislativeDocument[],
    allDocuments: LegislativeDocument[]
  ): Promise<DocumentRelationship[]> {
    const relationships: DocumentRelationship[] = [];

    for (const sourceDoc of sourceDocuments) {
      const text = `${sourceDoc.title} ${sourceDoc.summary}`;
      
      for (const pattern of this.relationshipPatterns) {
        const matches = Array.from(text.matchAll(pattern.regex));
        
        for (const match of matches) {
          const targetDoc = this.findDocumentByNumber(match[1], allDocuments);
          if (!targetDoc || targetDoc.id === sourceDoc.id) continue;

          const relationship = await this.createRelationshipFromPattern(
            sourceDoc, 
            targetDoc, 
            pattern, 
            match
          );
          relationships.push(relationship);
        }
      }
    }

    return relationships;
  }

  private async discoverSemanticRelationships(
    sourceDocuments: LegislativeDocument[],
    allDocuments: LegislativeDocument[]
  ): Promise<DocumentRelationship[]> {
    const relationships: DocumentRelationship[] = [];
    const semanticThreshold = 0.7;

    for (const sourceDoc of sourceDocuments) {
      const similarDocs = this.findSemanticallySimilarDocuments(sourceDoc, allDocuments, 5);
      
      for (const similar of similarDocs) {
        if (similar.similarity >= semanticThreshold) {
          relationships.push(similar.relationship);
        }
      }
    }

    return relationships;
  }

  private async discoverTemporalRelationships(
    documents: LegislativeDocument[]
  ): Promise<DocumentRelationship[]> {
    const relationships: DocumentRelationship[] = [];
    const sortedDocs = documents.sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

    for (let i = 0; i < sortedDocs.length - 1; i++) {
      for (let j = i + 1; j < Math.min(i + 5, sortedDocs.length); j++) {
        const docA = sortedDocs[i];
        const docB = sortedDocs[j];
        
        const timeDiff = Math.abs(new Date(docB.date).getTime() - new Date(docA.date).getTime()) / (1000 * 60 * 60 * 24);
        
        if (timeDiff <= 365 && this.haveSimilarAuthority(docA, docB)) {
          const relationship = await this.createTemporalRelationship(docA, docB, timeDiff);
          relationships.push(relationship);
        }
      }
    }

    return relationships;
  }

  private deduplicateRelationships(relationships: DocumentRelationship[]): DocumentRelationship[] {
    const seen = new Set<string>();
    const deduplicated: DocumentRelationship[] = [];

    for (const rel of relationships) {
      const key = `${rel.sourceDocument.id}-${rel.targetDocument.id}-${rel.relationshipType}`;
      const reverseKey = `${rel.targetDocument.id}-${rel.sourceDocument.id}-${rel.relationshipType}`;
      
      if (!seen.has(key) && !seen.has(reverseKey)) {
        seen.add(key);
        deduplicated.push(rel);
      }
    }

    return deduplicated;
  }

  private async extractCitations(
    document: LegislativeDocument,
    corpus: LegislativeDocument[]
  ): Promise<Citation[]> {
    const citations: Citation[] = [];
    const text = `${document.title} ${document.summary}`;
    
    // Pattern for Brazilian legal citations
    const citationPattern = /(?:lei|decreto|portaria|resolução)\s+n[ºo°]?\s*(\d+(?:[\/\-]\d+)?)/gi;
    
    let match;
    while ((match = citationPattern.exec(text)) !== null) {
      const targetDoc = this.findDocumentByNumber(match[1], corpus);
      if (targetDoc && targetDoc.id !== document.id) {
        citations.push({
          id: `citation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          sourceDocument: document.id,
          targetDocument: targetDoc.id,
          citationType: 'direct',
          citationContext: text.substring(Math.max(0, match.index - 50), match.index + 50),
          citationPurpose: 'reference',
          location: {
            section: 'content',
            position: { start: match.index, end: match.index + match[0].length },
            context: text.substring(Math.max(0, match.index - 100), match.index + 100)
          },
          extractedText: match[0],
          confidence: 0.85,
          validated: false,
          metadata: {
            extractedAt: new Date(),
            method: 'pattern_matching'
          }
        });
      }
    }

    return citations;
  }

  private findDocumentByNumber(number: string, documents: LegislativeDocument[]): LegislativeDocument | undefined {
    // Try to match by document number (simplified)
    return documents.find(doc => 
      doc.number?.includes(number) || 
      doc.title.includes(number) ||
      doc.url?.includes(number)
    );
  }

  private async findIncomingCitations(
    document: LegislativeDocument,
    corpus: LegislativeDocument[]
  ): Promise<Citation[]> {
    const incomingCitations: Citation[] = [];
    
    for (const otherDoc of corpus) {
      if (otherDoc.id === document.id) continue;
      
      const citations = await this.extractCitations(otherDoc, [document]);
      const relevantCitations = citations.filter(citation => citation.targetDocument === document.id);
      incomingCitations.push(...relevantCitations);
    }

    return incomingCitations;
  }

  private calculateCitationMetrics(
    outgoing: Citation[],
    incoming: Citation[],
    self: Citation[]
  ): CitationAnalysis['metrics'] {
    const citationCount = outgoing.length;
    const referencedByCount = incoming.length;
    
    // Calculate diversity (number of unique sources/targets)
    const uniqueTargets = new Set(outgoing.map(c => c.targetDocument)).size;
    const uniqueSources = new Set(incoming.map(c => c.sourceDocument)).size;
    const citationDiversity = (uniqueTargets + uniqueSources) / Math.max(citationCount + referencedByCount, 1);

    return {
      citationCount,
      referencedByCount,
      citationDiversity,
      temporalCitationPattern: [], // Would implement temporal analysis
      authorityCitationPattern: {}, // Would implement authority analysis
      typeCitationPattern: {} // Would implement type analysis
    };
  }

  private calculateImpactMetrics(
    document: LegislativeDocument,
    incomingCitations: Citation[],
    corpus: LegislativeDocument[]
  ): CitationAnalysis['impact'] {
    const citationCount = incomingCitations.length;
    
    // Simplified H-index calculation
    const hIndex = Math.min(citationCount, Math.sqrt(citationCount));
    
    // Citation velocity (citations per year since publication)
    const age = (Date.now() - new Date(document.date).getTime()) / (1000 * 60 * 60 * 24 * 365);
    const citationVelocity = age > 0 ? citationCount / age : 0;
    
    // Simplified influence score
    const influenceScore = citationCount * 0.5 + hIndex * 0.3 + citationVelocity * 0.2;
    
    return {
      hIndex,
      citationVelocity,
      influenceScore,
      networkCentrality: 0.5 // Would calculate from network
    };
  }

  private assessCitationQuality(
    outgoing: Citation[],
    incoming: Citation[]
  ): CitationAnalysis['quality'] {
    const totalCitations = outgoing.length + incoming.length;
    
    if (totalCitations === 0) {
      return { citationAccuracy: 0, contextualRelevance: 0, completeness: 0 };
    }

    const validatedCitations = [...outgoing, ...incoming].filter(c => c.validated).length;
    const highConfidenceCitations = [...outgoing, ...incoming].filter(c => c.confidence > 0.8).length;
    
    return {
      citationAccuracy: validatedCitations / totalCitations,
      contextualRelevance: highConfidenceCitations / totalCitations,
      completeness: Math.min(totalCitations / 10, 1) // Assumption: 10 citations is "complete"
    };
  }

  private findSemanticallySimilarDocuments(
    document: LegislativeDocument,
    corpus: LegislativeDocument[],
    maxResults: number
  ): Array<{ document: LegislativeDocument; similarity: number; relationship: DocumentRelationship }> {
    const results: Array<{ document: LegislativeDocument; similarity: number; relationship: DocumentRelationship }> = [];
    
    for (const otherDoc of corpus) {
      if (otherDoc.id === document.id) continue;
      
      const similarity = this.calculateSemanticSimilarity(document, otherDoc);
      
      if (similarity > 0.5) {
        const relationship = this.createSemanticRelationship(document, otherDoc, similarity);
        results.push({ document: otherDoc, similarity, relationship });
      }
    }

    return results
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, maxResults);
  }

  private calculateSemanticSimilarity(docA: LegislativeDocument, docB: LegislativeDocument): number {
    // Simple keyword-based similarity
    const keywordsA = new Set(docA.keywords.map(k => k.toLowerCase()));
    const keywordsB = new Set(docB.keywords.map(k => k.toLowerCase()));
    
    const intersection = new Set([...keywordsA].filter(k => keywordsB.has(k)));
    const union = new Set([...keywordsA, ...keywordsB]);
    
    return union.size > 0 ? intersection.size / union.size : 0;
  }

  private createSemanticRelationship(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    similarity: number
  ): DocumentRelationship {
    return {
      id: `semantic_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      sourceDocument: docA,
      targetDocument: docB,
      relationshipType: 'related',
      confidence: similarity,
      evidence: [],
      direction: 'bidirectional',
      strength: similarity > 0.8 ? 'strong' : similarity > 0.6 ? 'moderate' : 'weak',
      temporal: this.createTemporalAnalysis(docA, docB),
      legal: this.createLegalAnalysis(docA, docB),
      semantic: {
        topicSimilarity: similarity,
        conceptualOverlap: similarity,
        keywordSimilarity: similarity,
        intentAlignment: similarity * 0.8,
        scopeRelation: 'intersecting',
        sharedConcepts: docA.keywords.filter(k => docB.keywords.includes(k)),
        distinctiveConcepts: {
          source: docA.keywords.filter(k => !docB.keywords.includes(k)),
          target: docB.keywords.filter(k => !docA.keywords.includes(k))
        }
      },
      discoveredAt: new Date()
    };
  }

  private async createRelationshipFromCitation(
    sourceDoc: LegislativeDocument,
    targetDoc: LegislativeDocument,
    citation: Citation
  ): Promise<DocumentRelationship> {
    return {
      id: `citation_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      sourceDocument: sourceDoc,
      targetDocument: targetDoc,
      relationshipType: 'references',
      confidence: citation.confidence,
      evidence: [{
        type: 'explicit_citation',
        text: citation.extractedText,
        location: {
          document: 'source',
          position: citation.location.position
        },
        confidence: citation.confidence,
        extractedAt: new Date(),
        context: citation.citationContext
      }],
      direction: 'source_to_target',
      strength: citation.confidence > 0.8 ? 'strong' : 'moderate',
      temporal: this.createTemporalAnalysis(sourceDoc, targetDoc),
      legal: this.createLegalAnalysis(sourceDoc, targetDoc),
      semantic: {
        topicSimilarity: 0,
        conceptualOverlap: 0,
        keywordSimilarity: 0,
        intentAlignment: 0,
        scopeRelation: 'intersecting',
        sharedConcepts: [],
        distinctiveConcepts: { source: [], target: [] }
      },
      discoveredAt: new Date()
    };
  }

  private async createRelationshipFromPattern(
    sourceDoc: LegislativeDocument,
    targetDoc: LegislativeDocument,
    pattern: RelationshipPattern,
    match: RegExpMatchArray
  ): Promise<DocumentRelationship> {
    return {
      id: `pattern_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      sourceDocument: sourceDoc,
      targetDocument: targetDoc,
      relationshipType: pattern.relationshipType,
      confidence: pattern.confidence,
      evidence: [{
        type: 'structural_pattern',
        text: match[0],
        location: {
          document: 'source',
          position: { start: match.index || 0, end: (match.index || 0) + match[0].length }
        },
        confidence: pattern.confidence,
        extractedAt: new Date(),
        context: pattern.description
      }],
      direction: 'source_to_target',
      strength: pattern.confidence > 0.8 ? 'strong' : 'moderate',
      temporal: this.createTemporalAnalysis(sourceDoc, targetDoc),
      legal: this.createLegalAnalysis(sourceDoc, targetDoc),
      semantic: {
        topicSimilarity: 0,
        conceptualOverlap: 0,
        keywordSimilarity: 0,
        intentAlignment: 0,
        scopeRelation: 'intersecting',
        sharedConcepts: [],
        distinctiveConcepts: { source: [], target: [] }
      },
      discoveredAt: new Date()
    };
  }

  private async createTemporalRelationship(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    timeDiff: number
  ): Promise<DocumentRelationship> {
    return {
      id: `temporal_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      sourceDocument: docA,
      targetDocument: docB,
      relationshipType: 'related',
      confidence: Math.max(0.3, 1 - (timeDiff / 365)), // Confidence decreases with time
      evidence: [{
        type: 'temporal_sequence',
        text: `Published ${timeDiff} days apart`,
        location: { document: 'source', position: { start: 0, end: 0 } },
        confidence: 0.7,
        extractedAt: new Date(),
        context: 'Temporal proximity analysis'
      }],
      direction: 'bidirectional',
      strength: timeDiff < 30 ? 'strong' : timeDiff < 180 ? 'moderate' : 'weak',
      temporal: this.createTemporalAnalysis(docA, docB),
      legal: this.createLegalAnalysis(docA, docB),
      semantic: {
        topicSimilarity: 0,
        conceptualOverlap: 0,
        keywordSimilarity: 0,
        intentAlignment: 0,
        scopeRelation: 'intersecting',
        sharedConcepts: [],
        distinctiveConcepts: { source: [], target: [] }
      },
      discoveredAt: new Date()
    };
  }

  private createTemporalAnalysis(docA: LegislativeDocument, docB: LegislativeDocument): TemporalRelationship {
    const dateA = new Date(docA.date);
    const dateB = new Date(docB.date);
    const timeDiff = Math.abs(dateB.getTime() - dateA.getTime()) / (1000 * 60 * 60 * 24);
    
    return {
      chronologicalOrder: dateA < dateB ? 'before' : dateA > dateB ? 'after' : 'concurrent',
      timeDifference: timeDiff,
      effectiveOrder: 'unknown', // Would need effective dates
      publicationGap: timeDiff,
      temporalOverlap: timeDiff < 30
    };
  }

  private createLegalAnalysis(docA: LegislativeDocument, docB: LegislativeDocument): LegalRelationship {
    const hierarchyMap: Record<DocumentType, number> = {
      'lei': 3,
      'decreto': 2,
      'portaria': 1,
      'resolucao': 1,
      'instrucao_normativa': 1,
      'projeto_lei': 0,
      'medida_provisoria': 2
    };

    const levelA = hierarchyMap[docA.type] || 0;
    const levelB = hierarchyMap[docB.type] || 0;

    return {
      hierarchical: levelA > levelB ? 'superior' : levelA < levelB ? 'subordinate' : 'equal',
      jurisdiction: docA.state === docB.state ? 'same' : 'different',
      authority: docA.author === docB.author ? 'same' : 'related',
      legalEffect: 'neutral',
      bindingEffect: 'informational'
    };
  }

  private haveSimilarAuthority(docA: LegislativeDocument, docB: LegislativeDocument): boolean {
    return docA.author === docB.author || docA.state === docB.state;
  }

  private createNetworkNode(document: LegislativeDocument, relationships: DocumentRelationship[]): NetworkNode {
    const nodeRelationships = relationships.filter(rel => 
      rel.sourceDocument.id === document.id || rel.targetDocument.id === document.id
    );

    const inDegree = nodeRelationships.filter(rel => rel.targetDocument.id === document.id).length;
    const outDegree = nodeRelationships.filter(rel => rel.sourceDocument.id === document.id).length;
    const degree = inDegree + outDegree;

    return {
      id: document.id,
      document,
      position: { x: Math.random() * 1000, y: Math.random() * 1000 },
      size: Math.max(10, Math.min(50, degree * 5)),
      importance: degree / Math.max(relationships.length, 1),
      centrality: {
        degree,
        betweenness: 0, // Would calculate
        closeness: 0, // Would calculate
        eigenvector: 0 // Would calculate
      },
      cluster: 'default',
      metadata: {
        inDegree,
        outDegree,
        citationCount: outDegree,
        referencedBy: inDegree,
        documentAge: (Date.now() - new Date(document.date).getTime()) / (1000 * 60 * 60 * 24),
        influence: inDegree * 2 + outDegree
      }
    };
  }

  private createNetworkEdge(relationship: DocumentRelationship): NetworkEdge {
    const typeColors: Record<RelationshipType, string> = {
      'amends': '#ff6b6b',
      'repeals': '#ee5a6f',
      'references': '#4ecdc4',
      'implements': '#45b7d1',
      'supersedes': '#f39c12',
      'complements': '#27ae60',
      'conflicts': '#e74c3c',
      'consolidates': '#9b59b6',
      'interprets': '#16a085',
      'applies': '#2ecc71',
      'precedent': '#34495e',
      'successor': '#7f8c8d',
      'related': '#95a5a6',
      'derivative': '#f1c40f',
      'parallel': '#e67e22'
    };

    return {
      id: relationship.id,
      source: relationship.sourceDocument.id,
      target: relationship.targetDocument.id,
      relationship,
      weight: relationship.confidence,
      style: {
        color: typeColors[relationship.relationshipType] || '#95a5a6',
        width: Math.max(1, relationship.confidence * 5),
        type: relationship.direction === 'bidirectional' ? 'solid' : 'solid'
      }
    };
  }

  private applyLayout(nodes: NetworkNode[], edges: NetworkEdge[], algorithm: string): void {
    // Simplified layout - in practice would use proper graph layout algorithms
    switch (algorithm) {
      case 'hierarchical':
        this.applyHierarchicalLayout(nodes, edges);
        break;
      case 'circular':
        this.applyCircularLayout(nodes);
        break;
      case 'temporal':
        this.applyTemporalLayout(nodes);
        break;
      default:
        this.applyForceLayout(nodes, edges);
    }
  }

  private applyForceLayout(nodes: NetworkNode[], edges: NetworkEdge[]): void {
    // Simple force-directed layout simulation
    const iterations = 100;
    for (let i = 0; i < iterations; i++) {
      // Apply repulsive forces between nodes
      for (let j = 0; j < nodes.length; j++) {
        for (let k = j + 1; k < nodes.length; k++) {
          const dx = nodes[k].position.x - nodes[j].position.x;
          const dy = nodes[k].position.y - nodes[j].position.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          if (distance > 0) {
            const force = 1000 / (distance * distance);
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;
            
            nodes[j].position.x -= fx;
            nodes[j].position.y -= fy;
            nodes[k].position.x += fx;
            nodes[k].position.y += fy;
          }
        }
      }
      
      // Apply attractive forces along edges
      for (const edge of edges) {
        const sourceNode = nodes.find(n => n.id === edge.source);
        const targetNode = nodes.find(n => n.id === edge.target);
        
        if (sourceNode && targetNode) {
          const dx = targetNode.position.x - sourceNode.position.x;
          const dy = targetNode.position.y - sourceNode.position.y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          if (distance > 0) {
            const force = distance * 0.01 * edge.weight;
            const fx = (dx / distance) * force;
            const fy = (dy / distance) * force;
            
            sourceNode.position.x += fx;
            sourceNode.position.y += fy;
            targetNode.position.x -= fx;
            targetNode.position.y -= fy;
          }
        }
      }
    }
  }

  private applyHierarchicalLayout(nodes: NetworkNode[], edges: NetworkEdge[]): void {
    // Group by document type hierarchy
    const hierarchy: Record<DocumentType, number> = {
      'lei': 4,
      'decreto': 3,
      'portaria': 2,
      'resolucao': 2,
      'instrucao_normativa': 2,
      'projeto_lei': 1,
      'medida_provisoria': 3
    };

    nodes.forEach((node, index) => {
      const level = hierarchy[node.document.type] || 1;
      node.position.y = level * 200;
      node.position.x = (index % 10) * 150;
    });
  }

  private applyCircularLayout(nodes: NetworkNode[]): void {
    const radius = 300;
    const angleStep = (2 * Math.PI) / nodes.length;
    
    nodes.forEach((node, index) => {
      const angle = index * angleStep;
      node.position.x = 500 + radius * Math.cos(angle);
      node.position.y = 500 + radius * Math.sin(angle);
    });
  }

  private applyTemporalLayout(nodes: NetworkNode[]): void {
    const sortedNodes = nodes.sort((a, b) => 
      new Date(a.document.date).getTime() - new Date(b.document.date).getTime()
    );
    
    sortedNodes.forEach((node, index) => {
      node.position.x = index * 100;
      node.position.y = 300 + Math.sin(index * 0.5) * 100;
    });
  }

  private createClusters(
    documents: LegislativeDocument[],
    relationships: DocumentRelationship[],
    method: string
  ): DocumentCluster[] {
    switch (method) {
      case 'authority':
        return this.clusterByAuthority(documents);
      case 'temporal':
        return this.clusterByTime(documents);
      case 'regulatory':
        return this.clusterByRegulatory(documents);
      default:
        return this.clusterByTopic(documents);
    }
  }

  private clusterByTopic(documents: LegislativeDocument[]): DocumentCluster[] {
    const clusters: Map<string, LegislativeDocument[]> = new Map();
    
    for (const doc of documents) {
      const primaryKeyword = doc.keywords[0] || 'general';
      const cluster = clusters.get(primaryKeyword) || [];
      cluster.push(doc);
      clusters.set(primaryKeyword, cluster);
    }

    return Array.from(clusters.entries()).map(([topic, docs], index) => ({
      id: `cluster_${index}`,
      label: topic,
      documents: docs,
      centroid: docs[0], // Simplified
      cohesion: 0.7,
      separation: 0.3,
      topics: [topic],
      timespan: {
        start: new Date(Math.min(...docs.map(d => new Date(d.date).getTime()))),
        end: new Date(Math.max(...docs.map(d => new Date(d.date).getTime())))
      },
      authority: docs[0].author,
      regulatory: {
        framework: 'transport',
        domain: topic,
        complexity: 0.5
      }
    }));
  }

  private clusterByAuthority(documents: LegislativeDocument[]): DocumentCluster[] {
    const clusters: Map<string, LegislativeDocument[]> = new Map();
    
    for (const doc of documents) {
      const authority = doc.author || 'unknown';
      const cluster = clusters.get(authority) || [];
      cluster.push(doc);
      clusters.set(authority, cluster);
    }

    return Array.from(clusters.entries()).map(([authority, docs], index) => ({
      id: `authority_cluster_${index}`,
      label: authority,
      documents: docs,
      centroid: docs[0],
      cohesion: 0.8,
      separation: 0.4,
      topics: [...new Set(docs.flatMap(d => d.keywords))],
      timespan: {
        start: new Date(Math.min(...docs.map(d => new Date(d.date).getTime()))),
        end: new Date(Math.max(...docs.map(d => new Date(d.date).getTime())))
      },
      authority,
      regulatory: {
        framework: 'authority_based',
        domain: 'mixed',
        complexity: 0.6
      }
    }));
  }

  private clusterByTime(documents: LegislativeDocument[]): DocumentCluster[] {
    const yearClusters: Map<number, LegislativeDocument[]> = new Map();
    
    for (const doc of documents) {
      const year = new Date(doc.date).getFullYear();
      const cluster = yearClusters.get(year) || [];
      cluster.push(doc);
      yearClusters.set(year, cluster);
    }

    return Array.from(yearClusters.entries()).map(([year, docs], index) => ({
      id: `temporal_cluster_${index}`,
      label: `${year}`,
      documents: docs,
      centroid: docs[0],
      cohesion: 0.6,
      separation: 0.5,
      topics: [...new Set(docs.flatMap(d => d.keywords))],
      timespan: {
        start: new Date(year, 0, 1),
        end: new Date(year, 11, 31)
      },
      authority: 'mixed',
      regulatory: {
        framework: 'temporal',
        domain: 'mixed',
        complexity: 0.4
      }
    }));
  }

  private clusterByRegulatory(documents: LegislativeDocument[]): DocumentCluster[] {
    const typeClusters: Map<DocumentType, LegislativeDocument[]> = new Map();
    
    for (const doc of documents) {
      const cluster = typeClusters.get(doc.type) || [];
      cluster.push(doc);
      typeClusters.set(doc.type, cluster);
    }

    return Array.from(typeClusters.entries()).map(([type, docs], index) => ({
      id: `regulatory_cluster_${index}`,
      label: type,
      documents: docs,
      centroid: docs[0],
      cohesion: 0.9,
      separation: 0.2,
      topics: [...new Set(docs.flatMap(d => d.keywords))],
      timespan: {
        start: new Date(Math.min(...docs.map(d => new Date(d.date).getTime()))),
        end: new Date(Math.max(...docs.map(d => new Date(d.date).getTime())))
      },
      authority: 'mixed',
      regulatory: {
        framework: 'type_based',
        domain: type,
        complexity: type === 'lei' ? 0.8 : 0.5
      }
    }));
  }

  private calculateNetworkMetrics(nodes: NetworkNode[], edges: NetworkEdge[]): NetworkMetrics {
    const totalNodes = nodes.length;
    const totalEdges = edges.length;
    const density = totalNodes > 1 ? (2 * totalEdges) / (totalNodes * (totalNodes - 1)) : 0;

    // Sort nodes by degree centrality
    const centralNodes = nodes
      .sort((a, b) => b.centrality.degree - a.centrality.degree)
      .slice(0, 5)
      .map(node => ({
        nodeId: node.id,
        score: node.centrality.degree,
        type: 'degree'
      }));

    // Sort by influence
    const influentialDocuments = nodes
      .sort((a, b) => b.metadata.influence - a.metadata.influence)
      .slice(0, 5)
      .map(node => ({
        document: node.document,
        influence: node.metadata.influence
      }));

    return {
      totalNodes,
      totalEdges,
      density,
      averagePathLength: 0, // Would calculate
      clusteringCoefficient: 0, // Would calculate
      modularity: 0, // Would calculate
      components: 1, // Simplified
      diameter: 0, // Would calculate
      centralNodes,
      influentialDocuments
    };
  }

  private buildNetworkTimeline(
    documents: LegislativeDocument[],
    relationships: DocumentRelationship[]
  ): NetworkTimeline {
    const events = documents.map(doc => ({
      date: new Date(doc.date),
      type: 'creation' as const,
      documents: [doc.id],
      description: `${doc.type} ${doc.title} published`,
      impact: 'medium' as const
    }));

    // Add relationship events
    for (const rel of relationships) {
      if (rel.relationshipType === 'amends' || rel.relationshipType === 'repeals') {
        events.push({
          date: new Date(rel.sourceDocument.date),
          type: rel.relationshipType === 'amends' ? 'amendment' : 'repeal',
          documents: [rel.sourceDocument.id, rel.targetDocument.id],
          description: `${rel.sourceDocument.title} ${rel.relationshipType} ${rel.targetDocument.title}`,
          impact: 'high'
        });
      }
    }

    // Sort events by date
    events.sort((a, b) => a.date.getTime() - b.date.getTime());

    return {
      events,
      evolutionPhases: [] // Would implement phase detection
    };
  }

  private getEmptyMetrics(): NetworkMetrics {
    return {
      totalNodes: 0,
      totalEdges: 0,
      density: 0,
      averagePathLength: 0,
      clusteringCoefficient: 0,
      modularity: 0,
      components: 0,
      diameter: 0,
      centralNodes: [],
      influentialDocuments: []
    };
  }

  // Export methods

  private exportToGraphML(network: DocumentNetwork): string {
    let graphml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    graphml += '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n';
    graphml += '  <graph id="document-network" edgedefault="directed">\n';
    
    // Nodes
    for (const node of network.nodes) {
      graphml += `    <node id="${node.id}">\n`;
      graphml += `      <data key="title">${node.document.title}</data>\n`;
      graphml += `      <data key="type">${node.document.type}</data>\n`;
      graphml += `      <data key="author">${node.document.author}</data>\n`;
      graphml += '    </node>\n';
    }
    
    // Edges
    for (const edge of network.edges) {
      graphml += `    <edge source="${edge.source}" target="${edge.target}">\n`;
      graphml += `      <data key="relationship">${edge.relationship.relationshipType}</data>\n`;
      graphml += `      <data key="confidence">${edge.relationship.confidence}</data>\n`;
      graphml += '    </edge>\n';
    }
    
    graphml += '  </graph>\n';
    graphml += '</graphml>';
    return graphml;
  }

  private exportToGEXF(network: DocumentNetwork): string {
    // GEXF format implementation
    return JSON.stringify(network); // Simplified
  }

  private exportToJSON(network: DocumentNetwork): string {
    return JSON.stringify(network, null, 2);
  }

  private exportToCSV(network: DocumentNetwork): string {
    let csv = 'source,target,relationship,confidence,strength\n';
    for (const edge of network.edges) {
      csv += `${edge.source},${edge.target},${edge.relationship.relationshipType},${edge.relationship.confidence},${edge.relationship.strength}\n`;
    }
    return csv;
  }

  private exportToCytoscape(network: DocumentNetwork): string {
    const cytoscapeData = {
      elements: {
        nodes: network.nodes.map(node => ({
          data: {
            id: node.id,
            title: node.document.title,
            type: node.document.type,
            importance: node.importance
          },
          position: node.position
        })),
        edges: network.edges.map(edge => ({
          data: {
            id: edge.id,
            source: edge.source,
            target: edge.target,
            relationship: edge.relationship.relationshipType,
            confidence: edge.relationship.confidence
          }
        }))
      }
    };
    
    return JSON.stringify(cytoscapeData, null, 2);
  }
}

export const documentRelationshipService = DocumentRelationshipService.getInstance();