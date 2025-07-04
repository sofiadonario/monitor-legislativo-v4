/**
 * Document Comparison Service
 * Advanced document comparison with diff algorithms, semantic analysis, and legal text comparison
 */
import { LegislativeDocument, DocumentType } from '../types';

export interface DocumentComparison {
  id: string;
  documentA: LegislativeDocument;
  documentB: LegislativeDocument;
  comparisonType: 'textual' | 'semantic' | 'structural' | 'legal';
  similarity: number;
  differences: DocumentDifference[];
  semanticAnalysis: SemanticComparison;
  structuralAnalysis: StructuralComparison;
  legalAnalysis: LegalComparison;
  timeline: ComparisonTimeline;
  exportFormats: ComparisonExportFormats;
  createdAt: Date;
  updatedAt: Date;
}

export interface DocumentDifference {
  id: string;
  type: 'addition' | 'deletion' | 'modification' | 'move';
  severity: 'minor' | 'moderate' | 'major' | 'critical';
  category: 'content' | 'structure' | 'metadata' | 'legal';
  position: {
    documentA?: { start: number; end: number; line?: number };
    documentB?: { start: number; end: number; line?: number };
  };
  originalText?: string;
  newText?: string;
  context: string;
  explanation: string;
  legalImplications?: string[];
  confidence: number;
}

export interface SemanticComparison {
  conceptualSimilarity: number;
  topicOverlap: number;
  intentAlignment: number;
  scopeComparison: {
    broadening: number;
    narrowing: number;
    unchanged: number;
  };
  keywordAnalysis: {
    common: string[];
    uniqueToA: string[];
    uniqueToB: string[];
    modified: Array<{ from: string; to: string; reason: string }>;
  };
  semanticShifts: Array<{
    concept: string;
    shift: 'emphasis' | 'definition' | 'scope' | 'application';
    description: string;
    impact: 'low' | 'medium' | 'high';
  }>;
}

export interface StructuralComparison {
  organizationSimilarity: number;
  sectionsComparison: {
    added: string[];
    removed: string[];
    modified: Array<{ original: string; new: string; changeType: string }>;
    reordered: Array<{ section: string; fromPosition: number; toPosition: number }>;
  };
  hierarchyChanges: Array<{
    type: 'promotion' | 'demotion' | 'restructure';
    element: string;
    description: string;
  }>;
  formatChanges: Array<{
    type: 'numbering' | 'referencing' | 'citation' | 'layout';
    description: string;
    impact: string;
  }>;
}

export interface LegalComparison {
  jurisdictionAlignment: number;
  authorityConsistency: number;
  regulatoryImpact: {
    newObligations: string[];
    removedObligations: string[];
    modifiedObligations: Array<{ original: string; modified: string; impact: string }>;
  };
  complianceImplications: Array<{
    area: string;
    implication: string;
    severity: 'informational' | 'advisory' | 'mandatory' | 'critical';
    affectedParties: string[];
  }>;
  precedentAnalysis: {
    newPrecedents: string[];
    conflictingPrecedents: string[];
    clarifiedPrecedents: string[];
  };
  implementationRequirements: Array<{
    requirement: string;
    deadline?: Date;
    responsibleParty: string;
    complexity: 'simple' | 'moderate' | 'complex';
  }>;
}

export interface ComparisonTimeline {
  events: Array<{
    date: Date;
    type: 'creation' | 'amendment' | 'review' | 'publication' | 'enforcement';
    document: 'A' | 'B' | 'both';
    description: string;
    significance: 'low' | 'medium' | 'high';
  }>;
  relationshipType: 'amendment' | 'replacement' | 'supplement' | 'repeal' | 'independent';
  genealogy: Array<{
    document: string;
    relationship: string;
    date: Date;
  }>;
}

export interface ComparisonExportFormats {
  unifiedDiff: string;
  sideBySide: string;
  redline: string;
  summary: string;
  legalMemo: string;
  changeLog: string;
}

export interface ComparisonMetrics {
  textualSimilarity: number;
  structuralSimilarity: number;
  semanticSimilarity: number;
  legalContinuity: number;
  overallSimilarity: number;
  changeComplexity: number;
  reviewRecommendation: 'accept' | 'review' | 'flag' | 'reject';
}

export class DocumentComparisonService {
  private static instance: DocumentComparisonService;
  private comparisons: Map<string, DocumentComparison> = new Map();
  private diffAlgorithms: Map<string, (a: string, b: string) => any> = new Map();

  private constructor() {
    this.initializeDiffAlgorithms();
  }

  public static getInstance(): DocumentComparisonService {
    if (!DocumentComparisonService.instance) {
      DocumentComparisonService.instance = new DocumentComparisonService();
    }
    return DocumentComparisonService.instance;
  }

  /**
   * Compare two documents with comprehensive analysis
   */
  public async compareDocuments(
    documentA: LegislativeDocument,
    documentB: LegislativeDocument,
    options: {
      comparisonType?: 'textual' | 'semantic' | 'structural' | 'legal' | 'comprehensive';
      includeSemanticAnalysis?: boolean;
      includeLegalAnalysis?: boolean;
      algorithm?: 'myers' | 'patience' | 'histogram' | 'minimal';
      contextLines?: number;
      ignoreWhitespace?: boolean;
      ignoreCase?: boolean;
    } = {}
  ): Promise<DocumentComparison> {
    const comparisonId = `comparison_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const {
      comparisonType = 'comprehensive',
      includeSemanticAnalysis = true,
      includeLegalAnalysis = true,
      algorithm = 'myers',
      contextLines = 3,
      ignoreWhitespace = false,
      ignoreCase = false
    } = options;

    // Perform textual comparison
    const differences = await this.performTextualComparison(
      documentA, 
      documentB, 
      { algorithm, contextLines, ignoreWhitespace, ignoreCase }
    );

    // Calculate similarity metrics
    const metrics = this.calculateComparisonMetrics(documentA, documentB, differences);

    // Perform semantic analysis if requested
    const semanticAnalysis = includeSemanticAnalysis 
      ? await this.performSemanticAnalysis(documentA, documentB, differences)
      : this.getEmptySemanticAnalysis();

    // Perform structural analysis
    const structuralAnalysis = await this.performStructuralAnalysis(documentA, documentB);

    // Perform legal analysis if requested
    const legalAnalysis = includeLegalAnalysis
      ? await this.performLegalAnalysis(documentA, documentB, differences)
      : this.getEmptyLegalAnalysis();

    // Build timeline
    const timeline = this.buildComparisonTimeline(documentA, documentB);

    // Generate export formats
    const exportFormats = this.generateExportFormats(documentA, documentB, differences, {
      semantic: semanticAnalysis,
      structural: structuralAnalysis,
      legal: legalAnalysis
    });

    const comparison: DocumentComparison = {
      id: comparisonId,
      documentA,
      documentB,
      comparisonType,
      similarity: metrics.overallSimilarity,
      differences,
      semanticAnalysis,
      structuralAnalysis,
      legalAnalysis,
      timeline,
      exportFormats,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.comparisons.set(comparisonId, comparison);
    return comparison;
  }

  /**
   * Get comparison by ID
   */
  public getComparison(id: string): DocumentComparison | null {
    return this.comparisons.get(id) || null;
  }

  /**
   * Get all comparisons for a document
   */
  public getDocumentComparisons(documentId: string): DocumentComparison[] {
    return Array.from(this.comparisons.values())
      .filter(comparison => 
        comparison.documentA.id === documentId || 
        comparison.documentB.id === documentId
      )
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Batch compare multiple documents
   */
  public async batchCompareDocuments(
    documents: LegislativeDocument[],
    options: {
      comparisonMatrix?: boolean;
      similarityThreshold?: number;
      maxComparisons?: number;
    } = {}
  ): Promise<{
    comparisons: DocumentComparison[];
    matrix?: number[][];
    clusters?: Array<{ documents: LegislativeDocument[]; similarity: number }>;
  }> {
    const {
      comparisonMatrix = false,
      similarityThreshold = 0.7,
      maxComparisons = 100
    } = options;

    const comparisons: DocumentComparison[] = [];
    const matrix: number[][] = [];
    let comparisonCount = 0;

    for (let i = 0; i < documents.length && comparisonCount < maxComparisons; i++) {
      const row: number[] = [];
      for (let j = 0; j < documents.length && comparisonCount < maxComparisons; j++) {
        if (i === j) {
          row.push(1.0);
        } else if (i < j) {
          const comparison = await this.compareDocuments(documents[i], documents[j], {
            comparisonType: 'textual', // Lightweight for batch operations
            includeSemanticAnalysis: false,
            includeLegalAnalysis: false
          });
          
          comparisons.push(comparison);
          row.push(comparison.similarity);
          comparisonCount++;
        } else {
          row.push(matrix[j][i]); // Use symmetric value
        }
      }
      if (comparisonMatrix) matrix.push(row);
    }

    // Find clusters if similarity threshold is provided
    const clusters = this.findDocumentClusters(documents, matrix, similarityThreshold);

    return {
      comparisons,
      matrix: comparisonMatrix ? matrix : undefined,
      clusters
    };
  }

  /**
   * Generate comparison summary report
   */
  public generateComparisonReport(
    comparison: DocumentComparison,
    format: 'executive' | 'detailed' | 'technical' | 'legal' = 'detailed'
  ): string {
    switch (format) {
      case 'executive':
        return this.generateExecutiveSummary(comparison);
      case 'detailed':
        return this.generateDetailedReport(comparison);
      case 'technical':
        return this.generateTechnicalReport(comparison);
      case 'legal':
        return this.generateLegalReport(comparison);
      default:
        return this.generateDetailedReport(comparison);
    }
  }

  // Private helper methods

  private initializeDiffAlgorithms(): void {
    // Initialize diff algorithms
    this.diffAlgorithms.set('myers', this.myersDiff.bind(this));
    this.diffAlgorithms.set('patience', this.patienceDiff.bind(this));
    this.diffAlgorithms.set('histogram', this.histogramDiff.bind(this));
    this.diffAlgorithms.set('minimal', this.minimalDiff.bind(this));
  }

  private async performTextualComparison(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    options: any
  ): Promise<DocumentDifference[]> {
    const textA = this.normalizeDocumentText(docA, options);
    const textB = this.normalizeDocumentText(docB, options);
    
    const algorithm = this.diffAlgorithms.get(options.algorithm) || this.myersDiff;
    const rawDiff = algorithm(textA, textB);
    
    return this.processDiffResults(rawDiff, textA, textB, options.contextLines);
  }

  private normalizeDocumentText(document: LegislativeDocument, options: any): string {
    let text = `${document.title}\n\n${document.summary}`;
    
    if (options.ignoreCase) {
      text = text.toLowerCase();
    }
    
    if (options.ignoreWhitespace) {
      text = text.replace(/\s+/g, ' ').trim();
    }
    
    return text;
  }

  private myersDiff(textA: string, textB: string): any {
    // Simplified Myers diff algorithm implementation
    const linesA = textA.split('\n');
    const linesB = textB.split('\n');
    const diffs = [];
    
    let i = 0, j = 0;
    while (i < linesA.length || j < linesB.length) {
      if (i >= linesA.length) {
        diffs.push({ type: 'addition', line: linesB[j], lineNum: j });
        j++;
      } else if (j >= linesB.length) {
        diffs.push({ type: 'deletion', line: linesA[i], lineNum: i });
        i++;
      } else if (linesA[i] === linesB[j]) {
        diffs.push({ type: 'unchanged', line: linesA[i], lineNum: i });
        i++;
        j++;
      } else {
        // Simple heuristic: assume single line change
        diffs.push({ 
          type: 'modification', 
          oldLine: linesA[i], 
          newLine: linesB[j], 
          lineNum: i 
        });
        i++;
        j++;
      }
    }
    
    return diffs;
  }

  private patienceDiff(textA: string, textB: string): any {
    // Placeholder for patience diff - would implement actual algorithm
    return this.myersDiff(textA, textB);
  }

  private histogramDiff(textA: string, textB: string): any {
    // Placeholder for histogram diff - would implement actual algorithm
    return this.myersDiff(textA, textB);
  }

  private minimalDiff(textA: string, textB: string): any {
    // Placeholder for minimal diff - would implement actual algorithm
    return this.myersDiff(textA, textB);
  }

  private processDiffResults(rawDiff: any[], textA: string, textB: string, contextLines: number): DocumentDifference[] {
    const differences: DocumentDifference[] = [];
    
    for (let i = 0; i < rawDiff.length; i++) {
      const diff = rawDiff[i];
      
      if (diff.type !== 'unchanged') {
        const difference: DocumentDifference = {
          id: `diff_${i}`,
          type: diff.type as DocumentDifference['type'],
          severity: this.assessDifferenceSeverity(diff),
          category: this.categorizeDifference(diff),
          position: {
            documentA: diff.type !== 'addition' ? { start: 0, end: 0, line: diff.lineNum } : undefined,
            documentB: diff.type !== 'deletion' ? { start: 0, end: 0, line: diff.lineNum } : undefined
          },
          originalText: diff.oldLine || diff.line,
          newText: diff.newLine || diff.line,
          context: this.extractContext(rawDiff, i, contextLines),
          explanation: this.generateDifferenceExplanation(diff),
          confidence: 0.9
        };
        
        differences.push(difference);
      }
    }
    
    return differences;
  }

  private assessDifferenceSeverity(diff: any): DocumentDifference['severity'] {
    // Simple heuristic - in practice would be more sophisticated
    if (diff.type === 'modification') {
      const oldLength = (diff.oldLine || '').length;
      const newLength = (diff.newLine || '').length;
      const changeRatio = Math.abs(oldLength - newLength) / Math.max(oldLength, newLength, 1);
      
      if (changeRatio > 0.8) return 'critical';
      if (changeRatio > 0.5) return 'major';
      if (changeRatio > 0.2) return 'moderate';
      return 'minor';
    }
    
    return diff.type === 'addition' || diff.type === 'deletion' ? 'moderate' : 'minor';
  }

  private categorizeDifference(diff: any): DocumentDifference['category'] {
    // Simple categorization - would be more sophisticated in practice
    const text = diff.oldLine || diff.newLine || diff.line || '';
    
    if (text.match(/artigo|parágrafo|inciso|alínea/i)) return 'structure';
    if (text.match(/autor|data|número/i)) return 'metadata';
    if (text.match(/deve|obrigatório|proibido|permitido/i)) return 'legal';
    
    return 'content';
  }

  private extractContext(diffs: any[], index: number, contextLines: number): string {
    const start = Math.max(0, index - contextLines);
    const end = Math.min(diffs.length, index + contextLines + 1);
    
    return diffs.slice(start, end)
      .map(d => d.line || d.oldLine || d.newLine)
      .filter(Boolean)
      .join('\n');
  }

  private generateDifferenceExplanation(diff: any): string {
    switch (diff.type) {
      case 'addition':
        return `New content added: "${diff.line}"`;
      case 'deletion':
        return `Content removed: "${diff.line}"`;
      case 'modification':
        return `Content changed from "${diff.oldLine}" to "${diff.newLine}"`;
      default:
        return 'Content unchanged';
    }
  }

  private async performSemanticAnalysis(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    differences: DocumentDifference[]
  ): Promise<SemanticComparison> {
    // Extract keywords from both documents
    const keywordsA = new Set(docA.keywords.map(k => k.toLowerCase()));
    const keywordsB = new Set(docB.keywords.map(k => k.toLowerCase()));
    
    const common = Array.from(keywordsA).filter(k => keywordsB.has(k));
    const uniqueToA = Array.from(keywordsA).filter(k => !keywordsB.has(k));
    const uniqueToB = Array.from(keywordsB).filter(k => !keywordsA.has(k));
    
    const conceptualSimilarity = common.length / Math.max(keywordsA.size, keywordsB.size, 1);
    const topicOverlap = common.length / (keywordsA.size + keywordsB.size - common.length);
    
    return {
      conceptualSimilarity,
      topicOverlap,
      intentAlignment: 0.8, // Placeholder
      scopeComparison: {
        broadening: uniqueToB.length / Math.max(keywordsB.size, 1),
        narrowing: uniqueToA.length / Math.max(keywordsA.size, 1),
        unchanged: common.length / Math.max(keywordsA.size, keywordsB.size, 1)
      },
      keywordAnalysis: {
        common,
        uniqueToA,
        uniqueToB,
        modified: [] // Would implement keyword modification detection
      },
      semanticShifts: [] // Would implement semantic shift detection
    };
  }

  private async performStructuralAnalysis(
    docA: LegislativeDocument,
    docB: LegislativeDocument
  ): Promise<StructuralComparison> {
    // Placeholder implementation - would analyze document structure
    return {
      organizationSimilarity: 0.85,
      sectionsComparison: {
        added: [],
        removed: [],
        modified: [],
        reordered: []
      },
      hierarchyChanges: [],
      formatChanges: []
    };
  }

  private async performLegalAnalysis(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    differences: DocumentDifference[]
  ): Promise<LegalComparison> {
    // Analyze legal implications of differences
    const legalDifferences = differences.filter(d => d.category === 'legal');
    
    return {
      jurisdictionAlignment: docA.state === docB.state ? 1.0 : 0.5,
      authorityConsistency: docA.author === docB.author ? 1.0 : 0.7,
      regulatoryImpact: {
        newObligations: [],
        removedObligations: [],
        modifiedObligations: []
      },
      complianceImplications: [],
      precedentAnalysis: {
        newPrecedents: [],
        conflictingPrecedents: [],
        clarifiedPrecedents: []
      },
      implementationRequirements: []
    };
  }

  private getEmptySemanticAnalysis(): SemanticComparison {
    return {
      conceptualSimilarity: 0,
      topicOverlap: 0,
      intentAlignment: 0,
      scopeComparison: { broadening: 0, narrowing: 0, unchanged: 0 },
      keywordAnalysis: { common: [], uniqueToA: [], uniqueToB: [], modified: [] },
      semanticShifts: []
    };
  }

  private getEmptyLegalAnalysis(): LegalComparison {
    return {
      jurisdictionAlignment: 0,
      authorityConsistency: 0,
      regulatoryImpact: { newObligations: [], removedObligations: [], modifiedObligations: [] },
      complianceImplications: [],
      precedentAnalysis: { newPrecedents: [], conflictingPrecedents: [], clarifiedPrecedents: [] },
      implementationRequirements: []
    };
  }

  private calculateComparisonMetrics(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    differences: DocumentDifference[]
  ): ComparisonMetrics {
    const totalDifferences = differences.length;
    const criticalDifferences = differences.filter(d => d.severity === 'critical').length;
    const majorDifferences = differences.filter(d => d.severity === 'major').length;
    
    const textualSimilarity = Math.max(0, 1 - (totalDifferences / 100)); // Simplified
    const changeComplexity = (criticalDifferences * 3 + majorDifferences * 2 + totalDifferences) / 100;
    
    let reviewRecommendation: ComparisonMetrics['reviewRecommendation'] = 'accept';
    if (criticalDifferences > 0) reviewRecommendation = 'reject';
    else if (majorDifferences > 3) reviewRecommendation = 'flag';
    else if (totalDifferences > 10) reviewRecommendation = 'review';
    
    return {
      textualSimilarity,
      structuralSimilarity: 0.8, // Placeholder
      semanticSimilarity: 0.7, // Placeholder
      legalContinuity: 0.9, // Placeholder
      overallSimilarity: (textualSimilarity + 0.8 + 0.7 + 0.9) / 4,
      changeComplexity,
      reviewRecommendation
    };
  }

  private buildComparisonTimeline(
    docA: LegislativeDocument,
    docB: LegislativeDocument
  ): ComparisonTimeline {
    const events = [
      {
        date: new Date(docA.date),
        type: 'creation' as const,
        document: 'A' as const,
        description: `Document A created: ${docA.title}`,
        significance: 'high' as const
      },
      {
        date: new Date(docB.date),
        type: 'creation' as const,
        document: 'B' as const,
        description: `Document B created: ${docB.title}`,
        significance: 'high' as const
      }
    ].sort((a, b) => a.date.getTime() - b.date.getTime());
    
    return {
      events,
      relationshipType: 'independent', // Would determine actual relationship
      genealogy: []
    };
  }

  private generateExportFormats(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    differences: DocumentDifference[],
    analyses: any
  ): ComparisonExportFormats {
    return {
      unifiedDiff: this.generateUnifiedDiff(docA, docB, differences),
      sideBySide: this.generateSideBySide(docA, docB, differences),
      redline: this.generateRedline(docA, docB, differences),
      summary: this.generateSummary(docA, docB, differences, analyses),
      legalMemo: this.generateLegalMemo(docA, docB, differences, analyses),
      changeLog: this.generateChangeLog(differences)
    };
  }

  private generateUnifiedDiff(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    differences: DocumentDifference[]
  ): string {
    let diff = `--- ${docA.title}\n`;
    diff += `+++ ${docB.title}\n`;
    
    differences.forEach(d => {
      switch (d.type) {
        case 'deletion':
          diff += `- ${d.originalText}\n`;
          break;
        case 'addition':
          diff += `+ ${d.newText}\n`;
          break;
        case 'modification':
          diff += `- ${d.originalText}\n`;
          diff += `+ ${d.newText}\n`;
          break;
      }
    });
    
    return diff;
  }

  private generateSideBySide(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    differences: DocumentDifference[]
  ): string {
    // Simplified side-by-side format
    return `${docA.title} | ${docB.title}\n${'='.repeat(80)}\n`;
  }

  private generateRedline(
    docA: LegislativeDocument,
    docB: LegislativeDocument,
    differences: DocumentDifference[]
  ): string {
    // Simplified redline format
    let redline = docA.summary;
    
    differences.forEach(d => {
      switch (d.type) {
        case 'deletion':
          redline = redline.replace(d.originalText || '', `[DELETED: ${d.originalText}]`);
          break;
        case 'addition':
          redline += `[ADDED: ${d.newText}]`;
          break;
        case 'modification':
          redline = redline.replace(d.originalText || '', `[CHANGED: ${d.originalText} → ${d.newText}]`);
          break;
      }
    });
    
    return redline;
  }

  private generateSummary(docA: LegislativeDocument, docB: LegislativeDocument, differences: DocumentDifference[], analyses: any): string {
    const summary = `Document Comparison Summary\n${'='.repeat(30)}\n\n`;
    return summary + `Compared: ${docA.title} vs ${docB.title}\n` +
           `Total differences: ${differences.length}\n` +
           `Major changes: ${differences.filter(d => d.severity === 'major' || d.severity === 'critical').length}\n`;
  }

  private generateLegalMemo(docA: LegislativeDocument, docB: LegislativeDocument, differences: DocumentDifference[], analyses: any): string {
    return `LEGAL MEMORANDUM\n\nComparison of ${docA.title} and ${docB.title}\n\n` +
           `This memorandum analyzes the differences between the two documents...\n`;
  }

  private generateChangeLog(differences: DocumentDifference[]): string {
    let log = `CHANGE LOG\n${'='.repeat(10)}\n\n`;
    
    differences.forEach((d, i) => {
      log += `${i + 1}. ${d.type.toUpperCase()}: ${d.explanation}\n`;
      log += `   Severity: ${d.severity}\n`;
      log += `   Category: ${d.category}\n\n`;
    });
    
    return log;
  }

  private findDocumentClusters(
    documents: LegislativeDocument[],
    matrix: number[][],
    threshold: number
  ): Array<{ documents: LegislativeDocument[]; similarity: number }> {
    const clusters = [];
    const visited = new Set<number>();
    
    for (let i = 0; i < documents.length; i++) {
      if (visited.has(i)) continue;
      
      const cluster = [documents[i]];
      visited.add(i);
      let totalSimilarity = 0;
      let comparisons = 0;
      
      for (let j = i + 1; j < documents.length; j++) {
        if (matrix[i][j] >= threshold) {
          cluster.push(documents[j]);
          visited.add(j);
          totalSimilarity += matrix[i][j];
          comparisons++;
        }
      }
      
      if (cluster.length > 1) {
        clusters.push({
          documents: cluster,
          similarity: comparisons > 0 ? totalSimilarity / comparisons : 0
        });
      }
    }
    
    return clusters.sort((a, b) => b.similarity - a.similarity);
  }

  private generateExecutiveSummary(comparison: DocumentComparison): string {
    return `EXECUTIVE SUMMARY\n\nDocument Comparison: ${comparison.documentA.title} vs ${comparison.documentB.title}\n` +
           `Overall Similarity: ${(comparison.similarity * 100).toFixed(1)}%\n` +
           `Key Changes: ${comparison.differences.filter(d => d.severity === 'major' || d.severity === 'critical').length}\n`;
  }

  private generateDetailedReport(comparison: DocumentComparison): string {
    let report = `DETAILED COMPARISON REPORT\n${'='.repeat(30)}\n\n`;
    report += `Document A: ${comparison.documentA.title}\n`;
    report += `Document B: ${comparison.documentB.title}\n`;
    report += `Comparison Type: ${comparison.comparisonType}\n`;
    report += `Overall Similarity: ${(comparison.similarity * 100).toFixed(1)}%\n\n`;
    
    report += `DIFFERENCES (${comparison.differences.length} total):\n`;
    comparison.differences.forEach((diff, i) => {
      report += `${i + 1}. ${diff.explanation} (${diff.severity})\n`;
    });
    
    return report;
  }

  private generateTechnicalReport(comparison: DocumentComparison): string {
    return `TECHNICAL COMPARISON REPORT\n\nAlgorithm: ${comparison.comparisonType}\n` +
           `Processing Time: ${comparison.updatedAt.getTime() - comparison.createdAt.getTime()}ms\n` +
           `Confidence Metrics: Available\n`;
  }

  private generateLegalReport(comparison: DocumentComparison): string {
    const legal = comparison.legalAnalysis;
    return `LEGAL ANALYSIS REPORT\n\nJurisdiction Alignment: ${(legal.jurisdictionAlignment * 100).toFixed(1)}%\n` +
           `Authority Consistency: ${(legal.authorityConsistency * 100).toFixed(1)}%\n` +
           `Compliance Implications: ${legal.complianceImplications.length}\n`;
  }
}

export const documentComparisonService = DocumentComparisonService.getInstance();