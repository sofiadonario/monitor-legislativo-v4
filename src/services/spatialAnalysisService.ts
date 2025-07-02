/**
 * SpatialAnalysisService
 * Provides clustering, regional analysis, and spatial statistics for Brazilian legislative documents
 */
import { DocumentLocation, Coordinates, DocumentType, Municipality, StateData } from '../types';

export interface DocumentCluster {
  id: string;
  center: Coordinates;
  radius: number;
  documents: DocumentLocation[];
  density: number;
  dominantType: DocumentType;
  weight: number;
}

export interface RegionalStatistics {
  stateId: string;
  stateName: string;
  municipalityCount: number;
  totalDocuments: number;
  documentsByType: Record<DocumentType, number>;
  averageConfidence: number;
  precisionDistribution: Record<string, number>;
  topMunicipalities: Array<{
    id: string;
    name: string;
    documentCount: number;
  }>;
  documentDensity: number; // documents per km²
  coverage: number; // percentage of municipalities with documents
}

export interface SpatialHotspot {
  id: string;
  center: Coordinates;
  radius: number;
  significance: number;
  documentCount: number;
  zScore: number;
  pValue: number;
  type: 'hot' | 'cold';
}

export interface TransportCorridorAnalysis {
  corridorId: string;
  name: string;
  totalDocuments: number;
  documentsByType: Record<DocumentType, number>;
  averageDistance: number; // average distance from corridor
  municipalitiesAffected: string[];
  regulatoryComplexity: number; // 0-1 score
}

export class SpatialAnalysisService {
  private static instance: SpatialAnalysisService;

  private constructor() {}

  public static getInstance(): SpatialAnalysisService {
    if (!SpatialAnalysisService.instance) {
      SpatialAnalysisService.instance = new SpatialAnalysisService();
    }
    return SpatialAnalysisService.instance;
  }

  /**
   * Cluster documents using DBSCAN algorithm
   */
  public clusterDocuments(
    documents: DocumentLocation[],
    maxDistance: number = 50, // km
    minPoints: number = 3
  ): DocumentCluster[] {
    if (documents.length === 0) return [];

    const clusters: DocumentCluster[] = [];
    const visited = new Set<string>();
    const clustered = new Set<string>();

    for (const doc of documents) {
      if (visited.has(doc.urn)) continue;
      visited.add(doc.urn);

      const neighbors = this.getNeighbors(doc, documents, maxDistance);
      
      if (neighbors.length >= minPoints) {
        const cluster = this.expandCluster(doc, neighbors, documents, maxDistance, minPoints, visited, clustered);
        if (cluster.documents.length > 0) {
          clusters.push(cluster);
        }
      }
    }

    return clusters;
  }

  /**
   * Calculate regional statistics for Brazilian states
   */
  public calculateRegionalStatistics(
    documents: DocumentLocation[],
    states: StateData[],
    municipalities: Municipality[]
  ): RegionalStatistics[] {
    const stateStats: RegionalStatistics[] = [];

    for (const state of states) {
      const stateDocs = documents.filter(doc => doc.state === state.abbreviation);
      const stateMunicipalities = municipalities.filter(muni => muni.stateId === state.id);
      
      // Calculate document type distribution
      const documentsByType = stateDocs.reduce((acc, doc) => {
        acc[doc.type] = (acc[doc.type] || 0) + 1;
        return acc;
      }, {} as Record<DocumentType, number>);

      // Calculate precision distribution
      const precisionDistribution = stateDocs.reduce((acc, doc) => {
        acc[doc.precision] = (acc[doc.precision] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      // Calculate average confidence
      const averageConfidence = stateDocs.length > 0 
        ? stateDocs.reduce((sum, doc) => sum + doc.confidence, 0) / stateDocs.length
        : 0;

      // Find top municipalities by document count
      const municipalityDocCounts = stateDocs.reduce((acc, doc) => {
        acc[doc.municipality] = (acc[doc.municipality] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);

      const topMunicipalities = Object.entries(municipalityDocCounts)
        .map(([name, count]) => ({ 
          id: name, 
          name, 
          documentCount: count 
        }))
        .sort((a, b) => b.documentCount - a.documentCount)
        .slice(0, 5);

      // Calculate density and coverage
      const documentDensity = state.area ? stateDocs.length / state.area : 0;
      const municipalitiesWithDocs = new Set(stateDocs.map(doc => doc.municipality)).size;
      const coverage = stateMunicipalities.length > 0 
        ? municipalitiesWithDocs / stateMunicipalities.length 
        : 0;

      stateStats.push({
        stateId: state.id,
        stateName: state.name,
        municipalityCount: stateMunicipalities.length,
        totalDocuments: stateDocs.length,
        documentsByType,
        averageConfidence,
        precisionDistribution,
        topMunicipalities,
        documentDensity,
        coverage
      });
    }

    return stateStats.sort((a, b) => b.totalDocuments - a.totalDocuments);
  }

  /**
   * Identify spatial hotspots using Getis-Ord Gi* statistic
   */
  public identifyHotspots(
    documents: DocumentLocation[],
    searchRadius: number = 100 // km
  ): SpatialHotspot[] {
    if (documents.length < 10) return [];

    const hotspots: SpatialHotspot[] = [];
    const gridSize = 0.5; // degrees
    const bounds = this.calculateBounds(documents);

    // Create grid points for analysis
    for (let lat = bounds.south; lat <= bounds.north; lat += gridSize) {
      for (let lng = bounds.west; lng <= bounds.east; lng += gridSize) {
        const point = { lat, lng };
        const nearbyDocs = documents.filter(doc => 
          this.calculateDistance(point, doc.coordinates) <= searchRadius
        );

        if (nearbyDocs.length >= 5) {
          const giStat = this.calculateGiStatistic(point, documents, searchRadius);
          
          if (Math.abs(giStat.zScore) >= 1.96) { // 95% confidence
            hotspots.push({
              id: `hotspot_${lat}_${lng}`,
              center: point,
              radius: searchRadius,
              significance: Math.abs(giStat.zScore),
              documentCount: nearbyDocs.length,
              zScore: giStat.zScore,
              pValue: giStat.pValue,
              type: giStat.zScore > 0 ? 'hot' : 'cold'
            });
          }
        }
      }
    }

    return hotspots.sort((a, b) => b.significance - a.significance);
  }

  /**
   * Analyze transport corridor regulatory patterns
   */
  public analyzeTransportCorridors(
    documents: DocumentLocation[],
    corridorDistance: number = 25 // km from major routes
  ): TransportCorridorAnalysis[] {
    // Major Brazilian transport corridors (simplified)
    const corridors = [
      {
        id: 'br-101',
        name: 'BR-101 (Rio-Bahia)',
        route: [
          { lat: -22.9068, lng: -43.1729 },
          { lat: -20.3155, lng: -40.3128 },
          { lat: -16.6869, lng: -39.2091 },
          { lat: -12.9714, lng: -38.5014 }
        ]
      },
      {
        id: 'br-116',
        name: 'BR-116 (Dutra)',
        route: [
          { lat: -23.5505, lng: -46.6333 },
          { lat: -22.9068, lng: -43.1729 }
        ]
      },
      {
        id: 'tiete-parana',
        name: 'Hidrovia Tietê-Paraná',
        route: [
          { lat: -23.5505, lng: -46.6333 },
          { lat: -22.7295, lng: -47.6307 },
          { lat: -20.4697, lng: -54.6201 }
        ]
      }
    ];

    const analyses: TransportCorridorAnalysis[] = [];

    for (const corridor of corridors) {
      const corridorDocs = documents.filter(doc => 
        this.isNearCorridor(doc.coordinates, corridor.route, corridorDistance)
      );

      if (corridorDocs.length === 0) continue;

      const documentsByType = corridorDocs.reduce((acc, doc) => {
        acc[doc.type] = (acc[doc.type] || 0) + 1;
        return acc;
      }, {} as Record<DocumentType, number>);

      const averageDistance = corridorDocs.reduce((sum, doc) => 
        sum + this.distanceToRoute(doc.coordinates, corridor.route), 0
      ) / corridorDocs.length;

      const municipalitiesAffected = [...new Set(corridorDocs.map(doc => doc.municipality))];

      // Calculate regulatory complexity based on document type diversity and volume
      const typeCount = Object.keys(documentsByType).length;
      const maxDocs = Math.max(...Object.values(documentsByType));
      const regulatoryComplexity = Math.min(1, (typeCount * Math.log(maxDocs + 1)) / 10);

      analyses.push({
        corridorId: corridor.id,
        name: corridor.name,
        totalDocuments: corridorDocs.length,
        documentsByType,
        averageDistance,
        municipalitiesAffected,
        regulatoryComplexity
      });
    }

    return analyses.sort((a, b) => b.totalDocuments - a.totalDocuments);
  }

  /**
   * Calculate spatial autocorrelation (Moran's I)
   */
  public calculateSpatialAutocorrelation(
    documents: DocumentLocation[],
    attribute: keyof DocumentLocation = 'confidence'
  ): { moranI: number; pValue: number; significance: string } {
    if (documents.length < 10) {
      return { moranI: 0, pValue: 1, significance: 'insufficient_data' };
    }

    const n = documents.length;
    let sumW = 0;
    let sumWX = 0;
    let sumX = 0;
    let sumX2 = 0;

    // Calculate mean
    const mean = documents.reduce((sum, doc) => {
      const value = typeof doc[attribute] === 'number' ? doc[attribute] : 0;
      return sum + value;
    }, 0) / n;

    // Calculate spatial weights and statistics
    for (let i = 0; i < n; i++) {
      const xi = typeof documents[i][attribute] === 'number' ? documents[i][attribute] : 0;
      sumX += xi;
      sumX2 += xi * xi;

      for (let j = 0; j < n; j++) {
        if (i !== j) {
          const distance = this.calculateDistance(
            documents[i].coordinates,
            documents[j].coordinates
          );
          const weight = distance <= 50 ? 1 / (distance + 1) : 0; // 50km threshold
          
          sumW += weight;
          
          const xj = typeof documents[j][attribute] === 'number' ? documents[j][attribute] : 0;
          sumWX += weight * (xi - mean) * (xj - mean);
        }
      }
    }

    const variance = (sumX2 - (sumX * sumX) / n) / (n - 1);
    const moranI = sumW > 0 ? (n * sumWX) / (sumW * variance * (n - 1)) : 0;

    // Simple p-value approximation (for demonstration)
    const expectedI = -1 / (n - 1);
    const zScore = Math.abs((moranI - expectedI) / 0.1); // simplified
    const pValue = 2 * (1 - this.normalCDF(zScore));

    let significance = 'not_significant';
    if (pValue < 0.01) significance = 'highly_significant';
    else if (pValue < 0.05) significance = 'significant';
    else if (pValue < 0.1) significance = 'marginally_significant';

    return { moranI, pValue, significance };
  }

  // Private helper methods

  private getNeighbors(
    doc: DocumentLocation,
    documents: DocumentLocation[],
    maxDistance: number
  ): DocumentLocation[] {
    return documents.filter(other => 
      other.urn !== doc.urn && 
      this.calculateDistance(doc.coordinates, other.coordinates) <= maxDistance
    );
  }

  private expandCluster(
    seed: DocumentLocation,
    neighbors: DocumentLocation[],
    documents: DocumentLocation[],
    maxDistance: number,
    minPoints: number,
    visited: Set<string>,
    clustered: Set<string>
  ): DocumentCluster {
    const clusterDocs = [seed];
    clustered.add(seed.urn);

    const queue = [...neighbors];
    
    while (queue.length > 0) {
      const current = queue.shift()!;
      
      if (!visited.has(current.urn)) {
        visited.add(current.urn);
        const currentNeighbors = this.getNeighbors(current, documents, maxDistance);
        
        if (currentNeighbors.length >= minPoints) {
          queue.push(...currentNeighbors);
        }
      }
      
      if (!clustered.has(current.urn)) {
        clusterDocs.push(current);
        clustered.add(current.urn);
      }
    }

    // Calculate cluster properties
    const center = this.calculateCentroid(clusterDocs.map(doc => doc.coordinates));
    const maxRadius = Math.max(...clusterDocs.map(doc => 
      this.calculateDistance(center, doc.coordinates)
    ));
    
    const typeCount = clusterDocs.reduce((acc, doc) => {
      acc[doc.type] = (acc[doc.type] || 0) + 1;
      return acc;
    }, {} as Record<DocumentType, number>);
    
    const dominantType = Object.entries(typeCount)
      .sort(([,a], [,b]) => b - a)[0][0] as DocumentType;

    return {
      id: `cluster_${center.lat}_${center.lng}`,
      center,
      radius: maxRadius,
      documents: clusterDocs,
      density: clusterDocs.length / (Math.PI * maxRadius * maxRadius),
      dominantType,
      weight: clusterDocs.reduce((sum, doc) => sum + doc.confidence, 0) / clusterDocs.length
    };
  }

  private calculateDistance(coord1: Coordinates, coord2: Coordinates): number {
    const R = 6371; // Earth's radius in km
    const dLat = (coord2.lat - coord1.lat) * Math.PI / 180;
    const dLon = (coord2.lng - coord1.lng) * Math.PI / 180;
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(coord1.lat * Math.PI / 180) * Math.cos(coord2.lat * Math.PI / 180) * 
      Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  }

  private calculateCentroid(coordinates: Coordinates[]): Coordinates {
    const lat = coordinates.reduce((sum, coord) => sum + coord.lat, 0) / coordinates.length;
    const lng = coordinates.reduce((sum, coord) => sum + coord.lng, 0) / coordinates.length;
    return { lat, lng };
  }

  private calculateBounds(documents: DocumentLocation[]) {
    const lats = documents.map(doc => doc.coordinates.lat);
    const lngs = documents.map(doc => doc.coordinates.lng);
    
    return {
      north: Math.max(...lats),
      south: Math.min(...lats),
      east: Math.max(...lngs),
      west: Math.min(...lngs)
    };
  }

  private calculateGiStatistic(
    point: Coordinates,
    documents: DocumentLocation[],
    radius: number
  ): { zScore: number; pValue: number } {
    const nearbyDocs = documents.filter(doc => 
      this.calculateDistance(point, doc.coordinates) <= radius
    );
    
    const localSum = nearbyDocs.length;
    const globalMean = documents.length / 100; // simplified global mean
    const globalStd = Math.sqrt(globalMean); // simplified
    
    const zScore = (localSum - globalMean) / globalStd;
    const pValue = 2 * (1 - this.normalCDF(Math.abs(zScore)));
    
    return { zScore, pValue };
  }

  private isNearCorridor(
    point: Coordinates,
    route: Coordinates[],
    maxDistance: number
  ): boolean {
    return this.distanceToRoute(point, route) <= maxDistance;
  }

  private distanceToRoute(point: Coordinates, route: Coordinates[]): number {
    let minDistance = Infinity;
    
    for (let i = 0; i < route.length - 1; i++) {
      const segmentDistance = this.distanceToSegment(point, route[i], route[i + 1]);
      minDistance = Math.min(minDistance, segmentDistance);
    }
    
    return minDistance;
  }

  private distanceToSegment(
    point: Coordinates,
    segmentStart: Coordinates,
    segmentEnd: Coordinates
  ): number {
    // Simplified distance to line segment calculation
    const segmentLength = this.calculateDistance(segmentStart, segmentEnd);
    if (segmentLength === 0) return this.calculateDistance(point, segmentStart);
    
    const distanceToStart = this.calculateDistance(point, segmentStart);
    const distanceToEnd = this.calculateDistance(point, segmentEnd);
    
    return Math.min(distanceToStart, distanceToEnd);
  }

  private normalCDF(x: number): number {
    // Approximation of normal cumulative distribution function
    return 0.5 * (1 + this.erf(x / Math.sqrt(2)));
  }

  private erf(x: number): number {
    // Approximation of error function
    const a1 =  0.254829592;
    const a2 = -0.284496736;
    const a3 =  1.421413741;
    const a4 = -1.453152027;
    const a5 =  1.061405429;
    const p  =  0.3275911;

    const sign = x >= 0 ? 1 : -1;
    x = Math.abs(x);

    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);

    return sign * y;
  }
}

export const spatialAnalysisService = SpatialAnalysisService.getInstance();