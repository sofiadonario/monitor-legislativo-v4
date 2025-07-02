/**
 * GIS Export Service
 * Provides export capabilities for GeoJSON, KML, CSV, and other spatial data formats
 */
import { DocumentLocation, Coordinates, StateData, Municipality } from '../types';
import { DocumentCluster, RegionalStatistics, SpatialHotspot } from './spatialAnalysisService';

export interface ExportOptions {
  format: 'geojson' | 'kml' | 'csv' | 'shapefile' | 'excel';
  includeMetadata?: boolean;
  coordinateSystem?: 'WGS84' | 'SIRGAS2000';
  precision?: number;
  timestamp?: boolean;
}

export interface GeoJSONExport {
  type: 'FeatureCollection';
  features: Array<{
    type: 'Feature';
    geometry: {
      type: 'Point' | 'Polygon';
      coordinates: number[] | number[][];
    };
    properties: Record<string, any>;
  }>;
  metadata?: {
    exportDate: string;
    totalFeatures: number;
    coordinateSystem: string;
    source: string;
  };
}

export class GISExportService {
  private static instance: GISExportService;

  private constructor() {}

  public static getInstance(): GISExportService {
    if (!GISExportService.instance) {
      GISExportService.instance = new GISExportService();
    }
    return GISExportService.instance;
  }

  /**
   * Export documents to GeoJSON format
   */
  public exportDocumentsToGeoJSON(
    documents: DocumentLocation[],
    options: ExportOptions = { format: 'geojson' }
  ): GeoJSONExport {
    const features = documents.map(doc => ({
      type: 'Feature' as const,
      geometry: {
        type: 'Point' as const,
        coordinates: [
          this.roundCoordinate(doc.coordinates.lng, options.precision),
          this.roundCoordinate(doc.coordinates.lat, options.precision)
        ]
      },
      properties: {
        urn: doc.urn,
        title: doc.title,
        type: doc.type,
        municipality: doc.municipality,
        state: doc.state,
        confidence: doc.confidence,
        precision: doc.precision,
        ...(options.includeMetadata && {
          address: doc.address?.formattedAddress,
          exportDate: new Date().toISOString()
        })
      }
    }));

    const result: GeoJSONExport = {
      type: 'FeatureCollection',
      features
    };

    if (options.includeMetadata) {
      result.metadata = {
        exportDate: new Date().toISOString(),
        totalFeatures: features.length,
        coordinateSystem: options.coordinateSystem || 'WGS84',
        source: 'Monitor Legislativo v4'
      };
    }

    return result;
  }

  /**
   * Export clusters to GeoJSON format
   */
  public exportClustersToGeoJSON(
    clusters: DocumentCluster[],
    options: ExportOptions = { format: 'geojson' }
  ): GeoJSONExport {
    const features = clusters.map((cluster, index) => ({
      type: 'Feature' as const,
      geometry: {
        type: 'Point' as const,
        coordinates: [
          this.roundCoordinate(cluster.center.lng, options.precision),
          this.roundCoordinate(cluster.center.lat, options.precision)
        ]
      },
      properties: {
        clusterId: cluster.id,
        clusterIndex: index + 1,
        documentCount: cluster.documents.length,
        radius: cluster.radius,
        density: cluster.density,
        dominantType: cluster.dominantType,
        weight: cluster.weight,
        ...(options.includeMetadata && {
          documents: cluster.documents.map(doc => doc.urn),
          exportDate: new Date().toISOString()
        })
      }
    }));

    return {
      type: 'FeatureCollection',
      features,
      ...(options.includeMetadata && {
        metadata: {
          exportDate: new Date().toISOString(),
          totalFeatures: features.length,
          coordinateSystem: options.coordinateSystem || 'WGS84',
          source: 'Monitor Legislativo v4 - Cluster Analysis'
        }
      })
    };
  }

  /**
   * Export hotspots to GeoJSON format
   */
  public exportHotspotsToGeoJSON(
    hotspots: SpatialHotspot[],
    options: ExportOptions = { format: 'geojson' }
  ): GeoJSONExport {
    const features = hotspots.map((hotspot, index) => ({
      type: 'Feature' as const,
      geometry: {
        type: 'Point' as const,
        coordinates: [
          this.roundCoordinate(hotspot.center.lng, options.precision),
          this.roundCoordinate(hotspot.center.lat, options.precision)
        ]
      },
      properties: {
        hotspotId: hotspot.id,
        hotspotIndex: index + 1,
        type: hotspot.type,
        documentCount: hotspot.documentCount,
        radius: hotspot.radius,
        significance: hotspot.significance,
        zScore: hotspot.zScore,
        pValue: hotspot.pValue,
        ...(options.includeMetadata && {
          exportDate: new Date().toISOString()
        })
      }
    }));

    return {
      type: 'FeatureCollection',
      features,
      ...(options.includeMetadata && {
        metadata: {
          exportDate: new Date().toISOString(),
          totalFeatures: features.length,
          coordinateSystem: options.coordinateSystem || 'WGS84',
          source: 'Monitor Legislativo v4 - Hotspot Analysis'
        }
      })
    };
  }

  /**
   * Export boundaries to GeoJSON format
   */
  public exportBoundariesToGeoJSON(
    states: StateData[],
    municipalities: Municipality[],
    options: ExportOptions = { format: 'geojson' }
  ): GeoJSONExport {
    const stateFeatures = states
      .filter(state => state.boundaries)
      .map(state => ({
        type: 'Feature' as const,
        geometry: state.boundaries!,
        properties: {
          type: 'state',
          id: state.id,
          name: state.name,
          abbreviation: state.abbreviation,
          region: state.region,
          capital: state.capital,
          population: state.population,
          area: state.area,
          ...(options.includeMetadata && {
            exportDate: new Date().toISOString()
          })
        }
      }));

    const municipalityFeatures = municipalities
      .filter(muni => muni.boundaries)
      .map(muni => ({
        type: 'Feature' as const,
        geometry: muni.boundaries!,
        properties: {
          type: 'municipality',
          id: muni.id,
          name: muni.name,
          stateId: muni.stateId,
          stateAbbreviation: muni.stateAbbreviation,
          ibgeCode: muni.ibgeCode,
          population: muni.population,
          area: muni.area,
          ...(options.includeMetadata && {
            exportDate: new Date().toISOString()
          })
        }
      }));

    return {
      type: 'FeatureCollection',
      features: [...stateFeatures, ...municipalityFeatures],
      ...(options.includeMetadata && {
        metadata: {
          exportDate: new Date().toISOString(),
          totalFeatures: stateFeatures.length + municipalityFeatures.length,
          coordinateSystem: options.coordinateSystem || 'WGS84',
          source: 'Monitor Legislativo v4 - Administrative Boundaries'
        }
      })
    };
  }

  /**
   * Export documents to KML format
   */
  public exportDocumentsToKML(
    documents: DocumentLocation[],
    options: ExportOptions = { format: 'kml' }
  ): string {
    const timestamp = options.timestamp ? new Date().toISOString() : '';
    
    const placemarks = documents.map(doc => `
      <Placemark>
        <name><![CDATA[${doc.title}]]></name>
        <description><![CDATA[
          <strong>Type:</strong> ${doc.type}<br/>
          <strong>Municipality:</strong> ${doc.municipality}, ${doc.state}<br/>
          <strong>Confidence:</strong> ${Math.round(doc.confidence * 100)}%<br/>
          <strong>Precision:</strong> ${doc.precision}<br/>
          ${doc.address ? `<strong>Address:</strong> ${doc.address.formattedAddress}<br/>` : ''}
          <strong>URN:</strong> ${doc.urn}
        ]]></description>
        <Point>
          <coordinates>${this.roundCoordinate(doc.coordinates.lng, options.precision)},${this.roundCoordinate(doc.coordinates.lat, options.precision)},0</coordinates>
        </Point>
        <ExtendedData>
          <Data name="urn"><value>${doc.urn}</value></Data>
          <Data name="type"><value>${doc.type}</value></Data>
          <Data name="confidence"><value>${doc.confidence}</value></Data>
          <Data name="precision"><value>${doc.precision}</value></Data>
          ${timestamp ? `<Data name="exportDate"><value>${timestamp}</value></Data>` : ''}
        </ExtendedData>
      </Placemark>
    `).join('');

    return `<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Monitor Legislativo v4 - Legislative Documents</name>
    <description>Brazilian Legislative Documents with Geographic Information</description>
    ${timestamp ? `<TimeStamp><when>${timestamp}</when></TimeStamp>` : ''}
    <Style id="documentIcon">
      <IconStyle>
        <Icon>
          <href>http://maps.google.com/mapfiles/kml/pushpin/blue-pushpin.png</href>
        </Icon>
      </IconStyle>
    </Style>
    ${placemarks}
  </Document>
</kml>`;
  }

  /**
   * Export data to CSV format
   */
  public exportDocumentsToCSV(
    documents: DocumentLocation[],
    options: ExportOptions = { format: 'csv' }
  ): string {
    const headers = [
      'urn',
      'title',
      'type',
      'municipality',
      'state',
      'latitude',
      'longitude',
      'confidence',
      'precision'
    ];

    if (options.includeMetadata) {
      headers.push('address', 'exportDate');
    }

    const rows = documents.map(doc => {
      const row = [
        this.escapeCsvValue(doc.urn),
        this.escapeCsvValue(doc.title),
        doc.type,
        this.escapeCsvValue(doc.municipality),
        doc.state,
        this.roundCoordinate(doc.coordinates.lat, options.precision),
        this.roundCoordinate(doc.coordinates.lng, options.precision),
        doc.confidence,
        doc.precision
      ];

      if (options.includeMetadata) {
        row.push(
          this.escapeCsvValue(doc.address?.formattedAddress || ''),
          new Date().toISOString()
        );
      }

      return row.join(',');
    });

    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Export regional statistics to CSV
   */
  public exportRegionalStatisticsToCSV(
    statistics: RegionalStatistics[],
    options: ExportOptions = { format: 'csv' }
  ): string {
    const headers = [
      'stateId',
      'stateName',
      'totalDocuments',
      'municipalityCount',
      'documentDensity',
      'coverage',
      'averageConfidence',
      'topMunicipality1',
      'topMunicipality1Count',
      'topMunicipality2',
      'topMunicipality2Count',
      'topMunicipality3',
      'topMunicipality3Count'
    ];

    if (options.includeMetadata) {
      headers.push('exportDate');
    }

    const rows = statistics.map(stat => {
      const row = [
        stat.stateId,
        this.escapeCsvValue(stat.stateName),
        stat.totalDocuments,
        stat.municipalityCount,
        stat.documentDensity,
        stat.coverage,
        stat.averageConfidence,
        this.escapeCsvValue(stat.topMunicipalities[0]?.name || ''),
        stat.topMunicipalities[0]?.documentCount || 0,
        this.escapeCsvValue(stat.topMunicipalities[1]?.name || ''),
        stat.topMunicipalities[1]?.documentCount || 0,
        this.escapeCsvValue(stat.topMunicipalities[2]?.name || ''),
        stat.topMunicipalities[2]?.documentCount || 0
      ];

      if (options.includeMetadata) {
        row.push(new Date().toISOString());
      }

      return row.join(',');
    });

    return [headers.join(','), ...rows].join('\n');
  }

  /**
   * Download exported data as file
   */
  public downloadFile(
    content: string | GeoJSONExport,
    filename: string,
    mimeType: string = 'application/json'
  ): void {
    const blob = new Blob(
      [typeof content === 'string' ? content : JSON.stringify(content, null, 2)],
      { type: mimeType }
    );
    
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  /**
   * Generate export filename with timestamp
   */
  public generateFilename(
    prefix: string,
    format: string,
    includeTimestamp: boolean = true
  ): string {
    const timestamp = includeTimestamp 
      ? `_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}`
      : '';
    return `${prefix}${timestamp}.${format}`;
  }

  /**
   * Get export summary information
   */
  public getExportSummary(
    documents: DocumentLocation[],
    clusters?: DocumentCluster[],
    hotspots?: SpatialHotspot[]
  ): {
    documentCount: number;
    uniqueStates: number;
    uniqueMunicipalities: number;
    clusterCount?: number;
    hotspotCount?: number;
    avgConfidence: number;
    spatialExtent: {
      north: number;
      south: number;
      east: number;
      west: number;
    };
  } {
    const uniqueStates = new Set(documents.map(doc => doc.state)).size;
    const uniqueMunicipalities = new Set(documents.map(doc => doc.municipality)).size;
    const avgConfidence = documents.length > 0
      ? documents.reduce((sum, doc) => sum + doc.confidence, 0) / documents.length
      : 0;

    const lats = documents.map(doc => doc.coordinates.lat);
    const lngs = documents.map(doc => doc.coordinates.lng);

    return {
      documentCount: documents.length,
      uniqueStates,
      uniqueMunicipalities,
      ...(clusters && { clusterCount: clusters.length }),
      ...(hotspots && { hotspotCount: hotspots.length }),
      avgConfidence,
      spatialExtent: {
        north: Math.max(...lats),
        south: Math.min(...lats),
        east: Math.max(...lngs),
        west: Math.min(...lngs)
      }
    };
  }

  // Private helper methods

  private roundCoordinate(coord: number, precision?: number): number {
    const digits = precision || 6;
    return Math.round(coord * Math.pow(10, digits)) / Math.pow(10, digits);
  }

  private escapeCsvValue(value: string): string {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }
}

export const gisExportService = GISExportService.getInstance();