/**
 * Geographic Features Test Suite
 * Tests all geographic and spatial analysis components with Brazilian municipality data
 */
import { describe, test, expect, beforeEach } from '@jest/globals';
import { spatialAnalysisService } from '../services/spatialAnalysisService';
import { gisExportService } from '../services/gisExportService';
import { geographicService } from '../services/geographicService';
import {
  sampleStates,
  sampleMunicipalities,
  sampleGeographicDocuments,
  allTestDocuments,
  testDataSummary
} from '../data/sampleGeographicData';

describe('Geographic Features Test Suite', () => {
  
  describe('Sample Data Integrity', () => {
    test('should have valid test data structure', () => {
      expect(testDataSummary.states).toBe(5);
      expect(testDataSummary.municipalities).toBe(7);
      expect(testDataSummary.realDocuments).toBe(12);
      expect(testDataSummary.documents).toBeGreaterThan(100);
      expect(testDataSummary.coverage.states).toBeGreaterThanOrEqual(3);
      expect(testDataSummary.confidence.avg).toBeGreaterThan(0.7);
    });

    test('should have valid coordinate ranges for Brazil', () => {
      sampleMunicipalities.forEach(muni => {
        // Brazil latitude range: ~5°N to ~34°S
        expect(muni.coordinates.lat).toBeGreaterThanOrEqual(-35);
        expect(muni.coordinates.lat).toBeLessThanOrEqual(6);
        // Brazil longitude range: ~35°W to ~74°W
        expect(muni.coordinates.lng).toBeGreaterThanOrEqual(-75);
        expect(muni.coordinates.lng).toBeLessThanOrEqual(-30);
      });
    });

    test('should have valid IBGE codes', () => {
      sampleMunicipalities.forEach(muni => {
        expect(muni.ibgeCode).toMatch(/^\d{7}$/); // IBGE codes are 7 digits
        expect(muni.ibgeCode.length).toBe(7);
      });
    });
  });

  describe('GeographicService Tests', () => {
    test('should calculate distances between Brazilian cities correctly', async () => {
      const sp = { lat: -23.5505, lng: -46.6333 }; // São Paulo
      const rj = { lat: -22.9068, lng: -43.1729 }; // Rio de Janeiro
      
      const distance = await geographicService.calculateDistance(sp, rj);
      
      // Real distance SP-RJ is approximately 357 km
      expect(distance).toBeGreaterThan(350);
      expect(distance).toBeLessThan(370);
    });

    test('should find municipalities by state correctly', async () => {
      const spMunicipalities = await geographicService.getMunicipalities('SP');
      const allSpMunis = sampleMunicipalities.filter(m => m.stateAbbreviation === 'SP');
      
      expect(spMunicipalities.length).toBeGreaterThanOrEqual(allSpMunis.length);
      
      const spMuniNames = spMunicipalities.map(m => m.name);
      expect(spMuniNames).toContain('São Paulo');
      expect(spMuniNames).toContain('Campinas');
      expect(spMuniNames).toContain('Santos');
    });

    test('should perform location-based search within radius', async () => {
      const centerSP = { lat: -23.5505, lng: -46.6333 };
      const radius = 100; // 100km around São Paulo
      
      const results = await geographicService.searchByLocation(centerSP, radius);
      
      expect(results.length).toBeGreaterThan(0);
      
      // Verify all results are within the specified radius
      for (const doc of results) {
        const distance = await geographicService.calculateDistance(centerSP, doc.coordinates);
        expect(distance).toBeLessThanOrEqual(radius);
      }
    });
  });

  describe('SpatialAnalysisService Tests', () => {
    test('should perform DBSCAN clustering on Brazilian documents', () => {
      const clusters = spatialAnalysisService.clusterDocuments(allTestDocuments, 50, 3);
      
      expect(clusters.length).toBeGreaterThan(0);
      
      clusters.forEach(cluster => {
        expect(cluster.documents.length).toBeGreaterThanOrEqual(3);
        expect(cluster.center.lat).toBeGreaterThanOrEqual(-35);
        expect(cluster.center.lat).toBeLessThanOrEqual(6);
        expect(cluster.center.lng).toBeGreaterThanOrEqual(-75);
        expect(cluster.center.lng).toBeLessThanOrEqual(-30);
        expect(cluster.radius).toBeGreaterThan(0);
        expect(cluster.density).toBeGreaterThan(0);
        expect(cluster.weight).toBeGreaterThan(0);
        expect(cluster.weight).toBeLessThanOrEqual(1);
      });
    });

    test('should calculate regional statistics for Brazilian states', () => {
      const regionalStats = spatialAnalysisService.calculateRegionalStatistics(
        allTestDocuments,
        sampleStates,
        sampleMunicipalities
      );
      
      expect(regionalStats.length).toBeGreaterThan(0);
      expect(regionalStats.length).toBeLessThanOrEqual(sampleStates.length);
      
      regionalStats.forEach(stat => {
        expect(stat.totalDocuments).toBeGreaterThan(0);
        expect(stat.averageConfidence).toBeGreaterThan(0);
        expect(stat.averageConfidence).toBeLessThanOrEqual(1);
        expect(stat.coverage).toBeGreaterThanOrEqual(0);
        expect(stat.coverage).toBeLessThanOrEqual(1);
        expect(stat.documentDensity).toBeGreaterThanOrEqual(0);
        
        // Check if state exists in our sample data
        const state = sampleStates.find(s => s.id === stat.stateId);
        expect(state).toBeDefined();
        expect(stat.stateName).toBe(state!.name);
      });
    });

    test('should identify spatial hotspots using Getis-Ord Gi*', () => {
      const hotspots = spatialAnalysisService.identifyHotspots(allTestDocuments, 100);
      
      // Should find some hotspots with sufficient data
      expect(hotspots.length).toBeGreaterThanOrEqual(0);
      
      hotspots.forEach(hotspot => {
        expect(hotspot.center.lat).toBeGreaterThanOrEqual(-35);
        expect(hotspot.center.lat).toBeLessThanOrEqual(6);
        expect(hotspot.center.lng).toBeGreaterThanOrEqual(-75);
        expect(hotspot.center.lng).toBeLessThanOrEqual(-30);
        expect(hotspot.documentCount).toBeGreaterThan(0);
        expect(hotspot.radius).toBeGreaterThan(0);
        expect(hotspot.significance).toBeGreaterThan(0);
        expect(['hot', 'cold']).toContain(hotspot.type);
      });
    });

    test('should calculate spatial autocorrelation (Moran\'s I)', () => {
      const moranResult = spatialAnalysisService.calculateSpatialAutocorrelation(allTestDocuments);
      
      expect(typeof moranResult.moranI).toBe('number');
      expect(moranResult.pValue).toBeGreaterThanOrEqual(0);
      expect(moranResult.pValue).toBeLessThanOrEqual(1);
      expect(['not_significant', 'marginally_significant', 'significant', 'highly_significant', 'insufficient_data'])
        .toContain(moranResult.significance);
    });

    test('should analyze transport corridors', () => {
      const corridorAnalysis = spatialAnalysisService.analyzeTransportCorridors(allTestDocuments, 25);
      
      expect(corridorAnalysis.length).toBeGreaterThanOrEqual(0);
      
      corridorAnalysis.forEach(analysis => {
        expect(analysis.totalDocuments).toBeGreaterThan(0);
        expect(analysis.averageDistance).toBeGreaterThanOrEqual(0);
        expect(analysis.regulatoryComplexity).toBeGreaterThanOrEqual(0);
        expect(analysis.regulatoryComplexity).toBeLessThanOrEqual(1);
        expect(analysis.municipalitiesAffected.length).toBeGreaterThan(0);
      });
    });
  });

  describe('GIS Export Service Tests', () => {
    test('should export documents to valid GeoJSON format', () => {
      const geoJson = gisExportService.exportDocumentsToGeoJSON(sampleGeographicDocuments, {
        format: 'geojson',
        includeMetadata: true,
        precision: 6
      });
      
      expect(geoJson.type).toBe('FeatureCollection');
      expect(geoJson.features.length).toBe(sampleGeographicDocuments.length);
      expect(geoJson.metadata).toBeDefined();
      expect(geoJson.metadata!.totalFeatures).toBe(sampleGeographicDocuments.length);
      expect(geoJson.metadata!.coordinateSystem).toBe('WGS84');
      
      geoJson.features.forEach((feature, index) => {
        expect(feature.type).toBe('Feature');
        expect(feature.geometry.type).toBe('Point');
        expect(feature.geometry.coordinates.length).toBe(2);
        expect(feature.properties.urn).toBe(sampleGeographicDocuments[index].urn);
        expect(feature.properties.municipality).toBe(sampleGeographicDocuments[index].municipality);
        expect(feature.properties.state).toBe(sampleGeographicDocuments[index].state);
      });
    });

    test('should export documents to valid KML format', () => {
      const kml = gisExportService.exportDocumentsToKML(sampleGeographicDocuments, {
        format: 'kml',
        includeMetadata: true,
        precision: 5
      });
      
      expect(kml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
      expect(kml).toContain('<kml xmlns="http://www.opengis.net/kml/2.2">');
      expect(kml).toContain('<Document>');
      expect(kml).toContain('Monitor Legislativo v4');
      
      // Should contain placemarks for each document
      const placemarkCount = (kml.match(/<Placemark>/g) || []).length;
      expect(placemarkCount).toBe(sampleGeographicDocuments.length);
      
      // Check for proper coordinate format in KML
      sampleGeographicDocuments.forEach(doc => {
        const expectedCoords = `${doc.coordinates.lng.toFixed(5)},${doc.coordinates.lat.toFixed(5)},0`;
        expect(kml).toContain(expectedCoords);
      });
    });

    test('should export documents to valid CSV format', () => {
      const csv = gisExportService.exportDocumentsToCSV(sampleGeographicDocuments, {
        format: 'csv',
        includeMetadata: true,
        precision: 6
      });
      
      const lines = csv.split('\n');
      expect(lines.length).toBe(sampleGeographicDocuments.length + 1); // +1 for header
      
      const headers = lines[0].split(',');
      expect(headers).toContain('urn');
      expect(headers).toContain('title');
      expect(headers).toContain('latitude');
      expect(headers).toContain('longitude');
      expect(headers).toContain('municipality');
      expect(headers).toContain('state');
      expect(headers).toContain('confidence');
      expect(headers).toContain('precision');
      
      // Check data rows
      for (let i = 1; i < lines.length; i++) {
        const row = lines[i].split(',');
        expect(row.length).toBe(headers.length);
        
        // Verify coordinates are valid numbers
        const lat = parseFloat(row[headers.indexOf('latitude')]);
        const lng = parseFloat(row[headers.indexOf('longitude')]);
        expect(lat).toBeGreaterThanOrEqual(-35);
        expect(lat).toBeLessThanOrEqual(6);
        expect(lng).toBeGreaterThanOrEqual(-75);
        expect(lng).toBeLessThanOrEqual(-30);
      }
    });

    test('should export clusters to GeoJSON format', () => {
      const clusters = spatialAnalysisService.clusterDocuments(allTestDocuments, 50, 3);
      const geoJson = gisExportService.exportClustersToGeoJSON(clusters, {
        format: 'geojson',
        includeMetadata: true
      });
      
      expect(geoJson.type).toBe('FeatureCollection');
      expect(geoJson.features.length).toBe(clusters.length);
      
      geoJson.features.forEach((feature, index) => {
        expect(feature.type).toBe('Feature');
        expect(feature.geometry.type).toBe('Point');
        expect(feature.properties.clusterId).toBe(clusters[index].id);
        expect(feature.properties.documentCount).toBe(clusters[index].documents.length);
        expect(feature.properties.dominantType).toBe(clusters[index].dominantType);
      });
    });

    test('should export boundaries to GeoJSON format', () => {
      const geoJson = gisExportService.exportBoundariesToGeoJSON(
        sampleStates,
        sampleMunicipalities,
        { format: 'geojson', includeMetadata: true }
      );
      
      expect(geoJson.type).toBe('FeatureCollection');
      expect(geoJson.features.length).toBe(sampleStates.length + sampleMunicipalities.length);
      
      const stateFeatures = geoJson.features.filter(f => f.properties.type === 'state');
      const municipalityFeatures = geoJson.features.filter(f => f.properties.type === 'municipality');
      
      expect(stateFeatures.length).toBe(sampleStates.length);
      expect(municipalityFeatures.length).toBe(sampleMunicipalities.length);
    });

    test('should generate export summary correctly', () => {
      const clusters = spatialAnalysisService.clusterDocuments(allTestDocuments, 50, 3);
      const hotspots = spatialAnalysisService.identifyHotspots(allTestDocuments, 100);
      
      const summary = gisExportService.getExportSummary(allTestDocuments, clusters, hotspots);
      
      expect(summary.documentCount).toBe(allTestDocuments.length);
      expect(summary.uniqueStates).toBeGreaterThan(0);
      expect(summary.uniqueMunicipalities).toBeGreaterThan(0);
      expect(summary.clusterCount).toBe(clusters.length);
      expect(summary.hotspotCount).toBe(hotspots.length);
      expect(summary.avgConfidence).toBeGreaterThan(0);
      expect(summary.avgConfidence).toBeLessThanOrEqual(1);
      
      // Verify spatial extent covers Brazil
      expect(summary.spatialExtent.north).toBeGreaterThan(summary.spatialExtent.south);
      expect(summary.spatialExtent.east).toBeGreaterThan(summary.spatialExtent.west);
      expect(summary.spatialExtent.south).toBeGreaterThanOrEqual(-35);
      expect(summary.spatialExtent.north).toBeLessThanOrEqual(6);
      expect(summary.spatialExtent.west).toBeGreaterThanOrEqual(-75);
      expect(summary.spatialExtent.east).toBeLessThanOrEqual(-30);
    });
  });

  describe('Integration Tests', () => {
    test('should perform complete geographic analysis workflow', () => {
      // 1. Cluster documents
      const clusters = spatialAnalysisService.clusterDocuments(allTestDocuments, 50, 3);
      expect(clusters.length).toBeGreaterThan(0);
      
      // 2. Identify hotspots
      const hotspots = spatialAnalysisService.identifyHotspots(allTestDocuments, 100);
      expect(hotspots.length).toBeGreaterThanOrEqual(0);
      
      // 3. Calculate regional statistics
      const regionalStats = spatialAnalysisService.calculateRegionalStatistics(
        allTestDocuments,
        sampleStates,
        sampleMunicipalities
      );
      expect(regionalStats.length).toBeGreaterThan(0);
      
      // 4. Export all data formats
      const documentsGeoJSON = gisExportService.exportDocumentsToGeoJSON(allTestDocuments);
      const clustersGeoJSON = gisExportService.exportClustersToGeoJSON(clusters);
      const documentsKML = gisExportService.exportDocumentsToKML(allTestDocuments);
      const documentsCSV = gisExportService.exportDocumentsToCSV(allTestDocuments);
      
      expect(documentsGeoJSON.features.length).toBe(allTestDocuments.length);
      expect(clustersGeoJSON.features.length).toBe(clusters.length);
      expect(documentsKML).toContain('<Document>');
      expect(documentsCSV.split('\n').length).toBe(allTestDocuments.length + 1);
      
      // 5. Verify data consistency
      const summary = gisExportService.getExportSummary(allTestDocuments, clusters, hotspots);
      expect(summary.documentCount).toBe(allTestDocuments.length);
      expect(summary.clusterCount).toBe(clusters.length);
      expect(summary.hotspotCount).toBe(hotspots.length);
    });

    test('should handle edge cases gracefully', () => {
      // Empty datasets
      expect(() => spatialAnalysisService.clusterDocuments([], 50, 3)).not.toThrow();
      expect(() => spatialAnalysisService.identifyHotspots([], 100)).not.toThrow();
      expect(() => gisExportService.exportDocumentsToGeoJSON([])).not.toThrow();
      
      // Single document
      const singleDoc = [sampleGeographicDocuments[0]];
      const singleCluster = spatialAnalysisService.clusterDocuments(singleDoc, 50, 1);
      expect(singleCluster.length).toBeLessThanOrEqual(1);
      
      // Very small radius
      const tightClusters = spatialAnalysisService.clusterDocuments(allTestDocuments, 1, 3);
      expect(tightClusters.length).toBeGreaterThanOrEqual(0);
    });
  });
});

// Performance benchmarks (optional)
describe('Geographic Performance Tests', () => {
  test('should cluster large datasets efficiently', () => {
    const startTime = Date.now();
    spatialAnalysisService.clusterDocuments(allTestDocuments, 50, 3);
    const endTime = Date.now();
    
    // Should complete clustering within reasonable time (2 seconds for test data)
    expect(endTime - startTime).toBeLessThan(2000);
  });

  test('should export large datasets efficiently', () => {
    const startTime = Date.now();
    gisExportService.exportDocumentsToGeoJSON(allTestDocuments);
    const endTime = Date.now();
    
    // Should complete export within reasonable time (1 second for test data)
    expect(endTime - startTime).toBeLessThan(1000);
  });
});