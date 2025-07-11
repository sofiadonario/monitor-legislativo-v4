export interface GeoJSONFeature {
  type: "Feature";
  properties: {
    id: string;
    name: string;
    abbreviation: string;
    capital: string;
    region: string;
    coordinates?: [number, number];
  };
  geometry: {
    type: "Polygon" | "MultiPolygon";
    coordinates: number[][][] | number[][][][];
  };
}

export interface GeoJSONFeatureCollection {
  type: "FeatureCollection";
  features: GeoJSONFeature[];
} 