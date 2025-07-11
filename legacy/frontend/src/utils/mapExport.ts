/**
 * Map Export Utilities
 * 
 * Utilities for exporting the map visualization as images and other formats.
 * Uses html2canvas for reliable map capture with proper styling.
 */

import html2canvas from 'html2canvas';

export interface MapExportOptions {
  format: 'png' | 'jpeg' | 'svg';
  quality?: number; // 0.1 to 1.0 for JPEG
  scale?: number; // 1 to 4 for higher resolution
  includeControls?: boolean;
  includeLegend?: boolean;
  backgroundColor?: string;
  filename?: string;
}

/**
 * Export the map container as a PNG image
 */
export const exportMapToPNG = async (options: MapExportOptions = {}): Promise<void> => {
  const {
    quality = 0.9,
    scale = 2,
    includeControls = false,
    includeLegend = true,
    backgroundColor = '#ffffff',
    filename = 'legislative-map'
  } = options;

  try {
    // Find the map container
    const mapContainer = document.querySelector('.map-wrapper') as HTMLElement;
    if (!mapContainer) {
      throw new Error('Map container not found');
    }

    // Temporarily hide controls if not included
    const controls = mapContainer.querySelectorAll('.map-controls');
    const controlsDisplay: string[] = [];
    
    if (!includeControls) {
      controls.forEach((control, index) => {
        const element = control as HTMLElement;
        controlsDisplay[index] = element.style.display;
        element.style.display = 'none';
      });
    }

    // Temporarily hide legend if not included
    const legend = mapContainer.querySelector('.map-legend') as HTMLElement;
    let legendDisplay = '';
    
    if (!includeLegend && legend) {
      legendDisplay = legend.style.display;
      legend.style.display = 'none';
    }

    // Configure html2canvas options
    const canvasOptions = {
      allowTaint: true,
      useCORS: true,
      scale: scale,
      backgroundColor: backgroundColor,
      width: mapContainer.offsetWidth,
      height: mapContainer.offsetHeight,
      logging: false,
      removeContainer: false,
      imageTimeout: 15000,
      onclone: (clonedDoc: Document) => {
        // Ensure all styles are applied to the cloned document
        const clonedContainer = clonedDoc.querySelector('.map-wrapper') as HTMLElement;
        if (clonedContainer) {
          clonedContainer.style.transform = 'none';
          clonedContainer.style.position = 'static';
        }
      }
    };

    // Capture the map
    const canvas = await html2canvas(mapContainer, canvasOptions);

    // Restore hidden elements
    if (!includeControls) {
      controls.forEach((control, index) => {
        const element = control as HTMLElement;
        element.style.display = controlsDisplay[index] || '';
      });
    }

    if (!includeLegend && legend) {
      legend.style.display = legendDisplay;
    }

    // Convert to blob and download
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
    const finalFilename = `${filename}-${timestamp}.png`;

    canvas.toBlob((blob) => {
      if (blob) {
        downloadBlob(blob, finalFilename);
      } else {
        throw new Error('Failed to create image blob');
      }
    }, 'image/png', quality);

  } catch (error) {
    console.error('Map export failed:', error);
    throw new Error(`Failed to export map: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

/**
 * Export the map with additional metadata overlay
 */
export const exportMapWithMetadata = async (
  documents: any[], 
  selectedState?: string,
  options: MapExportOptions = {}
): Promise<void> => {
  const {
    filename = 'legislative-map-with-data'
  } = options;

  try {
    // Create a temporary overlay with metadata
    const overlay = createMetadataOverlay(documents, selectedState);
    
    // Find the map container and add overlay
    const mapContainer = document.querySelector('.map-wrapper') as HTMLElement;
    if (!mapContainer) {
      throw new Error('Map container not found');
    }

    mapContainer.appendChild(overlay);

    try {
      // Export with metadata
      await exportMapToPNG({ ...options, filename });
    } finally {
      // Remove the overlay
      mapContainer.removeChild(overlay);
    }

  } catch (error) {
    console.error('Map export with metadata failed:', error);
    throw error;
  }
};

/**
 * Create a metadata overlay for the map
 */
const createMetadataOverlay = (documents: any[], selectedState?: string): HTMLElement => {
  const overlay = document.createElement('div');
  overlay.className = 'map-export-overlay';
  overlay.style.cssText = `
    position: absolute;
    top: 10px;
    left: 10px;
    background: rgba(255, 255, 255, 0.95);
    padding: 16px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    line-height: 1.4;
    max-width: 300px;
    z-index: 1000;
    border: 1px solid #e0e0e0;
  `;

  const title = document.createElement('h3');
  title.textContent = 'Monitor Legislativo de Transportes';
  title.style.cssText = `
    margin: 0 0 12px 0;
    font-size: 16px;
    font-weight: 600;
    color: #2196F3;
  `;

  const stats = document.createElement('div');
  const currentDate = new Date().toLocaleDateString('pt-BR');
  
  stats.innerHTML = `
    <div style="margin-bottom: 8px;"><strong>Data de exportação:</strong> ${currentDate}</div>
    <div style="margin-bottom: 8px;"><strong>Documentos encontrados:</strong> ${documents.length}</div>
    ${selectedState ? `<div style="margin-bottom: 8px;"><strong>Estado selecionado:</strong> ${selectedState}</div>` : ''}
    <div style="margin-bottom: 8px;"><strong>Fonte:</strong> Dados Abertos do Governo Federal</div>
    <div style="font-size: 12px; color: #666; margin-top: 12px; padding-top: 12px; border-top: 1px solid #e0e0e0;">
      Plataforma Acadêmica de Pesquisa<br>
      Legislação de Transportes do Brasil
    </div>
  `;

  overlay.appendChild(title);
  overlay.appendChild(stats);
  
  return overlay;
};

/**
 * Download a blob as a file
 */
const downloadBlob = (blob: Blob, filename: string): void => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  
  // Clean up the URL
  setTimeout(() => URL.revokeObjectURL(url), 100);
};

/**
 * Export the current map view as SVG (simplified version)
 */
export const exportMapToSVG = async (options: MapExportOptions = {}): Promise<void> => {
  const { filename = 'legislative-map' } = options;
  
  try {
    // Find SVG elements in the map
    const mapContainer = document.querySelector('.map-wrapper') as HTMLElement;
    if (!mapContainer) {
      throw new Error('Map container not found');
    }

    const svgElements = mapContainer.querySelectorAll('svg');
    if (svgElements.length === 0) {
      throw new Error('No SVG elements found in map');
    }

    // Clone the main SVG
    const mainSvg = svgElements[0].cloneNode(true) as SVGElement;
    
    // Set SVG attributes for standalone file
    mainSvg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    mainSvg.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink');
    
    // Add CSS styles as inline styles (simplified)
    const styles = `
      <style>
        .map-state { fill: #e0e0e0; stroke: #ffffff; stroke-width: 1; }
        .map-state.highlighted { fill: #2196F3; stroke: #1976D2; stroke-width: 2; }
        .map-state.selected { fill: #1976D2; stroke: #0D47A1; stroke-width: 3; }
        .state-label { font-family: Arial, sans-serif; font-size: 11px; font-weight: 600; fill: #333; text-anchor: middle; }
      </style>
    `;
    
    mainSvg.insertAdjacentHTML('afterbegin', styles);

    // Create SVG content
    const svgContent = new XMLSerializer().serializeToString(mainSvg);
    const blob = new Blob([svgContent], { type: 'image/svg+xml;charset=utf-8' });
    
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
    const finalFilename = `${filename}-${timestamp}.svg`;
    
    downloadBlob(blob, finalFilename);

  } catch (error) {
    console.error('SVG export failed:', error);
    throw new Error(`Failed to export SVG: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
};

/**
 * Check if the browser supports the required features for map export
 */
export const isMapExportSupported = (): boolean => {
  try {
    // Check for required APIs
    const hasCanvas = !!document.createElement('canvas').getContext;
    const hasBlob = !!window.Blob;
    const hasCreateObjectURL = !!window.URL?.createObjectURL;
    
    return hasCanvas && hasBlob && hasCreateObjectURL;
  } catch {
    return false;
  }
};

/**
 * Get estimated export file size
 */
export const getEstimatedExportSize = (scale: number = 2): string => {
  const mapContainer = document.querySelector('.map-wrapper') as HTMLElement;
  if (!mapContainer) {
    return 'Unknown';
  }

  // Rough estimation based on dimensions and scale
  const width = mapContainer.offsetWidth * scale;
  const height = mapContainer.offsetHeight * scale;
  const estimatedBytes = width * height * 4; // 4 bytes per pixel for RGBA
  const estimatedMB = estimatedBytes / (1024 * 1024);

  if (estimatedMB < 1) {
    return `~${Math.round(estimatedMB * 1024)} KB`;
  } else {
    return `~${estimatedMB.toFixed(1)} MB`;
  }
};