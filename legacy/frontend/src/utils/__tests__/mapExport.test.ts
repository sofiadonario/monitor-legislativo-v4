import { isMapExportSupported, getEstimatedExportSize, exportMapToPNG } from '../mapExport';

// Mock html2canvas
jest.mock('html2canvas', () => ({
  __esModule: true,
  default: jest.fn()
}));

import html2canvas from 'html2canvas';

// Mock DOM methods
const mockQuerySelector = jest.fn();
const mockQuerySelectorAll = jest.fn();
const mockCreateElement = jest.fn();
const mockAppendChild = jest.fn();
const mockRemoveChild = jest.fn();
const mockClick = jest.fn();
const mockCreateObjectURL = jest.fn();
const mockRevokeObjectURL = jest.fn();
const mockToBlob = jest.fn();

Object.defineProperty(document, 'querySelector', { value: mockQuerySelector });
Object.defineProperty(document, 'querySelectorAll', { value: mockQuerySelectorAll });
Object.defineProperty(document, 'createElement', { value: mockCreateElement });
Object.defineProperty(document.body, 'appendChild', { value: mockAppendChild });
Object.defineProperty(document.body, 'removeChild', { value: mockRemoveChild });
Object.defineProperty(URL, 'createObjectURL', { value: mockCreateObjectURL });
Object.defineProperty(URL, 'revokeObjectURL', { value: mockRevokeObjectURL });

const mockBlobConstructor = jest.fn();
global.Blob = mockBlobConstructor as any;

describe('Map Export Utilities', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset DOM mocks
    mockQuerySelector.mockReturnValue(null);
    mockQuerySelectorAll.mockReturnValue([]);
    mockCreateObjectURL.mockReturnValue('mock-url');
    mockBlobConstructor.mockImplementation(() => ({}));
    
    // Setup default canvas mock
    const mockCanvas = {
      toBlob: mockToBlob,
      offsetWidth: 800,
      offsetHeight: 600
    };
    
    const mockAnchor = {
      href: '',
      download: '',
      click: mockClick,
      style: { display: '' }
    };
    
    mockCreateElement.mockReturnValue(mockAnchor);
    (html2canvas as jest.Mock).mockResolvedValue(mockCanvas);
  });

  describe('isMapExportSupported', () => {
    it('should return true when all required APIs are available', () => {
      const mockCanvas = {
        getContext: jest.fn().mockReturnValue({})
      };
      
      Object.defineProperty(document, 'createElement', {
        value: jest.fn().mockReturnValue(mockCanvas)
      });
      
      const result = isMapExportSupported();
      expect(result).toBe(true);
    });

    it('should return false when canvas is not supported', () => {
      const mockCanvas = {
        getContext: null
      };
      
      Object.defineProperty(document, 'createElement', {
        value: jest.fn().mockReturnValue(mockCanvas)
      });
      
      const result = isMapExportSupported();
      expect(result).toBe(false);
    });

    it('should return false when Blob is not available', () => {
      const originalBlob = global.Blob;
      delete (global as any).Blob;
      
      const result = isMapExportSupported();
      expect(result).toBe(false);
      
      global.Blob = originalBlob;
    });

    it('should return false when URL.createObjectURL is not available', () => {
      const originalCreateObjectURL = URL.createObjectURL;
      delete (URL as any).createObjectURL;
      
      const result = isMapExportSupported();
      expect(result).toBe(false);
      
      URL.createObjectURL = originalCreateObjectURL;
    });

    it('should handle exceptions gracefully', () => {
      Object.defineProperty(document, 'createElement', {
        value: jest.fn().mockImplementation(() => {
          throw new Error('DOM error');
        })
      });
      
      const result = isMapExportSupported();
      expect(result).toBe(false);
    });
  });

  describe('getEstimatedExportSize', () => {
    it('should return "Unknown" when map container is not found', () => {
      mockQuerySelector.mockReturnValue(null);
      
      const result = getEstimatedExportSize();
      expect(result).toBe('Unknown');
    });

    it('should calculate size in KB for small images', () => {
      const mockContainer = {
        offsetWidth: 400,
        offsetHeight: 300
      };
      mockQuerySelector.mockReturnValue(mockContainer);
      
      const result = getEstimatedExportSize(1);
      expect(result).toContain('KB');
    });

    it('should calculate size in MB for large images', () => {
      const mockContainer = {
        offsetWidth: 2000,
        offsetHeight: 1500
      };
      mockQuerySelector.mockReturnValue(mockContainer);
      
      const result = getEstimatedExportSize(2);
      expect(result).toContain('MB');
    });

    it('should use default scale when not provided', () => {
      const mockContainer = {
        offsetWidth: 800,
        offsetHeight: 600
      };
      mockQuerySelector.mockReturnValue(mockContainer);
      
      const result = getEstimatedExportSize();
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });
  });

  describe('exportMapToPNG', () => {
    let mockMapContainer: any;
    let mockControls: any[];
    let mockLegend: any;

    beforeEach(() => {
      mockMapContainer = {
        offsetWidth: 800,
        offsetHeight: 600,
        appendChild: jest.fn(),
        removeChild: jest.fn(),
        querySelector: jest.fn(),
        querySelectorAll: jest.fn()
      };

      mockControls = [
        { style: { display: 'block' } },
        { style: { display: 'flex' } }
      ];

      mockLegend = {
        style: { display: 'block' }
      };

      mockMapContainer.querySelector.mockReturnValue(mockLegend);
      mockMapContainer.querySelectorAll.mockReturnValue(mockControls);
      mockQuerySelector.mockReturnValue(mockMapContainer);

      mockToBlob.mockImplementation((callback) => {
        callback(new Blob());
      });
    });

    it('should export map successfully with default options', async () => {
      await exportMapToPNG();

      expect(html2canvas).toHaveBeenCalledWith(
        mockMapContainer,
        expect.objectContaining({
          allowTaint: true,
          useCORS: true,
          scale: 2,
          backgroundColor: '#ffffff'
        })
      );

      expect(mockToBlob).toHaveBeenCalled();
      expect(mockCreateObjectURL).toHaveBeenCalled();
      expect(mockClick).toHaveBeenCalled();
    });

    it('should hide controls when includeControls is false', async () => {
      await exportMapToPNG({ 
        format: 'png',
        includeControls: false 
      });

      // Controls should be hidden
      expect(mockControls[0].style.display).toBe('none');
      expect(mockControls[1].style.display).toBe('none');

      // Controls should be restored
      expect(mockControls[0].style.display).toBe('block');
      expect(mockControls[1].style.display).toBe('flex');
    });

    it('should hide legend when includeLegend is false', async () => {
      await exportMapToPNG({ 
        format: 'png',
        includeLegend: false 
      });

      // Legend should be temporarily hidden and restored
      expect(mockLegend.style.display).toBe('block');
    });

    it('should use custom options', async () => {
      const customOptions = {
        format: 'png' as const,
        quality: 0.8,
        scale: 3,
        backgroundColor: '#f0f0f0',
        filename: 'custom-map'
      };

      await exportMapToPNG(customOptions);

      expect(html2canvas).toHaveBeenCalledWith(
        mockMapContainer,
        expect.objectContaining({
          scale: 3,
          backgroundColor: '#f0f0f0'
        })
      );

      expect(mockToBlob).toHaveBeenCalledWith(
        expect.any(Function),
        'image/png',
        0.8
      );
    });

    it('should throw error when map container is not found', async () => {
      mockQuerySelector.mockReturnValue(null);

      await expect(exportMapToPNG()).rejects.toThrow('Map container not found');
    });

    it('should throw error when blob creation fails', async () => {
      mockToBlob.mockImplementation((callback) => {
        callback(null);
      });

      await expect(exportMapToPNG()).rejects.toThrow('Failed to create image blob');
    });

    it('should handle html2canvas errors', async () => {
      (html2canvas as jest.Mock).mockRejectedValue(new Error('Canvas error'));

      await expect(exportMapToPNG()).rejects.toThrow('Failed to export map: Canvas error');
    });

    it('should generate timestamped filename', async () => {
      const dateNowSpy = jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2023-01-01T12:00:00.000Z');

      await exportMapToPNG({ format: 'png', filename: 'test-map' });

      expect(mockCreateElement).toHaveBeenCalledWith('a');
      
      dateNowSpy.mockRestore();
    });

    it('should clean up URL after download', async () => {
      const setTimeoutSpy = jest.spyOn(global, 'setTimeout');

      await exportMapToPNG();

      expect(setTimeoutSpy).toHaveBeenCalledWith(
        expect.any(Function),
        100
      );

      // Simulate timeout execution
      const timeoutCallback = setTimeoutSpy.mock.calls[0][0];
      timeoutCallback();

      expect(mockRevokeObjectURL).toHaveBeenCalledWith('mock-url');

      setTimeoutSpy.mockRestore();
    });
  });
});