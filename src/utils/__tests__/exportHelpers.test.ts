import Papa from 'papaparse';
import { exportToCSV, exportToXML, exportToHTML } from '../exportHelpers';
import { LegislativeDocument, ExportOptions } from '../../types';

// Mock Papa.unparse
jest.mock('papaparse', () => ({
  unparse: jest.fn()
}));

// Mock global DOM methods
const mockCreateElement = jest.fn();
const mockAppendChild = jest.fn();
const mockRemoveChild = jest.fn();
const mockClick = jest.fn();
const mockCreateObjectURL = jest.fn();
const mockRevokeObjectURL = jest.fn();

Object.defineProperty(document, 'createElement', { value: mockCreateElement });
Object.defineProperty(document.body, 'appendChild', { value: mockAppendChild });
Object.defineProperty(document.body, 'removeChild', { value: mockRemoveChild });
Object.defineProperty(URL, 'createObjectURL', { value: mockCreateObjectURL });
Object.defineProperty(URL, 'revokeObjectURL', { value: mockRevokeObjectURL });

const mockBlobConstructor = jest.fn();
global.Blob = mockBlobConstructor as any;

describe('Export Helpers', () => {
  const mockDocuments: LegislativeDocument[] = [
    {
      id: '1',
      title: 'Lei de Transportes Test',
      summary: 'Regulamenta transporte público',
      type: 'lei',
      number: '12345',
      date: '2023-01-15',
      source: 'Câmara dos Deputados',
      url: 'https://example.com/lei1',
      keywords: ['transporte', 'público'],
      state: 'SP',
      municipality: 'São Paulo'
    },
    {
      id: '2',
      title: 'Decreto de Logística',
      summary: 'Regulamenta logística urbana',
      type: 'decreto',
      number: '67890',
      date: '2023-02-20',
      source: 'Senado Federal',
      url: 'https://example.com/decreto1',
      keywords: ['logística', 'urbana'],
      state: 'RJ',
      municipality: 'Rio de Janeiro'
    }
  ];

  const mockOptions: ExportOptions = {
    format: 'csv',
    includeMetadata: true,
    includeMap: false
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup DOM mocks
    const mockAnchor = {
      href: '',
      download: '',
      click: mockClick
    };
    mockCreateElement.mockReturnValue(mockAnchor);
    mockCreateObjectURL.mockReturnValue('mock-url');
    mockBlobConstructor.mockReturnValue(new Blob());
    
    // Mock Papa.unparse
    (Papa.unparse as jest.Mock).mockReturnValue('mocked,csv,data');
  });

  describe('exportToCSV', () => {
    it('should export documents to CSV format', () => {
      exportToCSV(mockDocuments, mockOptions);

      expect(Papa.unparse).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            'ID': '1',
            'Título': 'Lei de Transportes Test',
            'Tipo': 'lei',
            'Número': '12345',
            'Data': '2023-01-15',
            'Estado': 'SP',
            'Município': 'São Paulo',
            'Resumo': 'Regulamenta transporte público',
            'Palavras-chave': 'transporte, público',
            'Fonte': 'Câmara dos Deputados',
            'URL': 'https://example.com/lei1'
          })
        ])
      );

      expect(mockBlobConstructor).toHaveBeenCalledWith(['mocked,csv,data'], { type: 'text/csv' });
      expect(mockCreateElement).toHaveBeenCalledWith('a');
      expect(mockClick).toHaveBeenCalled();
    });

    it('should handle documents without optional fields', () => {
      const docsWithoutOptional = mockDocuments.map(doc => ({
        ...doc,
        state: undefined,
        municipality: undefined,
        url: undefined
      }));

      exportToCSV(docsWithoutOptional, { ...mockOptions, includeMetadata: false });

      expect(Papa.unparse).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({
            'Estado': '',
            'Município': '',
          })
        ])
      );
    });
  });

  describe('exportToXML', () => {
    it('should export documents to XML format', () => {
      exportToXML(mockDocuments, mockOptions);

      expect(mockBlobConstructor).toHaveBeenCalledWith(
        [expect.stringContaining('<?xml version="1.0" encoding="UTF-8"?>')],
        { type: 'application/xml' }
      );

      const xmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(xmlContent).toContain('<documentos_legislativos>');
      expect(xmlContent).toContain('<titulo>Lei de Transportes Test</titulo>');
      expect(xmlContent).toContain('<numero>12345</numero>');
      expect(xmlContent).toContain('<estado>SP</estado>');
      expect(xmlContent).toContain('<municipio>São Paulo</municipio>');
      expect(xmlContent).toContain('<palavra_chave>transporte</palavra_chave>');
      expect(xmlContent).toContain('<metadados>');
      expect(xmlContent).toContain('</documentos_legislativos>');
    });

    it('should escape XML special characters', () => {
      const docWithSpecialChars = [{
        ...mockDocuments[0],
        title: 'Lei com <caracteres> & "especiais"',
        summary: 'Resumo com caracteres especiais: <>&"\''
      }];

      exportToXML(docWithSpecialChars, mockOptions);

      const xmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(xmlContent).toContain('&lt;caracteres&gt; &amp; &quot;especiais&quot;');
      expect(xmlContent).toContain('&lt;&gt;&amp;&quot;&#39;');
    });

    it('should handle documents without optional metadata', () => {
      exportToXML(mockDocuments, { ...mockOptions, includeMetadata: false });

      const xmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(xmlContent).not.toContain('<metadados>');
    });
  });

  describe('exportToHTML', () => {
    it('should export documents to HTML format', () => {
      exportToHTML(mockDocuments, mockOptions);

      expect(mockBlobConstructor).toHaveBeenCalledWith(
        [expect.stringContaining('<!DOCTYPE html>')],
        { type: 'text/html' }
      );

      const htmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(htmlContent).toContain('<title>Relatório de Dados Legislativos</title>');
      expect(htmlContent).toContain('Transport Legislation Academic Report');
      expect(htmlContent).toContain('Lei de Transportes Test');
      expect(htmlContent).toContain('Total de documentos encontrados:</strong> 2');
      expect(htmlContent).toContain('Estados com legislação:</strong> 2');
      expect(htmlContent).toContain('class="keywords">transporte</span>');
    });

    it('should include metadata when option is enabled', () => {
      exportToHTML(mockDocuments, mockOptions);

      const htmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(htmlContent).toContain('Citação acadêmica:');
      expect(htmlContent).toContain('https://example.com/lei1');
    });

    it('should exclude metadata when option is disabled', () => {
      exportToHTML(mockDocuments, { ...mockOptions, includeMetadata: false });

      const htmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(htmlContent).not.toContain('Citação acadêmica:');
    });

    it('should handle documents without URLs', () => {
      const docsWithoutUrl = mockDocuments.map(doc => ({ ...doc, url: undefined }));
      exportToHTML(docsWithoutUrl, mockOptions);

      const htmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(htmlContent).not.toContain('<a href="undefined"');
    });

    it('should escape HTML special characters', () => {
      const docWithSpecialChars = [{
        ...mockDocuments[0],
        title: 'Lei com <script>alert("xss")</script>',
        summary: 'Resumo com <tags> & "aspas"'
      }];

      exportToHTML(docWithSpecialChars, mockOptions);

      const htmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(htmlContent).toContain('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
      expect(htmlContent).toContain('&lt;tags&gt; &amp; &quot;aspas&quot;');
    });

    it('should calculate date range correctly', () => {
      exportToHTML(mockDocuments, mockOptions);

      const htmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(htmlContent).toContain('15/01/2023 a 20/02/2023');
    });

    it('should handle empty document list', () => {
      exportToHTML([], mockOptions);

      const htmlContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(htmlContent).toContain('Total de documentos encontrados:</strong> 0');
      expect(htmlContent).toContain('Período:</strong> N/A');
    });
  });
});