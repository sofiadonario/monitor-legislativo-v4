import { exportToBibTeX } from '../academicExports';
import { LegislativeDocument } from '../../types';

// Mock DOM methods
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

describe('Academic Exports', () => {
  const mockDocuments: LegislativeDocument[] = [
    {
      id: '1',
      title: 'Lei Federal do Transporte Público',
      summary: 'Regulamenta o transporte público federal',
      type: 'lei',
      number: '12345',
      date: '2023-01-15',
      source: 'Câmara dos Deputados',
      url: 'https://www.camara.leg.br/lei/12345',
      keywords: ['transporte', 'público'],
      state: 'DF',
      municipality: 'Brasília'
    },
    {
      id: '2',
      title: 'Decreto sobre Logística de Cargas',
      summary: 'Regulamenta a logística de cargas no país',
      type: 'decreto',
      number: '67.890',
      date: '2023-06-20',
      source: 'Senado Federal',
      url: 'https://www.senado.leg.br/decreto/67890',
      keywords: ['logística', 'cargas'],
      state: 'SP',
      municipality: 'São Paulo'
    },
    {
      id: '3',
      title: 'Resolução de Trânsito Urbano',
      summary: 'Estabelece normas para o trânsito urbano',
      type: 'resolucao',
      number: 'ABC123',
      date: '2023-03-10',
      source: 'LexML Brasil',
      url: undefined,
      keywords: ['trânsito', 'urbano'],
      state: 'RJ',
      municipality: 'Rio de Janeiro'
    }
  ];

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
    
    // Mock Date for consistent testing
    jest.spyOn(Date.prototype, 'toLocaleDateString').mockReturnValue('2023-12-01');
    jest.spyOn(Date.prototype, 'toISOString').mockReturnValue('2023-12-01T10:00:00.000Z');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('exportToBibTeX', () => {
    it('should export documents to BibTeX format', () => {
      exportToBibTeX(mockDocuments);

      expect(mockBlobConstructor).toHaveBeenCalledWith(
        [expect.stringContaining('@legislation{')],
        { type: 'text/plain;charset=utf-8' }
      );

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      
      // Check header comments
      expect(bibTeXContent).toContain('% BibTeX export from Brazilian Transport Legislation Monitor');
      expect(bibTeXContent).toContain('% Generated: 2023-12-01T10:00:00.000Z');
      expect(bibTeXContent).toContain('% Total entries: 3');
    });

    it('should generate correct BibTeX entries for Câmara documents', () => {
      const camaraDoc = [mockDocuments[0]];
      exportToBibTeX(camaraDoc);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      
      expect(bibTeXContent).toContain('@legislation{lei123452023,');
      expect(bibTeXContent).toContain('title={Lei Federal do Transporte Público},');
      expect(bibTeXContent).toContain('author={Brasil. Câmara dos Deputados},');
      expect(bibTeXContent).toContain('year={2023},');
      expect(bibTeXContent).toContain('type={lei},');
      expect(bibTeXContent).toContain('number={12345},');
      expect(bibTeXContent).toContain('institution={Câmara dos Deputados},');
      expect(bibTeXContent).toContain('url={https://www.camara.leg.br/lei/12345},');
      expect(bibTeXContent).toContain('note={Accessed: 2023-12-01}');
    });

    it('should generate correct BibTeX entries for Senado documents', () => {
      const senadoDoc = [mockDocuments[1]];
      exportToBibTeX(senadoDoc);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      
      expect(bibTeXContent).toContain('@legislation{decreto678902023,');
      expect(bibTeXContent).toContain('author={Brasil. Senado Federal},');
      expect(bibTeXContent).toContain('institution={Senado Federal},');
    });

    it('should generate correct BibTeX entries for LexML documents', () => {
      const lexmlDoc = [mockDocuments[2]];
      exportToBibTeX(lexmlDoc);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      
      expect(bibTeXContent).toContain('@legislation{resolucaoABC2023,');
      expect(bibTeXContent).toContain('author={Brasil. LexML},');
      expect(bibTeXContent).toContain('institution={LexML Brasil},');
    });

    it('should handle documents without URLs', () => {
      const docWithoutUrl = [mockDocuments[2]];
      exportToBibTeX(docWithoutUrl);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(bibTeXContent).toContain('url={},');
    });

    it('should generate clean citation keys by removing non-numeric characters from numbers', () => {
      exportToBibTeX(mockDocuments);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      
      // Should clean "67.890" to "67890" in the key
      expect(bibTeXContent).toContain('@legislation{decreto678902023,');
      
      // Should clean "ABC123" to "123" in the key
      expect(bibTeXContent).toContain('@legislation{resolucao1232023,');
    });

    it('should handle unknown sources with default author', () => {
      const unknownSourceDoc = [{
        ...mockDocuments[0],
        source: 'Unknown Institution'
      }];
      
      exportToBibTeX(unknownSourceDoc);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(bibTeXContent).toContain('author={Brasil},');
    });

    it('should create download link with correct filename', () => {
      exportToBibTeX(mockDocuments);

      expect(mockCreateElement).toHaveBeenCalledWith('a');
      expect(mockCreateObjectURL).toHaveBeenCalledWith(expect.any(Object));
      expect(mockClick).toHaveBeenCalled();
      expect(mockAppendChild).toHaveBeenCalled();
      expect(mockRemoveChild).toHaveBeenCalled();
      expect(mockRevokeObjectURL).toHaveBeenCalledWith('mock-url');

      const mockAnchor = mockCreateElement.mock.results[0].value;
      expect(mockAnchor.download).toBe('transport-legislation-2023-12-01T10:00:00.000Z.bib');
    });

    it('should separate multiple entries with double newlines', () => {
      exportToBibTeX(mockDocuments);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      
      // Count occurrences of closing braces followed by double newlines
      const entryPattern = /}\n\n@legislation/g;
      const matches = bibTeXContent.match(entryPattern);
      
      // Should have 2 double newlines between 3 entries
      expect(matches).toHaveLength(2);
    });

    it('should handle empty document array', () => {
      exportToBibTeX([]);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      
      expect(bibTeXContent).toContain('% Total entries: 0');
      expect(bibTeXContent).not.toContain('@legislation{');
    });

    it('should handle documents with special characters in titles', () => {
      const docWithSpecialChars = [{
        ...mockDocuments[0],
        title: 'Lei com "aspas" e {chaves} especiais'
      }];
      
      exportToBibTeX(docWithSpecialChars);

      const bibTeXContent = mockBlobConstructor.mock.calls[0][0][0];
      expect(bibTeXContent).toContain('title={Lei com "aspas" e {chaves} especiais},');
    });
  });
});