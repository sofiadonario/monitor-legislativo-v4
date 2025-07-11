import { ABNTCitationFormatter } from '../citationFormatter';
import { LegislativeDocument } from '../../types';

describe('ABNTCitationFormatter', () => {
  const mockDocument: LegislativeDocument = {
    id: '1',
    title: 'Lei dos Transportes Urbanos',
    summary: 'Regulamenta o transporte urbano no Brasil',
    type: 'lei',
    number: '12345',
    date: '2023-01-15',
    source: 'Câmara dos Deputados',
    url: 'https://www.camara.leg.br/lei/12345',
    keywords: ['transporte', 'urbano'],
    state: 'DF',
    municipality: 'Brasília'
  };

  describe('formatLegislation', () => {
    it('should format legislation document according to ABNT NBR 6023:2018', () => {
      const citation = ABNTCitationFormatter.formatLegislation(mockDocument);
      
      expect(citation).toContain('BRASIL.');
      expect(citation).toContain('Câmara dos Deputados.');
      expect(citation).toContain('Lei nº 12345');
      expect(citation).toContain('15/01/2023');
      expect(citation).toContain('Lei dos Transportes Urbanos');
      expect(citation).toContain('Brasília, DF');
      expect(citation).toContain('2023');
      expect(citation).toContain('https://www.camara.leg.br/lei/12345');
      expect(citation).toMatch(/Acesso em: \d{2}\/\d{2}\/\d{4}/);
    });

    it('should handle different document types correctly', () => {
      const decreeDoc = { ...mockDocument, type: 'decreto' };
      const citation = ABNTCitationFormatter.formatLegislation(decreeDoc);
      expect(citation).toContain('Decreto nº 12345');
    });

    it('should handle different sources correctly', () => {
      const senadoDoc = { ...mockDocument, source: 'Senado Federal' };
      const citation = ABNTCitationFormatter.formatLegislation(senadoDoc);
      expect(citation).toContain('Senado Federal.');
    });

    it('should handle documents without URL', () => {
      const docWithoutUrl = { ...mockDocument, url: undefined };
      const citation = ABNTCitationFormatter.formatLegislation(docWithoutUrl);
      expect(citation).not.toContain('Disponível em:');
      expect(citation).toMatch(/Acesso em: \d{2}\/\d{2}\/\d{4}/);
    });

    it('should handle unknown document types', () => {
      const unknownTypeDoc = { ...mockDocument, type: 'instrucao_normativa' };
      const citation = ABNTCitationFormatter.formatLegislation(unknownTypeDoc);
      expect(citation).toContain('Instrucao_normativa nº 12345');
    });

    it('should handle LexML source', () => {
      const lexmlDoc = { ...mockDocument, source: 'LexML Brasil' };
      const citation = ABNTCitationFormatter.formatLegislation(lexmlDoc);
      expect(citation).toContain('Presidência da República.');
    });
  });
});