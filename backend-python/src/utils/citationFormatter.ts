import { LegislativeDocument } from '../types';

export class ABNTCitationFormatter {
  static formatLegislation(doc: LegislativeDocument): string {
    const country = 'BRASIL';
    const institution = this.getInstitution(doc.source);
    const type = this.formatDocumentType(doc.type);
    const number = doc.number;
    const date = new Date(doc.date);
    const formattedDate = date.toLocaleDateString('pt-BR');
    const year = date.getFullYear();
    
    // ABNT NBR 6023:2018 format for legislation
    return `${country}. ${institution}. ${type} nº ${number}, de ${formattedDate}. ${doc.title}. ${doc.source}, ${this.getPublicationPlace(doc.source)}, ${year}. ${doc.url ? `Disponível em: ${doc.url}. ` : ''}Acesso em: ${new Date().toLocaleDateString('pt-BR')}.`;
  }
  
  private static getInstitution(source: string): string {
    if (source.includes('Câmara')) return 'Câmara dos Deputados';
    if (source.includes('Senado')) return 'Senado Federal';
    if (source.includes('LexML')) return 'Presidência da República';
    return 'Governo Federal';
  }
  
  private static formatDocumentType(type: string): string {
    const types: Record<string, string> = {
      'lei': 'Lei',
      'decreto': 'Decreto',
      'portaria': 'Portaria',
      'resolucao': 'Resolução',
      'medida_provisoria': 'Medida Provisória'
    };
    return types[type] || type.charAt(0).toUpperCase() + type.slice(1);
  }
  
  private static getPublicationPlace(source: string): string {
    return 'Brasília, DF';
  }
}