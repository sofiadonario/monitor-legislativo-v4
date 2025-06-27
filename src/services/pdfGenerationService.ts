import html2canvas from 'html2canvas';
import { apiConfig } from '../config/api';

export interface DocumentExportOptions {
  format: 'pdf' | 'word' | 'html' | 'txt' | 'citation';
  citationStyle?: 'abnt' | 'apa' | 'chicago' | 'vancouver';
  includeMetadata: boolean;
  includeCitation: boolean;
  includeAnalysis: boolean;
  pageSize?: 'a4' | 'letter' | 'legal';
  orientation?: 'portrait' | 'landscape';
  fontSize?: number;
  margins?: {
    top: number;
    right: number;
    bottom: number;
    left: number;
  };
}

export interface DocumentContent {
  id: string;
  title: string;
  content: string;
  metadata: {
    authors?: string[];
    date?: string;
    source?: string;
    url?: string;
    documentType?: string;
    urn?: string;
    [key: string]: any;
  };
  citation?: string;
  analysis?: {
    summary?: string;
    keyPoints?: string[];
    entities?: any[];
    relatedDocuments?: string[];
  };
}

export interface ExportResult {
  success: boolean;
  downloadUrl?: string;
  filename?: string;
  error?: string;
  exportedAt: Date;
  format: string;
  fileSize?: number;
}

class PdfGenerationService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = apiConfig.baseUrl;
  }

  // Generate PDF from document content
  async generatePdf(content: DocumentContent, options: DocumentExportOptions): Promise<ExportResult> {
    try {
      const htmlContent = this.generateHtmlContent(content, options);
      
      // For client-side PDF generation using html2canvas and jsPDF simulation
      // In production, this would likely be handled by the backend
      const blob = await this.createPdfBlob(htmlContent, options);
      
      const filename = this.generateFilename(content, 'pdf');
      const downloadUrl = URL.createObjectURL(blob);

      return {
        success: true,
        downloadUrl,
        filename,
        exportedAt: new Date(),
        format: 'pdf',
        fileSize: blob.size
      };
    } catch (error) {
      console.error('PDF generation failed:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        exportedAt: new Date(),
        format: 'pdf'
      };
    }
  }

  // Generate formatted HTML content
  private generateHtmlContent(content: DocumentContent, options: DocumentExportOptions): string {
    const { includeMetadata, includeCitation, includeAnalysis, fontSize = 12 } = options;
    
    let html = `
      <!DOCTYPE html>
      <html lang="pt-BR">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${content.title}</title>
        <style>
          body {
            font-family: 'Times New Roman', serif;
            font-size: ${fontSize}px;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
            background: white;
          }
          
          .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #1e40af;
            padding-bottom: 20px;
          }
          
          .title {
            font-size: ${fontSize + 8}px;
            font-weight: bold;
            color: #1e40af;
            margin-bottom: 10px;
            line-height: 1.3;
          }
          
          .metadata {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
          }
          
          .metadata h3 {
            color: #1e40af;
            margin-top: 0;
            font-size: ${fontSize + 2}px;
          }
          
          .metadata-item {
            margin: 8px 0;
            display: flex;
            flex-wrap: wrap;
          }
          
          .metadata-label {
            font-weight: bold;
            min-width: 120px;
            color: #374151;
          }
          
          .metadata-value {
            flex: 1;
            color: #6b7280;
          }
          
          .content {
            margin: 30px 0;
            text-align: justify;
            line-height: 1.8;
          }
          
          .content h1, .content h2, .content h3 {
            color: #1e40af;
            margin-top: 30px;
            margin-bottom: 15px;
          }
          
          .content h1 { font-size: ${fontSize + 6}px; }
          .content h2 { font-size: ${fontSize + 4}px; }
          .content h3 { font-size: ${fontSize + 2}px; }
          
          .content p {
            margin: 12px 0;
            text-indent: 20px;
          }
          
          .content ul, .content ol {
            margin: 15px 0;
            padding-left: 30px;
          }
          
          .citation {
            background: #eff6ff;
            border-left: 4px solid #3b82f6;
            padding: 15px;
            margin: 20px 0;
            font-style: italic;
          }
          
          .citation h3 {
            margin-top: 0;
            color: #1e40af;
            font-size: ${fontSize + 2}px;
          }
          
          .analysis {
            background: #f0fdf4;
            border: 1px solid #22c55e;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
          }
          
          .analysis h3 {
            color: #16a34a;
            margin-top: 0;
            font-size: ${fontSize + 2}px;
          }
          
          .key-points {
            list-style-type: none;
            padding: 0;
          }
          
          .key-points li {
            background: #dcfce7;
            margin: 8px 0;
            padding: 10px;
            border-radius: 4px;
            border-left: 3px solid #22c55e;
          }
          
          .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            font-size: ${fontSize - 2}px;
            color: #6b7280;
            text-align: center;
          }
          
          .watermark {
            position: fixed;
            bottom: 20px;
            right: 20px;
            opacity: 0.3;
            font-size: 10px;
            color: #9ca3af;
            transform: rotate(-45deg);
          }
          
          @media print {
            body { margin: 0; }
            .watermark { display: none; }
          }
        </style>
      </head>
      <body>
        <div class="watermark">Monitor Legislativo v4</div>
        
        <div class="header">
          <h1 class="title">${content.title}</h1>
          <p>Gerado pelo Monitor Legislativo v4 em ${new Date().toLocaleDateString('pt-BR')}</p>
        </div>
    `;

    // Add metadata section
    if (includeMetadata && content.metadata) {
      html += `
        <div class="metadata">
          <h3>Metadados do Documento</h3>
      `;

      const metadataFields = [
        { key: 'documentType', label: 'Tipo de Documento' },
        { key: 'authors', label: 'Autores' },
        { key: 'date', label: 'Data' },
        { key: 'source', label: 'Fonte' },
        { key: 'urn', label: 'URN' },
        { key: 'url', label: 'URL' }
      ];

      metadataFields.forEach(field => {
        const value = content.metadata[field.key];
        if (value) {
          let displayValue = value;
          if (Array.isArray(value)) {
            displayValue = value.join(', ');
          }
          
          html += `
            <div class="metadata-item">
              <div class="metadata-label">${field.label}:</div>
              <div class="metadata-value">${displayValue}</div>
            </div>
          `;
        }
      });

      html += '</div>';
    }

    // Add main content
    html += `
      <div class="content">
        ${this.formatContent(content.content)}
      </div>
    `;

    // Add analysis section
    if (includeAnalysis && content.analysis) {
      html += `
        <div class="analysis">
          <h3>Análise do Documento</h3>
      `;

      if (content.analysis.summary) {
        html += `
          <h4>Resumo</h4>
          <p>${content.analysis.summary}</p>
        `;
      }

      if (content.analysis.keyPoints && content.analysis.keyPoints.length > 0) {
        html += `
          <h4>Pontos Principais</h4>
          <ul class="key-points">
        `;
        content.analysis.keyPoints.forEach(point => {
          html += `<li>${point}</li>`;
        });
        html += '</ul>';
      }

      if (content.analysis.relatedDocuments && content.analysis.relatedDocuments.length > 0) {
        html += `
          <h4>Documentos Relacionados</h4>
          <ul>
        `;
        content.analysis.relatedDocuments.forEach(doc => {
          html += `<li>${doc}</li>`;
        });
        html += '</ul>';
      }

      html += '</div>';
    }

    // Add citation section
    if (includeCitation && content.citation) {
      html += `
        <div class="citation">
          <h3>Citação Acadêmica</h3>
          <p>${content.citation}</p>
        </div>
      `;
    }

    // Add footer
    html += `
        <div class="footer">
          <p>Este documento foi gerado automaticamente pelo Monitor Legislativo v4</p>
          <p>Data de geração: ${new Date().toLocaleString('pt-BR')}</p>
          <p>Plataforma de pesquisa acadêmica para legislação brasileira</p>
        </div>
      </body>
      </html>
    `;

    return html;
  }

  // Format content with basic HTML processing
  private formatContent(content: string): string {
    // Convert line breaks to paragraphs
    let formatted = content
      .split('\n\n')
      .map(paragraph => paragraph.trim())
      .filter(paragraph => paragraph.length > 0)
      .map(paragraph => `<p>${paragraph}</p>`)
      .join('\n');

    // Basic text formatting
    formatted = formatted
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>') // Bold
      .replace(/\*(.*?)\*/g, '<em>$1</em>') // Italic
      .replace(/`(.*?)`/g, '<code>$1</code>') // Code
      .replace(/\n- /g, '\n<li>') // List items
      .replace(/(<li>.*?)(?=\n(?!<li>))/gs, '<ul>$1</ul>'); // Wrap lists

    return formatted;
  }

  // Create PDF blob (simplified - in production would use proper PDF library)
  private async createPdfBlob(htmlContent: string, options: DocumentExportOptions): Promise<Blob> {
    // Create temporary container
    const container = document.createElement('div');
    container.innerHTML = htmlContent;
    container.style.cssText = `
      position: absolute;
      top: -10000px;
      left: -10000px;
      width: 800px;
      background: white;
      font-family: 'Times New Roman', serif;
    `;
    
    document.body.appendChild(container);

    try {
      // Capture as canvas
      const canvas = await html2canvas(container, {
        backgroundColor: '#ffffff',
        scale: 2,
        useCORS: true,
        allowTaint: true
      });

      // Convert to blob
      return new Promise((resolve) => {
        canvas.toBlob((blob) => {
          resolve(blob || new Blob());
        }, 'image/png', 0.95);
      });
    } finally {
      document.body.removeChild(container);
    }
  }

  // Export as different formats
  async exportDocument(content: DocumentContent, options: DocumentExportOptions): Promise<ExportResult> {
    switch (options.format) {
      case 'pdf':
        return this.generatePdf(content, options);
      case 'html':
        return this.exportAsHtml(content, options);
      case 'txt':
        return this.exportAsText(content, options);
      case 'citation':
        return this.exportAsCitation(content, options);
      default:
        return {
          success: false,
          error: `Unsupported format: ${options.format}`,
          exportedAt: new Date(),
          format: options.format
        };
    }
  }

  // Export as HTML
  private async exportAsHtml(content: DocumentContent, options: DocumentExportOptions): Promise<ExportResult> {
    try {
      const htmlContent = this.generateHtmlContent(content, options);
      const blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
      const filename = this.generateFilename(content, 'html');
      const downloadUrl = URL.createObjectURL(blob);

      return {
        success: true,
        downloadUrl,
        filename,
        exportedAt: new Date(),
        format: 'html',
        fileSize: blob.size
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        exportedAt: new Date(),
        format: 'html'
      };
    }
  }

  // Export as plain text
  private async exportAsText(content: DocumentContent, options: DocumentExportOptions): Promise<ExportResult> {
    try {
      let textContent = `${content.title}\n`;
      textContent += '='.repeat(content.title.length) + '\n\n';

      if (options.includeMetadata && content.metadata) {
        textContent += 'METADADOS\n---------\n';
        Object.entries(content.metadata).forEach(([key, value]) => {
          if (value) {
            const displayValue = Array.isArray(value) ? value.join(', ') : value;
            textContent += `${key}: ${displayValue}\n`;
          }
        });
        textContent += '\n';
      }

      textContent += 'CONTEÚDO\n--------\n';
      textContent += content.content + '\n\n';

      if (options.includeAnalysis && content.analysis) {
        textContent += 'ANÁLISE\n-------\n';
        if (content.analysis.summary) {
          textContent += `Resumo: ${content.analysis.summary}\n\n`;
        }
        if (content.analysis.keyPoints) {
          textContent += 'Pontos Principais:\n';
          content.analysis.keyPoints.forEach((point, index) => {
            textContent += `${index + 1}. ${point}\n`;
          });
          textContent += '\n';
        }
      }

      if (options.includeCitation && content.citation) {
        textContent += 'CITAÇÃO\n-------\n';
        textContent += content.citation + '\n\n';
      }

      textContent += `\nGerado pelo Monitor Legislativo v4 em ${new Date().toLocaleString('pt-BR')}`;

      const blob = new Blob([textContent], { type: 'text/plain;charset=utf-8' });
      const filename = this.generateFilename(content, 'txt');
      const downloadUrl = URL.createObjectURL(blob);

      return {
        success: true,
        downloadUrl,
        filename,
        exportedAt: new Date(),
        format: 'txt',
        fileSize: blob.size
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        exportedAt: new Date(),
        format: 'txt'
      };
    }
  }

  // Export citation only
  private async exportAsCitation(content: DocumentContent, options: DocumentExportOptions): Promise<ExportResult> {
    try {
      let citationContent = `CITAÇÃO ACADÊMICA\n${content.title}\n\n`;
      
      if (content.citation) {
        citationContent += `Formato: ${options.citationStyle?.toUpperCase() || 'ABNT'}\n`;
        citationContent += `Citação: ${content.citation}\n\n`;
      }

      citationContent += `Gerado em: ${new Date().toLocaleString('pt-BR')}\n`;
      citationContent += 'Monitor Legislativo v4 - Plataforma de Pesquisa Acadêmica';

      const blob = new Blob([citationContent], { type: 'text/plain;charset=utf-8' });
      const filename = this.generateFilename(content, 'txt', 'citacao');
      const downloadUrl = URL.createObjectURL(blob);

      return {
        success: true,
        downloadUrl,
        filename,
        exportedAt: new Date(),
        format: 'citation',
        fileSize: blob.size
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        exportedAt: new Date(),
        format: 'citation'
      };
    }
  }

  // Generate filename for downloads
  private generateFilename(content: DocumentContent, extension: string, prefix?: string): string {
    const sanitizedTitle = content.title
      .replace(/[^a-zA-Z0-9\s-]/g, '')
      .replace(/\s+/g, '_')
      .substring(0, 50);
    
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
    const prefixPart = prefix ? `${prefix}_` : '';
    
    return `${prefixPart}${sanitizedTitle}_${timestamp}.${extension}`;
  }

  // Download file
  downloadFile(downloadUrl: string, filename: string): void {
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    link.style.display = 'none';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Clean up URL after download
    setTimeout(() => {
      URL.revokeObjectURL(downloadUrl);
    }, 1000);
  }

  // Get default export options
  getDefaultOptions(): DocumentExportOptions {
    return {
      format: 'pdf',
      citationStyle: 'abnt',
      includeMetadata: true,
      includeCitation: true,
      includeAnalysis: false,
      pageSize: 'a4',
      orientation: 'portrait',
      fontSize: 12,
      margins: {
        top: 20,
        right: 20,
        bottom: 20,
        left: 20
      }
    };
  }
}

export const pdfGenerationService = new PdfGenerationService();