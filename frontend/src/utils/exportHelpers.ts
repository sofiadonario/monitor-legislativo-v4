import Papa from 'papaparse';
import { ExportOptions, LegislativeDocument } from '../types';

/**
 * Export documents to CSV format
 */
export const exportToCSV = (documents: LegislativeDocument[], options: ExportOptions) => {
  const csvData = documents.map(doc => ({
    'ID': doc.id,
    'Título': doc.title,
    'Tipo': doc.type,
    'Número': doc.number,
    'Data': doc.date,
    'Estado': doc.state || '',
    'Município': doc.municipality || '',
    'Resumo': doc.summary,
    'Palavras-chave': doc.keywords.join(', '),
    ...(options.includeMetadata && {
      'Fonte': doc.source,
      'Citação': doc.citation,
      'URL': doc.url || ''
    })
  }));

  const csv = Papa.unparse(csvData);
  downloadFile(csv, `transport-legislation-data-${new Date().toISOString()}.csv`, 'text/csv');
};

/**
 * Export documents to XML format
 */
export const exportToXML = (documents: LegislativeDocument[], options: ExportOptions) => {
  const xmlHeader = '<?xml version="1.0" encoding="UTF-8"?>\n';
  const rootStart = '<documentos_legislativos>\n';
  const metadata = `  <metadata>\n    <data_exportacao>${new Date().toISOString()}</data_exportacao>\n    <total_documentos>${documents.length}</total_documentos>\n  </metadata>\n`;
  
  const documentsXML = documents.map(doc => {
    const keywords = doc.keywords.map(k => `      <palavra_chave>${escapeXML(k)}</palavra_chave>`).join('\n');
    
    return `  <documento>
    <id>${doc.id}</id>
    <titulo>${escapeXML(doc.title)}</titulo>
    <tipo>${doc.type}</tipo>
    <numero>${escapeXML(doc.number)}</numero>
    <data>${doc.date}</data>
    ${doc.state ? `<estado>${doc.state}</estado>` : ''}
    ${doc.municipality ? `<municipio>${escapeXML(doc.municipality)}</municipio>` : ''}
    <resumo>${escapeXML(doc.summary)}</resumo>
    <palavras_chave>
${keywords}
    </palavras_chave>
    ${options.includeMetadata ? `<metadados>
      <fonte>${escapeXML(doc.source)}</fonte>
      <citacao>${escapeXML(doc.citation)}</citacao>
      ${doc.url ? `<url>${escapeXML(doc.url)}</url>` : ''}
    </metadados>` : ''}
  </documento>`;
  }).join('\n');
  
  const rootEnd = '\n</documentos_legislativos>';
  
  const xml = xmlHeader + rootStart + metadata + documentsXML + rootEnd;
  downloadFile(xml, `transport-legislation-data-${new Date().toISOString()}.xml`, 'application/xml');
};

/**
 * Export documents to HTML format
 */
export const exportToHTML = (documents: LegislativeDocument[], options: ExportOptions) => {
  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Dados Legislativos</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2196F3;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2196F3;
            margin: 0;
        }
        .summary {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        .document {
            border: 1px solid #ddd;
            margin-bottom: 20px;
            padding: 20px;
            border-radius: 5px;
            background: #fafafa;
        }
        .document h3 {
            color: #1976D2;
            margin-top: 0;
        }
        .doc-meta {
            background: #fff;
            padding: 10px;
            border-left: 4px solid #4CAF50;
            margin: 10px 0;
        }
        .keywords {
            background: #f0f0f0;
            padding: 5px 10px;
            border-radius: 15px;
            display: inline-block;
            margin: 2px;
            font-size: 0.9em;
        }
        .citation {
            background: #fff3e0;
            padding: 10px;
            border-left: 4px solid #FF9800;
            margin-top: 10px;
            font-style: italic;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Transport Legislation Academic Report</h1>
            <p>Brazilian Transport Legislation Monitor - Academic Research Platform</p>
            <p>Gerado em: ${new Date().toLocaleDateString('pt-BR', { 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            })}</p>
        </div>
        
        <div class="summary">
            <h2>Resumo da Pesquisa</h2>
            <p><strong>Total de documentos encontrados:</strong> ${documents.length}</p>
            <p><strong>Estados com legislação:</strong> ${[...new Set(documents.filter(d => d.state).map(d => d.state))].length}</p>
            <p><strong>Tipos de documentos:</strong> ${[...new Set(documents.map(d => d.type))].join(', ')}</p>
            <p><strong>Período:</strong> ${getDateRange(documents)}</p>
        </div>
        
        <div class="documents">
            ${documents.map((doc, index) => `
                <div class="document">
                    <h3>${index + 1}. ${escapeXML(doc.title)}</h3>
                    
                    <div class="doc-meta">
                        <strong>Tipo:</strong> ${doc.type.charAt(0).toUpperCase() + doc.type.slice(1)} | 
                        <strong>Número:</strong> ${escapeXML(doc.number)} | 
                        <strong>Data:</strong> ${new Date(doc.date).toLocaleDateString('pt-BR')}
                        ${doc.state ? ` | <strong>Estado:</strong> ${doc.state}` : ''}
                        ${doc.municipality ? ` | <strong>Município:</strong> ${escapeXML(doc.municipality)}` : ''}
                    </div>
                    
                    <p><strong>Resumo:</strong> ${escapeXML(doc.summary)}</p>
                    
                    <div>
                        <strong>Palavras-chave:</strong><br>
                        ${doc.keywords.map(keyword => `<span class="keywords">${escapeXML(keyword)}</span>`).join(' ')}
                    </div>
                    
                    ${options.includeMetadata ? `
                        <div class="citation">
                            <strong>Citação acadêmica:</strong><br>
                            ${escapeXML(doc.citation)}
                            ${doc.url ? `<br><strong>URL:</strong> <a href="${doc.url}" target="_blank">${doc.url}</a>` : ''}
                        </div>
                    ` : ''}
                </div>
            `).join('')}
        </div>
        
        <div class="footer">
            <p><strong>Citação sugerida para esta pesquisa:</strong></p>
            <p>Academic Transport Legislation Monitor. Brazilian transport legislation georeferenced data. 
               Exportado em ${new Date().toLocaleDateString('pt-BR')}. 
               Disponível em: [URL da aplicação].</p>
            <p><em>Este relatório foi gerado automaticamente. Sempre verifique as fontes originais.</em></p>
        </div>
    </div>
</body>
</html>`;

  downloadFile(html, `transport-legislation-report-${new Date().toISOString()}.html`, 'text/html');
};

/**
 * Helper function to escape XML special characters
 */
const escapeXML = (str: string): string => {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

/**
 * Helper function to get date range from documents
 */
const getDateRange = (documents: LegislativeDocument[]): string => {
  if (documents.length === 0) return 'N/A';
  
  const dates = documents.map(doc => new Date(doc.date));
  const minDate = new Date(Math.min.apply(null, dates as any));
  const maxDate = new Date(Math.max.apply(null, dates as any));
  
  return `${minDate.toLocaleDateString('pt-BR')} a ${maxDate.toLocaleDateString('pt-BR')}`;
};

/**
 * Helper function to download a file
 */
const downloadFile = (content: string, filename: string, mimeType: string) => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  
  document.body.appendChild(a);
  a.click();
  
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

/**
 * Export documents to BibTeX format for academic citations
 */
export { exportToBibTeX } from './academicExports';
