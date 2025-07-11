import { LegislativeDocument } from '../types';

export const exportToBibTeX = (documents: LegislativeDocument[]) => {
  const entries = documents.map(doc => {
    const authors = doc.source.includes('Câmara') ? 'Brasil. Câmara dos Deputados' :
                   doc.source.includes('Senado') ? 'Brasil. Senado Federal' :
                   doc.source.includes('LexML') ? 'Brasil. LexML' :
                   'Brasil';
    
    const year = new Date(doc.date).getFullYear();
    const key = `${doc.type}${doc.number.replace(/[^0-9]/g, '')}${year}`;
    
    return `@legislation{${key},
  title={${doc.title}},
  author={${authors}},
  year={${year}},
  type={${doc.type}},
  number={${doc.number}},
  institution={${doc.source}},
  url={${doc.url || ''}},
  note={Accessed: ${new Date().toLocaleDateString('en-CA')}}
}`;
  }).join('\n\n');
  
  const bibTeX = `% BibTeX export from Brazilian Transport Legislation Monitor
% Generated: ${new Date().toISOString()}
% Total entries: ${documents.length}

${entries}`;

  const blob = new Blob([bibTeX], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `transport-legislation-${new Date().toISOString()}.bib`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};