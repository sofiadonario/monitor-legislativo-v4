/**
 * SearchTemplates Component
 * Pre-defined search templates for common research scenarios
 */
import React from 'react';
import { SearchFilters } from '../../types';

interface SearchTemplatesProps {
  onTemplateApply: (filters: SearchFilters) => void;
}

interface SearchTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  filters: SearchFilters;
  tags: string[];
}

const SEARCH_TEMPLATES: SearchTemplate[] = [
  {
    id: 'urban-transport',
    name: 'Urban Transport Policies',
    description: 'Laws and regulations related to urban transportation and mobility',
    category: 'Transport',
    tags: ['urban', 'mobility', 'public transport'],
    filters: {
      searchTerm: 'transporte urbano mobilidade',
      documentTypes: ['lei', 'decreto', 'resolucao'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['transporte', 'mobilidade', 'ônibus', 'metro', 'trânsito'],
      dateFrom: new Date('2010-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'highway-infrastructure',
    name: 'Highway Infrastructure',
    description: 'Federal and state highway construction and maintenance laws',
    category: 'Transport',
    tags: ['highway', 'infrastructure', 'construction'],
    filters: {
      searchTerm: 'rodovia infraestrutura construção',
      documentTypes: ['lei', 'decreto'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['rodovia', 'infraestrutura', 'construção', 'pedágio', 'concessão'],
      dateFrom: new Date('2015-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'aviation-regulation',
    name: 'Aviation Regulation',
    description: 'Civil aviation laws and airport regulations',
    category: 'Transport',
    tags: ['aviation', 'airport', 'regulation'],
    filters: {
      searchTerm: 'aviação aeroporto regulamentação',
      documentTypes: ['lei', 'decreto', 'portaria', 'resolucao'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['aviação', 'aeroporto', 'ANAC', 'voo', 'aeronave'],
      dateFrom: new Date('2005-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'port-maritime',
    name: 'Port and Maritime Law',
    description: 'Maritime transport and port administration legislation',
    category: 'Transport',
    tags: ['maritime', 'port', 'shipping'],
    filters: {
      searchTerm: 'porto marítimo navegação',
      documentTypes: ['lei', 'decreto'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['porto', 'navegação', 'marítimo', 'ANTAQ', 'cabotagem'],
      dateFrom: new Date('2000-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'railway-transport',
    name: 'Railway Transport',
    description: 'Railway infrastructure and passenger transport laws',
    category: 'Transport',
    tags: ['railway', 'train', 'infrastructure'],
    filters: {
      searchTerm: 'ferrovia trem transporte',
      documentTypes: ['lei', 'decreto', 'resolucao'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['ferrovia', 'trem', 'ANTT', 'transporte ferroviário'],
      dateFrom: new Date('2012-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'traffic-safety',
    name: 'Traffic Safety and Code',
    description: 'Traffic laws, safety regulations and Brazilian Traffic Code',
    category: 'Safety',
    tags: ['traffic', 'safety', 'code'],
    filters: {
      searchTerm: 'trânsito segurança código',
      documentTypes: ['lei', 'decreto', 'resolucao'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['trânsito', 'segurança', 'CNH', 'multa', 'CONTRAN'],
      dateFrom: new Date('1997-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'fuel-regulation',
    name: 'Fuel and Energy',
    description: 'Transportation fuel regulation and energy policies',
    category: 'Energy',
    tags: ['fuel', 'energy', 'regulation'],
    filters: {
      searchTerm: 'combustível energia regulamentação',
      documentTypes: ['lei', 'decreto', 'portaria'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['combustível', 'energia', 'ANP', 'gasolina', 'etanol', 'diesel'],
      dateFrom: new Date('2000-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'sustainable-transport',
    name: 'Sustainable Transportation',
    description: 'Environmental policies for transportation and clean mobility',
    category: 'Environment',
    tags: ['sustainable', 'environment', 'clean'],
    filters: {
      searchTerm: 'transporte sustentável meio ambiente',
      documentTypes: ['lei', 'decreto', 'resolucao'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['sustentável', 'meio ambiente', 'bicicleta', 'elétrico', 'emissão'],
      dateFrom: new Date('2008-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'logistics-freight',
    name: 'Logistics and Freight',
    description: 'Freight transport and logistics industry regulations',
    category: 'Commerce',
    tags: ['logistics', 'freight', 'cargo'],
    filters: {
      searchTerm: 'logística carga frete',
      documentTypes: ['lei', 'decreto', 'portaria'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['logística', 'carga', 'frete', 'caminhão', 'transporte rodoviário'],
      dateFrom: new Date('2010-01-01'),
      dateTo: undefined
    }
  },
  {
    id: 'accessibility-transport',
    name: 'Accessibility in Transport',
    description: 'Accessibility laws for public transportation and infrastructure',
    category: 'Accessibility',
    tags: ['accessibility', 'inclusion', 'disability'],
    filters: {
      searchTerm: 'acessibilidade transporte inclusão',
      documentTypes: ['lei', 'decreto', 'resolucao'],
      states: [],
      municipalities: [],
      chambers: ['Câmara dos Deputados', 'Senado Federal'],
      keywords: ['acessibilidade', 'inclusão', 'deficiência', 'cadeirante', 'idoso'],
      dateFrom: new Date('2000-01-01'),
      dateTo: undefined
    }
  }
];

const TEMPLATE_CATEGORIES = Array.from(
  new Set(SEARCH_TEMPLATES.map(template => template.category))
);

export const SearchTemplates: React.FC<SearchTemplatesProps> = ({
  onTemplateApply
}) => {
  const [selectedCategory, setSelectedCategory] = React.useState<string>('All');
  const [searchQuery, setSearchQuery] = React.useState('');

  const filteredTemplates = SEARCH_TEMPLATES.filter(template => {
    const matchesCategory = selectedCategory === 'All' || template.category === selectedCategory;
    const matchesSearch = searchQuery === '' || 
      template.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    
    return matchesCategory && matchesSearch;
  });

  const handleTemplateSelect = (template: SearchTemplate) => {
    onTemplateApply(template.filters);
  };

  return (
    <div className="search-templates">
      <div className="search-templates__header">
        <h3>Search Templates</h3>
        <p>Pre-configured searches for common research scenarios</p>
      </div>

      <div className="search-templates__controls">
        <div className="search-templates__search">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search templates..."
            className="search-templates__search-input"
          />
        </div>

        <div className="search-templates__category-filter">
          <label htmlFor="category-select">Category:</label>
          <select
            id="category-select"
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="search-templates__category-select"
          >
            <option value="All">All Categories</option>
            {TEMPLATE_CATEGORIES.map(category => (
              <option key={category} value={category}>
                {category}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="search-templates__grid">
        {filteredTemplates.map(template => (
          <div key={template.id} className="search-templates__card">
            <div className="search-templates__card-header">
              <h4 className="search-templates__card-title">
                {template.name}
              </h4>
              <span className="search-templates__card-category">
                {template.category}
              </span>
            </div>

            <p className="search-templates__card-description">
              {template.description}
            </p>

            <div className="search-templates__card-details">
              <div className="search-templates__card-filters">
                <div className="search-templates__filter-item">
                  <strong>Search:</strong> {template.filters.searchTerm}
                </div>
                <div className="search-templates__filter-item">
                  <strong>Types:</strong> {template.filters.documentTypes.join(', ')}
                </div>
                <div className="search-templates__filter-item">
                  <strong>Keywords:</strong> {template.filters.keywords.slice(0, 3).join(', ')}
                  {template.filters.keywords.length > 3 && '...'}
                </div>
                {template.filters.dateFrom && (
                  <div className="search-templates__filter-item">
                    <strong>From:</strong> {template.filters.dateFrom.getFullYear()}
                  </div>
                )}
              </div>

              <div className="search-templates__card-tags">
                {template.tags.map(tag => (
                  <span key={tag} className="search-templates__tag">
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            <div className="search-templates__card-actions">
              <button
                onClick={() => handleTemplateSelect(template)}
                className="search-templates__apply-btn"
              >
                Apply Template
              </button>
            </div>
          </div>
        ))}
      </div>

      {filteredTemplates.length === 0 && (
        <div className="search-templates__empty">
          <h4>No templates found</h4>
          <p>Try adjusting your search criteria or category filter.</p>
        </div>
      )}

      <div className="search-templates__info">
        <h4>How to use templates:</h4>
        <ol>
          <li>Browse or search for a template that matches your research interest</li>
          <li>Click "Apply Template" to load the pre-configured filters</li>
          <li>Modify the filters as needed in the Basic or Advanced tabs</li>
          <li>Run your search to find relevant documents</li>
        </ol>
      </div>
    </div>
  );
};