import React, { useState, useEffect } from 'react';
import { SavedQuery, SearchFilters } from '../types';
import { savedQueriesService } from '../services/savedQueriesService';
import '../styles/components/SavedQueriesPanel.css';

interface SavedQueriesPanelProps {
  isOpen: boolean;
  onClose: () => void;
  onLoadQuery: (filters: SearchFilters) => void;
  currentFilters: SearchFilters;
}

interface SaveQueryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (name: string, description: string, isPublic: boolean, tags: string[]) => void;
  filters: SearchFilters;
}

const SaveQueryModal: React.FC<SaveQueryModalProps> = ({ isOpen, onClose, onSave, filters }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [isPublic, setIsPublic] = useState(false);
  const [tagsInput, setTagsInput] = useState('');
  const [error, setError] = useState('');

  const handleSave = () => {
    if (!name.trim()) {
      setError('Nome é obrigatório');
      return;
    }

    const tags = tagsInput.split(',').map(tag => tag.trim()).filter(tag => tag.length > 0);
    onSave(name.trim(), description.trim(), isPublic, tags);
    setName('');
    setDescription('');
    setIsPublic(false);
    setTagsInput('');
    setError('');
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <h3>Salvar Consulta</h3>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>
        
        <div className="modal-body">
          {error && <div className="error-message">{error}</div>}
          
          <div className="form-group">
            <label htmlFor="query-name">Nome da Consulta *</label>
            <input
              id="query-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Ex: Documentos sobre transporte público"
              maxLength={100}
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="query-description">Descrição</label>
            <textarea
              id="query-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Descrição opcional da consulta"
              rows={3}
              maxLength={500}
            />
          </div>
          
          <div className="form-group">
            <label htmlFor="query-tags">Tags (separadas por vírgula)</label>
            <input
              id="query-tags"
              type="text"
              value={tagsInput}
              onChange={(e) => setTagsInput(e.target.value)}
              placeholder="Ex: transporte, infraestrutura, mobilidade"
            />
          </div>
          
          <div className="form-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={isPublic}
                onChange={(e) => setIsPublic(e.target.checked)}
              />
              Tornar consulta pública
            </label>
          </div>
          
          <div className="query-preview">
            <h4>Preview da Consulta:</h4>
            <div className="preview-content">
              {filters.searchTerm && <span className="preview-tag">Busca: "{filters.searchTerm}"</span>}
              {filters.documentTypes.length > 0 && (
                <span className="preview-tag">Tipos: {filters.documentTypes.join(', ')}</span>
              )}
              {filters.states.length > 0 && (
                <span className="preview-tag">Estados: {filters.states.join(', ')}</span>
              )}
              {filters.keywords.length > 0 && (
                <span className="preview-tag">Palavras-chave: {filters.keywords.join(', ')}</span>
              )}
              {filters.dateFrom && (
                <span className="preview-tag">De: {filters.dateFrom.toLocaleDateString()}</span>
              )}
              {filters.dateTo && (
                <span className="preview-tag">Até: {filters.dateTo.toLocaleDateString()}</span>
              )}
            </div>
          </div>
        </div>
        
        <div className="modal-footer">
          <button className="btn-secondary" onClick={onClose}>Cancelar</button>
          <button className="btn-primary" onClick={handleSave}>Salvar Consulta</button>
        </div>
      </div>
    </div>
  );
};

export const SavedQueriesPanel: React.FC<SavedQueriesPanelProps> = ({
  isOpen,
  onClose,
  onLoadQuery,
  currentFilters
}) => {
  const [queries, setQueries] = useState<SavedQuery[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTag, setSelectedTag] = useState<string>('');
  const [showSaveModal, setShowSaveModal] = useState(false);
  const [activeTab, setActiveTab] = useState<'all' | 'recent' | 'popular' | 'public'>('all');
  const [sortBy, setSortBy] = useState<'name' | 'date' | 'usage'>('date');

  useEffect(() => {
    loadQueries();
  }, []);

  const loadQueries = () => {
    setQueries(savedQueriesService.getAllQueries());
  };

  const filteredQueries = React.useMemo(() => {
    let filtered = queries;

    // Filter by tab
    switch (activeTab) {
      case 'recent':
        filtered = savedQueriesService.getRecentQueries();
        break;
      case 'popular':
        filtered = savedQueriesService.getPopularQueries();
        break;
      case 'public':
        filtered = savedQueriesService.getPublicQueries();
        break;
      default:
        filtered = queries;
    }

    // Filter by search term
    if (searchTerm) {
      filtered = savedQueriesService.searchQueries(searchTerm);
    }

    // Filter by tag
    if (selectedTag) {
      filtered = filtered.filter(q => q.tags.includes(selectedTag));
    }

    // Sort
    switch (sortBy) {
      case 'name':
        filtered.sort((a, b) => a.name.localeCompare(b.name));
        break;
      case 'usage':
        filtered.sort((a, b) => b.timesUsed - a.timesUsed);
        break;
      case 'date':
      default:
        filtered.sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
    }

    return filtered;
  }, [queries, searchTerm, selectedTag, activeTab, sortBy]);

  const handleSaveQuery = (name: string, description: string, isPublic: boolean, tags: string[]) => {
    try {
      savedQueriesService.saveQuery(name, currentFilters, {
        description,
        isPublic,
        tags
      });
      loadQueries();
      setShowSaveModal(false);
    } catch (error) {
      console.error('Error saving query:', error);
    }
  };

  const handleLoadQuery = (query: SavedQuery) => {
    savedQueriesService.useQuery(query.id);
    onLoadQuery(query.filters);
    loadQueries(); // Refresh to update usage count
  };

  const handleDeleteQuery = (id: string) => {
    if (confirm('Tem certeza que deseja excluir esta consulta?')) {
      savedQueriesService.deleteQuery(id);
      loadQueries();
    }
  };

  const handleDuplicateQuery = (query: SavedQuery) => {
    const newName = `${query.name} (cópia)`;
    savedQueriesService.duplicateQuery(query.id, newName);
    loadQueries();
  };

  const formatFilters = (filters: SearchFilters): string => {
    const parts: string[] = [];
    
    if (filters.searchTerm) parts.push(`"${filters.searchTerm}"`);
    if (filters.documentTypes.length > 0) parts.push(`Tipos: ${filters.documentTypes.length}`);
    if (filters.states.length > 0) parts.push(`Estados: ${filters.states.length}`);
    if (filters.keywords.length > 0) parts.push(`Tags: ${filters.keywords.length}`);
    
    return parts.join(' • ');
  };

  const allTags = savedQueriesService.getAllTags();
  const stats = savedQueriesService.getStats();

  if (!isOpen) return null;

  return (
    <>
      <div className="saved-queries-overlay" onClick={onClose}>
        <div className="saved-queries-panel" onClick={(e) => e.stopPropagation()}>
          <div className="panel-header">
            <h2>Consultas Salvas</h2>
            <div className="header-actions">
              <button 
                className="btn-primary btn-small"
                onClick={() => setShowSaveModal(true)}
                disabled={!currentFilters.searchTerm && currentFilters.documentTypes.length === 0}
              >
                💾 Salvar Atual
              </button>
              <button className="panel-close" onClick={onClose}>×</button>
            </div>
          </div>

          <div className="panel-content">
            {/* Stats */}
            <div className="stats-bar">
              <span>{stats.total} consultas</span>
              <span>•</span>
              <span>{stats.totalUsage} usos</span>
              {stats.mostUsed && (
                <>
                  <span>•</span>
                  <span>Mais usada: "{stats.mostUsed.name}" ({stats.mostUsed.timesUsed}x)</span>
                </>
              )}
            </div>

            {/* Search and Filters */}
            <div className="search-controls">
              <input
                type="text"
                placeholder="Buscar consultas..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="search-input"
              />
              
              <select
                value={selectedTag}
                onChange={(e) => setSelectedTag(e.target.value)}
                className="tag-filter"
              >
                <option value="">Todas as tags</option>
                {allTags.map(tag => (
                  <option key={tag} value={tag}>{tag}</option>
                ))}
              </select>
              
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="sort-select"
              >
                <option value="date">Por data</option>
                <option value="name">Por nome</option>
                <option value="usage">Por uso</option>
              </select>
            </div>

            {/* Tabs */}
            <div className="tabs">
              <button
                className={`tab ${activeTab === 'all' ? 'active' : ''}`}
                onClick={() => setActiveTab('all')}
              >
                Todas ({stats.total})
              </button>
              <button
                className={`tab ${activeTab === 'recent' ? 'active' : ''}`}
                onClick={() => setActiveTab('recent')}
              >
                Recentes
              </button>
              <button
                className={`tab ${activeTab === 'popular' ? 'active' : ''}`}
                onClick={() => setActiveTab('popular')}
              >
                Populares
              </button>
              <button
                className={`tab ${activeTab === 'public' ? 'active' : ''}`}
                onClick={() => setActiveTab('public')}
              >
                Públicas ({stats.public})
              </button>
            </div>

            {/* Queries List */}
            <div className="queries-list">
              {filteredQueries.length === 0 ? (
                <div className="empty-state">
                  <p>Nenhuma consulta encontrada.</p>
                  {activeTab === 'all' && !searchTerm && (
                    <button 
                      className="btn-primary"
                      onClick={() => setShowSaveModal(true)}
                      disabled={!currentFilters.searchTerm && currentFilters.documentTypes.length === 0}
                    >
                      Salvar primeira consulta
                    </button>
                  )}
                </div>
              ) : (
                filteredQueries.map(query => (
                  <div key={query.id} className="query-item">
                    <div className="query-main">
                      <div className="query-header">
                        <h4 className="query-name">{query.name}</h4>
                        <div className="query-meta">
                          {query.isPublic && <span className="public-badge">Público</span>}
                          <span className="usage-count">{query.timesUsed} usos</span>
                          <span className="query-date">
                            {new Date(query.updatedAt).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                      
                      {query.description && (
                        <p className="query-description">{query.description}</p>
                      )}
                      
                      <div className="query-filters">
                        {formatFilters(query.filters)}
                      </div>
                      
                      {query.tags.length > 0 && (
                        <div className="query-tags">
                          {query.tags.map(tag => (
                            <span key={tag} className="tag">{tag}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    
                    <div className="query-actions">
                      <button
                        className="btn-primary btn-small"
                        onClick={() => handleLoadQuery(query)}
                      >
                        Usar
                      </button>
                      <button
                        className="btn-secondary btn-small"
                        onClick={() => handleDuplicateQuery(query)}
                      >
                        Duplicar
                      </button>
                      <button
                        className="btn-danger btn-small"
                        onClick={() => handleDeleteQuery(query.id)}
                      >
                        Excluir
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      <SaveQueryModal
        isOpen={showSaveModal}
        onClose={() => setShowSaveModal(false)}
        onSave={handleSaveQuery}
        filters={currentFilters}
      />
    </>
  );
};