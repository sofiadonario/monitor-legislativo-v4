/**
 * SavedSearches Component
 * Manage saved search patterns and history
 */
import React, { useState, useEffect } from 'react';
import { SearchFilters, SavedQuery } from '../../types';
import { savedQueriesService } from '../../services/savedQueriesService';

interface SavedSearchesProps {
  currentFilters: SearchFilters;
  onSavedSearchApply: (filters: SearchFilters) => void;
}

export const SavedSearches: React.FC<SavedSearchesProps> = ({
  currentFilters,
  onSavedSearchApply
}) => {
  const [savedSearches, setSavedSearches] = useState<SavedQuery[]>([]);
  const [loading, setLoading] = useState(true);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveDialogData, setSaveDialogData] = useState({
    name: '',
    description: '',
    isPublic: false,
    tags: [] as string[]
  });
  const [tagInput, setTagInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState<'name' | 'created' | 'used'>('created');

  useEffect(() => {
    loadSavedSearches();
  }, []);

  const loadSavedSearches = async () => {
    try {
      setLoading(true);
      const searches = savedQueriesService.getAllQueries();
      setSavedSearches(searches);
    } catch (error) {
      console.error('Failed to load saved searches:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveCurrentSearch = async () => {
    if (!saveDialogData.name.trim()) return;

    try {
      savedQueriesService.saveQuery(
        saveDialogData.name,
        currentFilters,
        {
          description: saveDialogData.description,
          isPublic: saveDialogData.isPublic,
          tags: saveDialogData.tags
        }
      );
      await loadSavedSearches();
      setShowSaveDialog(false);
      setSaveDialogData({
        name: '',
        description: '',
        isPublic: false,
        tags: []
      });
    } catch (error) {
      console.error('Failed to save search:', error);
    }
  };

  const handleDeleteSearch = async (id: string) => {
    if (!confirm('Are you sure you want to delete this saved search?')) return;

    try {
      await savedQueriesService.deleteQuery(id);
      setSavedSearches(prev => prev.filter(search => search.id !== id));
    } catch (error) {
      console.error('Failed to delete search:', error);
    }
  };

  const handleApplySearch = async (savedSearch: SavedQuery) => {
    try {
      // Update usage count
      savedQueriesService.updateQuery(savedSearch.id, {
        ...savedSearch,
        timesUsed: savedSearch.timesUsed + 1
      });
      onSavedSearchApply(savedSearch.filters);
      
      // Refresh the list to show updated usage count
      await loadSavedSearches();
    } catch (error) {
      console.error('Failed to apply search:', error);
      // Still apply the search even if usage tracking fails
      onSavedSearchApply(savedSearch.filters);
    }
  };

  const handleAddTag = () => {
    const tag = tagInput.trim();
    if (tag && !saveDialogData.tags.includes(tag)) {
      setSaveDialogData(prev => ({
        ...prev,
        tags: [...prev.tags, tag]
      }));
      setTagInput('');
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    setSaveDialogData(prev => ({
      ...prev,
      tags: prev.tags.filter(tag => tag !== tagToRemove)
    }));
  };

  const hasCurrentFilters = () => {
    return currentFilters.searchTerm.trim() || 
           currentFilters.documentTypes.length > 0 ||
           currentFilters.states.length > 0 ||
           currentFilters.municipalities.length > 0 ||
           currentFilters.chambers.length > 0 ||
           currentFilters.keywords.length > 0 ||
           currentFilters.dateFrom ||
           currentFilters.dateTo;
  };

  const filteredAndSortedSearches = savedSearches
    .filter(search => {
      if (!searchQuery) return true;
      const query = searchQuery.toLowerCase();
      return search.name.toLowerCase().includes(query) ||
             search.description?.toLowerCase().includes(query) ||
             search.tags.some(tag => tag.toLowerCase().includes(query));
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'name':
          return a.name.localeCompare(b.name);
        case 'used':
          return b.timesUsed - a.timesUsed;
        case 'created':
        default:
          return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
      }
    });

  if (loading) {
    return (
      <div className="saved-searches__loading">
        <p>Loading saved searches...</p>
      </div>
    );
  }

  return (
    <div className="saved-searches">
      <div className="saved-searches__header">
        <h3>Saved Searches</h3>
        <p>Manage your saved search patterns and history</p>
      </div>

      <div className="saved-searches__controls">
        <div className="saved-searches__left-controls">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search saved queries..."
            className="saved-searches__search-input"
          />
          
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'name' | 'created' | 'used')}
            className="saved-searches__sort-select"
          >
            <option value="created">Sort by Date</option>
            <option value="name">Sort by Name</option>
            <option value="used">Sort by Usage</option>
          </select>
        </div>

        <div className="saved-searches__right-controls">
          {hasCurrentFilters() && (
            <button
              onClick={() => setShowSaveDialog(true)}
              className="saved-searches__save-btn"
            >
              Save Current Search
            </button>
          )}
        </div>
      </div>

      <div className="saved-searches__list">
        {filteredAndSortedSearches.map(savedSearch => (
          <div key={savedSearch.id} className="saved-searches__item">
            <div className="saved-searches__item-header">
              <h4 className="saved-searches__item-name">
                {savedSearch.name}
                {savedSearch.isPublic && (
                  <span className="saved-searches__public-badge">Public</span>
                )}
              </h4>
              <div className="saved-searches__item-meta">
                <span className="saved-searches__item-date">
                  {new Date(savedSearch.createdAt).toLocaleDateString()}
                </span>
                <span className="saved-searches__item-usage">
                  Used {savedSearch.timesUsed} times
                </span>
              </div>
            </div>

            {savedSearch.description && (
              <p className="saved-searches__item-description">
                {savedSearch.description}
              </p>
            )}

            <div className="saved-searches__item-filters">
              {savedSearch.filters.searchTerm && (
                <span className="saved-searches__filter-item">
                  Term: "{savedSearch.filters.searchTerm}"
                </span>
              )}
              {savedSearch.filters.documentTypes.length > 0 && (
                <span className="saved-searches__filter-item">
                  Types: {savedSearch.filters.documentTypes.join(', ')}
                </span>
              )}
              {savedSearch.filters.states.length > 0 && (
                <span className="saved-searches__filter-item">
                  States: {savedSearch.filters.states.join(', ')}
                </span>
              )}
              {savedSearch.filters.keywords.length > 0 && (
                <span className="saved-searches__filter-item">
                  Keywords: {savedSearch.filters.keywords.slice(0, 3).join(', ')}
                  {savedSearch.filters.keywords.length > 3 && '...'}
                </span>
              )}
            </div>

            {savedSearch.tags.length > 0 && (
              <div className="saved-searches__item-tags">
                {savedSearch.tags.map(tag => (
                  <span key={tag} className="saved-searches__tag">
                    {tag}
                  </span>
                ))}
              </div>
            )}

            <div className="saved-searches__item-actions">
              <button
                onClick={() => handleApplySearch(savedSearch)}
                className="saved-searches__apply-btn"
              >
                Apply Search
              </button>
              <button
                onClick={() => handleDeleteSearch(savedSearch.id)}
                className="saved-searches__delete-btn"
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>

      {filteredAndSortedSearches.length === 0 && (
        <div className="saved-searches__empty">
          <h4>No saved searches found</h4>
          {searchQuery ? (
            <p>Try adjusting your search criteria.</p>
          ) : (
            <p>Save your current search to access it later.</p>
          )}
        </div>
      )}

      {/* Save Dialog */}
      {showSaveDialog && (
        <div className="saved-searches__dialog-overlay">
          <div className="saved-searches__dialog">
            <div className="saved-searches__dialog-header">
              <h3>Save Current Search</h3>
              <button
                onClick={() => setShowSaveDialog(false)}
                className="saved-searches__dialog-close"
              >
                ×
              </button>
            </div>

            <div className="saved-searches__dialog-content">
              <div className="saved-searches__dialog-field">
                <label htmlFor="save-name">Name *</label>
                <input
                  id="save-name"
                  type="text"
                  value={saveDialogData.name}
                  onChange={(e) => setSaveDialogData(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="Enter search name..."
                  className="saved-searches__dialog-input"
                />
              </div>

              <div className="saved-searches__dialog-field">
                <label htmlFor="save-description">Description</label>
                <textarea
                  id="save-description"
                  value={saveDialogData.description}
                  onChange={(e) => setSaveDialogData(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Optional description..."
                  className="saved-searches__dialog-textarea"
                  rows={3}
                />
              </div>

              <div className="saved-searches__dialog-field">
                <label>Tags</label>
                <div className="saved-searches__tag-input">
                  <input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleAddTag()}
                    placeholder="Add tags..."
                    className="saved-searches__dialog-input"
                  />
                  <button
                    onClick={handleAddTag}
                    className="saved-searches__add-tag-btn"
                  >
                    Add
                  </button>
                </div>
                {saveDialogData.tags.length > 0 && (
                  <div className="saved-searches__dialog-tags">
                    {saveDialogData.tags.map(tag => (
                      <span key={tag} className="saved-searches__tag">
                        {tag}
                        <button
                          onClick={() => handleRemoveTag(tag)}
                          className="saved-searches__tag-remove"
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="saved-searches__dialog-field">
                <label className="saved-searches__checkbox">
                  <input
                    type="checkbox"
                    checked={saveDialogData.isPublic}
                    onChange={(e) => setSaveDialogData(prev => ({ ...prev, isPublic: e.target.checked }))}
                  />
                  Make this search public (visible to other users)
                </label>
              </div>
            </div>

            <div className="saved-searches__dialog-actions">
              <button
                onClick={() => setShowSaveDialog(false)}
                className="saved-searches__dialog-cancel"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveCurrentSearch}
                disabled={!saveDialogData.name.trim()}
                className="saved-searches__dialog-save"
              >
                Save Search
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};