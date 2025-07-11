/**
 * SearchHistory Component
 * Manage and display recent search history
 */
import React, { useState, useEffect } from 'react';

interface SearchHistoryProps {
  onHistorySelect: (term: string) => void;
  maxItems?: number;
}

interface HistoryItem {
  term: string;
  timestamp: number;
  count: number;
}

export const SearchHistory: React.FC<SearchHistoryProps> = ({
  onHistorySelect,
  maxItems = 20
}) => {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [showHistory, setShowHistory] = useState(false);

  useEffect(() => {
    loadSearchHistory();
  }, []);

  const loadSearchHistory = () => {
    try {
      const historyData = localStorage.getItem('detailed-search-history');
      if (historyData) {
        const parsed = JSON.parse(historyData);
        setHistory(parsed.slice(0, maxItems));
      }
    } catch (error) {
      console.error('Error loading search history:', error);
    }
  };

  const clearHistory = () => {
    if (confirm('Are you sure you want to clear your search history?')) {
      localStorage.removeItem('detailed-search-history');
      localStorage.removeItem('search-history');
      setHistory([]);
    }
  };

  const removeHistoryItem = (termToRemove: string) => {
    try {
      const updatedHistory = history.filter(item => item.term !== termToRemove);
      setHistory(updatedHistory);
      localStorage.setItem('detailed-search-history', JSON.stringify(updatedHistory));
      
      // Also update simple history
      const simpleHistory = updatedHistory.map(item => item.term);
      localStorage.setItem('search-history', JSON.stringify(simpleHistory));
    } catch (error) {
      console.error('Error removing history item:', error);
    }
  };

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString();
  };

  if (history.length === 0) return null;

  return (
    <div className="search-history">
      <div className="search-history__toggle">
        <button
          onClick={() => setShowHistory(!showHistory)}
          className="search-history__toggle-btn"
        >
          Recent Searches ({history.length})
          <span className={`search-history__arrow ${showHistory ? 'expanded' : ''}`}>
            ▼
          </span>
        </button>
      </div>

      {showHistory && (
        <div className="search-history__panel">
          <div className="search-history__header">
            <h4>Recent Searches</h4>
            <button
              onClick={clearHistory}
              className="search-history__clear-btn"
            >
              Clear All
            </button>
          </div>

          <div className="search-history__list">
            {history.map((item, index) => (
              <div key={index} className="search-history__item">
                <button
                  onClick={() => onHistorySelect(item.term)}
                  className="search-history__item-btn"
                >
                  <div className="search-history__item-content">
                    <span className="search-history__term">{item.term}</span>
                    <div className="search-history__meta">
                      <span className="search-history__time">
                        {formatTimestamp(item.timestamp)}
                      </span>
                      {item.count > 1 && (
                        <span className="search-history__count">
                          {item.count}x
                        </span>
                      )}
                    </div>
                  </div>
                </button>
                <button
                  onClick={() => removeHistoryItem(item.term)}
                  className="search-history__remove-btn"
                  title="Remove from history"
                >
                  ×
                </button>
              </div>
            ))}
          </div>

          {history.length >= maxItems && (
            <div className="search-history__footer">
              <p>Showing last {maxItems} searches</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};