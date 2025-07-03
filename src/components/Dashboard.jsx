import React, { useState, useEffect } from 'react';
import Header from './Header.jsx';
import DataSummary from './DataSummary.jsx';
import SkeletonLoader from './SkeletonLoader.jsx';
import DataMap from './DataMap.jsx';
import DocumentList from './DocumentList.jsx';
import { LegislativeDataService } from '../services/legislativeDataService';

const Dashboard = () => {
  const [documents, setDocuments] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [usingFallback, setUsingFallback] = useState(false);
  
  // CRITICAL FIX: Add a key to force re-render when data source changes.
  const [dataSourceKey, setDataSourceKey] = useState(Date.now());

  useEffect(() => {
    const dataService = LegislativeDataService.getInstance();
    
    const loadData = async () => {
      try {
        setIsLoading(true);
        const { documents: fetchedDocs, usingFallback: fallbackUsed } = await dataService.fetchDocuments();
        setDocuments(fetchedDocs);
        setUsingFallback(fallbackUsed);
        setError(null);
        setDataSourceKey(Date.now()); // Update key on new data
      } catch (err) {
        console.error("Dashboard data loading error:", err);
        setError('Failed to load legislative data. Please try again later.');
        setDocuments([]); // Clear documents on error
      } finally {
        setIsLoading(false);
      }
    };

    loadData();
  }, []);

  const handleSearch = async (filters) => {
    // This function can be built out later
    console.log("Search triggered with filters:", filters);
  };

  return (
    <div className="dashboard" key={dataSourceKey}>
      <Header onSearch={handleSearch} />
      <main className="dashboard-main">
        {error && <div className="error-message">{error}</div>}
        
        <DataSummary documents={documents} isLoading={isLoading} usingFallback={usingFallback} />
        
        {isLoading ? (
          <SkeletonLoader />
        ) : (
          <div className="dashboard-content">
            <DataMap documents={documents} />
            <DocumentList documents={documents} />
          </div>
        )}
      </main>
    </div>
  );
};

export default Dashboard; 