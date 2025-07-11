import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { 
  processedDataService, 
  ProcessedDataStats, 
  ProcessedDataCategories, 
  ProcessedDocument 
} from '../services/processedDataService';

// Interfaces imported from service

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];

export const ProcessedDataDashboard: React.FC = () => {
  const [stats, setStats] = useState<ProcessedDataStats | null>(null);
  const [categories, setCategories] = useState<ProcessedDataCategories | null>(null);
  const [recentDocuments, setRecentDocuments] = useState<ProcessedDocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'categories' | 'documents'>('overview');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Use the service methods instead of direct fetch
      const [statsData, categoriesData, documentsData] = await Promise.all([
        processedDataService.getStats(),
        processedDataService.getCategories(),
        processedDataService.getProcessedDocuments({ limit: 1000 })
      ]);

      console.log('ProcessedData API Response:', {
        statsData,
        categoriesData,
        documentsCount: documentsData.data.length,
        totalFromCategories: categoriesData.total_documents
      });
      
      setStats(statsData.stats);
      setCategories(categoriesData.categories);
      setRecentDocuments(documentsData.data);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const formatChartData = (data: Record<string, number>, limit: number = 10) => {
    return Object.entries(data)
      .slice(0, limit)
      .map(([name, value]) => ({ name, value }));
  };

  const formatPieData = (data: Record<string, number>, limit: number = 6) => {
    const entries = Object.entries(data).slice(0, limit);
    return entries.map(([name, value], index) => ({
      name: name.length > 20 ? name.substring(0, 20) + '...' : name,
      value,
      color: COLORS[index % COLORS.length]
    }));
  };

  if (loading) {
    return (
      <div className="processed-data-dashboard">
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading processed data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="processed-data-dashboard">
        <div className="error-state">
          <h3>Error Loading Data</h3>
          <p>{error}</p>
          <button onClick={fetchData} className="retry-btn">
            🔄 Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="processed-data-dashboard">
      <div className="dashboard-header">
        <h2>📊 Processed Legislative Data</h2>
        <p>Analytics from your parsed CSV data in Supabase</p>
        <button onClick={fetchData} className="refresh-btn">
          🔄 Refresh Data
        </button>
      </div>

      {/* Navigation Tabs */}
      <div className="dashboard-tabs">
        <button
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          📈 Overview
        </button>
        <button
          className={`tab ${activeTab === 'categories' ? 'active' : ''}`}
          onClick={() => setActiveTab('categories')}
        >
          🏷️ Categories
        </button>
        <button
          className={`tab ${activeTab === 'documents' ? 'active' : ''}`}
          onClick={() => setActiveTab('documents')}
        >
          📄 Documents
        </button>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && stats && (
        <div className="overview-content">
          {/* Summary Cards */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">{stats.total_documents.toLocaleString()}</div>
              <div className="stat-label">Total Documents</div>
              <div className="stat-source">📋 {stats.data_source}</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.recent_documents.toLocaleString()}</div>
              <div className="stat-label">Recent Documents</div>
              <div className="stat-source">📅 Last 30 Days</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{Object.keys(stats.documents_by_year).length}</div>
              <div className="stat-label">Years Covered</div>
              <div className="stat-source">🗓️ Time Range</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{categories ? Object.keys(categories.document_types).length : 0}</div>
              <div className="stat-label">Document Types</div>
              <div className="stat-source">🏷️ Categories</div>
            </div>
          </div>

          {/* Documents by Year Chart */}
          <div className="chart-section">
            <h3>Documents by Year</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={formatChartData(stats.documents_by_year, 15)}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#0088FE" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Categories Tab */}
      {activeTab === 'categories' && categories && (
        <div className="categories-content">
          {/* Document Types */}
          <div className="category-section">
            <h3>Document Types Distribution</h3>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height={400}>
                <PieChart>
                  <Pie
                    data={formatPieData(categories.document_types)}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={120}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {formatPieData(categories.document_types).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* States Distribution */}
          <div className="category-section">
            <h3>Top States by Document Count</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={formatChartData(categories.states, 10)}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#00C49F" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Search Terms */}
          <div className="category-section">
            <h3>Top Search Terms</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={formatChartData(categories.search_terms, 8)}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" angle={-45} textAnchor="end" height={100} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#FFBB28" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* URN Types */}
          <div className="category-section">
            <h3>URN Types</h3>
            <div className="urn-types-list">
              {Object.entries(categories.urn_types).map(([type, count]) => (
                <div key={type} className="urn-type-item">
                  <span className="urn-type">{type}</span>
                  <span className="urn-count">{count} documents</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Documents Tab */}
      {activeTab === 'documents' && (
        <div className="documents-content">
          <h3>Recent Documents</h3>
          <div className="documents-list">
            {recentDocuments.map((doc) => (
              <div key={doc.id} className="document-card">
                <div className="document-header">
                  <h4>{doc.title}</h4>
                  <span className="document-type">{doc.document_type_full}</span>
                </div>
                <div className="document-meta">
                  <span className="urn">📋 {doc.urn}</span>
                  <span className="state">🏛️ {doc.state || 'Federal'}</span>
                  <span className="date">📅 {doc.promulgation_date}</span>
                </div>
                <div className="document-description">
                  {doc.document_description}
                </div>
                <div className="search-term">
                  🔍 Found by: <em>{doc.search_term}</em>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}; 