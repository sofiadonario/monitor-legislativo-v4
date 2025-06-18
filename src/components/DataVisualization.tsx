import React, { useMemo } from 'react';
import { LegislativeDocument, DocumentType } from '../types/types';
import '../styles/components/DataVisualization.css';

interface DataVisualizationProps {
  documents: LegislativeDocument[];
}

interface ChartData {
  label: string;
  value: number;
  percentage: number;
}

export const DataVisualization: React.FC<DataVisualizationProps> = ({ documents }) => {
  // Calculate statistics
  const stats = useMemo(() => {
    const now = new Date();
    const sixMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 6, 1);
    const oneYearAgo = new Date(now.getFullYear() - 1, now.getMonth(), 1);

    // Document type distribution
    const typeCount = new Map<DocumentType, number>();
    const stateCount = new Map<string, number>();
    const monthlyCount = new Map<string, number>();
    const keywordCount = new Map<string, number>();

    documents.forEach(doc => {
      // Count by type
      typeCount.set(doc.type, (typeCount.get(doc.type) || 0) + 1);
      
      // Count by state
      if (doc.state) {
        stateCount.set(doc.state, (stateCount.get(doc.state) || 0) + 1);
      }
      
      // Count by month
      const docDate = typeof doc.date === 'string' ? new Date(doc.date) : doc.date;
      const monthKey = `${docDate.getFullYear()}-${String(docDate.getMonth() + 1).padStart(2, '0')}`;
      monthlyCount.set(monthKey, (monthlyCount.get(monthKey) || 0) + 1);
      
      // Count keywords
      doc.keywords.forEach(keyword => {
        keywordCount.set(keyword, (keywordCount.get(keyword) || 0) + 1);
      });
    });

    // Convert to chart data
    const total = documents.length;
    
    const typeData: ChartData[] = Array.from(typeCount.entries())
      .map(([label, value]) => ({
        label,
        value,
        percentage: (value / total) * 100
      }))
      .sort((a, b) => b.value - a.value);

    const stateData: ChartData[] = Array.from(stateCount.entries())
      .map(([label, value]) => ({
        label,
        value,
        percentage: (value / total) * 100
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10); // Top 10 states

    const keywordData: ChartData[] = Array.from(keywordCount.entries())
      .map(([label, value]) => ({
        label,
        value,
        percentage: (value / total) * 100
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 15); // Top 15 keywords

    // Monthly trend data (last 12 months)
    const monthlyData: ChartData[] = [];
    for (let i = 11; i >= 0; i--) {
      const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
      const monthKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
      const count = monthlyCount.get(monthKey) || 0;
      monthlyData.push({
        label: date.toLocaleDateString('pt-BR', { month: 'short', year: '2-digit' }),
        value: count,
        percentage: 0
      });
    }

    // Recent activity
    const recentDocs = documents.filter(doc => {
      const docDate = typeof doc.date === 'string' ? new Date(doc.date) : doc.date;
      return docDate >= sixMonthsAgo;
    }).length;

    const yearlyDocs = documents.filter(doc => {
      const docDate = typeof doc.date === 'string' ? new Date(doc.date) : doc.date;
      return docDate >= oneYearAgo;
    }).length;

    return {
      total,
      recentDocs,
      yearlyDocs,
      typeData,
      stateData,
      keywordData,
      monthlyData,
      averagePerMonth: Math.round(yearlyDocs / 12)
    };
  }, [documents]);

  // Simple bar chart component
  const BarChart: React.FC<{ data: ChartData[]; maxValue?: number }> = ({ data, maxValue }) => {
    const max = maxValue || Math.max(...data.map(d => d.value));
    
    return (
      <div className="bar-chart">
        {data.map((item, index) => (
          <div key={index} className="bar-item">
            <div className="bar-label">{item.label}</div>
            <div className="bar-container">
              <div 
                className="bar-fill"
                style={{ width: `${(item.value / max) * 100}%` }}
              >
                <span className="bar-value">{item.value}</span>
              </div>
            </div>
            {item.percentage > 0 && (
              <div className="bar-percentage">{item.percentage.toFixed(1)}%</div>
            )}
          </div>
        ))}
      </div>
    );
  };

  // Line chart component for trends
  const LineChart: React.FC<{ data: ChartData[] }> = ({ data }) => {
    const maxValue = Math.max(...data.map(d => d.value));
    const height = 200;
    const width = 100;
    
    return (
      <div className="line-chart">
        <svg viewBox={`0 0 ${width * data.length} ${height + 40}`} preserveAspectRatio="none">
          {/* Grid lines */}
          {[0, 25, 50, 75, 100].map(percent => (
            <line
              key={percent}
              x1="0"
              y1={height - (height * percent / 100)}
              x2={width * data.length}
              y2={height - (height * percent / 100)}
              stroke="#e0e0e0"
              strokeWidth="1"
            />
          ))}
          
          {/* Line path */}
          <polyline
            points={data.map((item, index) => 
              `${index * width + width/2},${height - (item.value / maxValue) * height}`
            ).join(' ')}
            fill="none"
            stroke="#1976d2"
            strokeWidth="2"
          />
          
          {/* Data points */}
          {data.map((item, index) => (
            <g key={index}>
              <circle
                cx={index * width + width/2}
                cy={height - (item.value / maxValue) * height}
                r="4"
                fill="#1976d2"
              />
              <text
                x={index * width + width/2}
                y={height + 20}
                textAnchor="middle"
                fontSize="12"
                fill="#666"
              >
                {item.label}
              </text>
              <text
                x={index * width + width/2}
                y={height - (item.value / maxValue) * height - 10}
                textAnchor="middle"
                fontSize="11"
                fill="#333"
                fontWeight="bold"
              >
                {item.value}
              </text>
            </g>
          ))}
        </svg>
      </div>
    );
  };

  // Keyword cloud component
  const KeywordCloud: React.FC<{ data: ChartData[] }> = ({ data }) => {
    const maxCount = Math.max(...data.map(d => d.value));
    
    return (
      <div className="keyword-cloud">
        {data.map((item, index) => {
          const size = 0.8 + (item.value / maxCount) * 1.2;
          const opacity = 0.6 + (item.value / maxCount) * 0.4;
          
          return (
            <span
              key={index}
              className="keyword-tag"
              style={{
                fontSize: `${size}rem`,
                opacity,
                color: `hsl(${200 + index * 10}, 70%, 45%)`
              }}
              title={`${item.value} documents`}
            >
              {item.label}
            </span>
          );
        })}
      </div>
    );
  };

  return (
    <div className="data-visualization">
      <h2>Legislative Analytics Dashboard</h2>
      
      {/* Summary cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-content">
            <div className="stat-value">{stats.total}</div>
            <div className="stat-label">Total Documents</div>
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-icon">📅</div>
          <div className="stat-content">
            <div className="stat-value">{stats.recentDocs}</div>
            <div className="stat-label">Last 6 Months</div>
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-icon">📈</div>
          <div className="stat-content">
            <div className="stat-value">{stats.averagePerMonth}</div>
            <div className="stat-label">Avg. per Month</div>
          </div>
        </div>
        
        <div className="stat-card">
          <div className="stat-icon">🗓️</div>
          <div className="stat-content">
            <div className="stat-value">{stats.yearlyDocs}</div>
            <div className="stat-label">This Year</div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="charts-grid">
        <div className="chart-container">
          <h3>Document Types Distribution</h3>
          <BarChart data={stats.typeData} />
        </div>
        
        <div className="chart-container">
          <h3>Top States by Legislation</h3>
          <BarChart data={stats.stateData} />
        </div>
        
        <div className="chart-container full-width">
          <h3>Monthly Trend (Last 12 Months)</h3>
          <LineChart data={stats.monthlyData} />
        </div>
        
        <div className="chart-container full-width">
          <h3>Popular Keywords</h3>
          <KeywordCloud data={stats.keywordData} />
        </div>
      </div>

      {/* Export options */}
      <div className="visualization-actions">
        <button 
          className="export-chart-btn"
          onClick={() => {
            // Simple CSV export
            const csv = [
              ['Metric', 'Value'],
              ['Total Documents', stats.total],
              ['Recent Documents (6 months)', stats.recentDocs],
              ['Yearly Documents', stats.yearlyDocs],
              ['Average per Month', stats.averagePerMonth],
              '',
              ['Document Type', 'Count', 'Percentage'],
              ...stats.typeData.map(d => [d.label, d.value, d.percentage.toFixed(1) + '%']),
              '',
              ['State', 'Count', 'Percentage'],
              ...stats.stateData.map(d => [d.label, d.value, d.percentage.toFixed(1) + '%'])
            ].map(row => row.join(',')).join('\n');
            
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `legislative-analytics-${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            URL.revokeObjectURL(url);
          }}
        >
          📥 Export Analytics (CSV)
        </button>
      </div>
    </div>
  );
};