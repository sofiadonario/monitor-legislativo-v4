/**
 * Advanced Analytics Dashboard
 * Interactive data visualization and reporting
 */

import React, { useState, useMemo, useCallback } from 'react';
import { useQuery } from 'react-query';
import {
  LineChart,
  BarChart,
  PieChart,
  AreaChart,
  Line,
  Bar,
  Pie,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
  Treemap,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
} from 'recharts';
import { motion } from 'framer-motion';
import { format, subDays, startOfMonth, endOfMonth } from 'date-fns';
import { ptBR } from 'date-fns/locale';

import { useResponsive } from '../hooks/useResponsive';
import { PerformanceProfiler } from '../utils/performance';
import { getAnalytics } from '../services/api';
import DateRangePicker from '../components/common/DateRangePicker';
import MetricCard from '../components/analytics/MetricCard';
import ExportButton from '../components/common/ExportButton';
import LoadingSpinner from '../components/common/LoadingSpinner';

// Chart color palette
const COLORS = {
  primary: '#3B82F6',
  secondary: '#10B981',
  tertiary: '#F59E0B',
  quaternary: '#EF4444',
  quinary: '#8B5CF6',
  senary: '#EC4899',
};

const CHART_COLORS = Object.values(COLORS);

interface AnalyticsData {
  overview: {
    totalPropositions: number;
    activePropositions: number;
    approvedPropositions: number;
    rejectedPropositions: number;
    averageProcessingDays: number;
    trendingTopics: string[];
  };
  timeSeries: {
    date: string;
    newPropositions: number;
    statusChanges: number;
    searches: number;
  }[];
  propositionsByType: {
    type: string;
    count: number;
    percentage: number;
  }[];
  propositionsByStatus: {
    status: string;
    count: number;
  }[];
  authorActivity: {
    author: string;
    propositions: number;
    approved: number;
    pending: number;
    party: string;
  }[];
  topicAnalysis: {
    topic: string;
    count: number;
    sentiment: number;
    growth: number;
  }[];
  searchTrends: {
    term: string;
    searches: number;
    growth: number;
  }[];
  performanceMetrics: {
    metric: string;
    value: number;
    target: number;
  }[];
}

const Analytics: React.FC = () => {
  const { isMobile, isTablet } = useResponsive();
  const [dateRange, setDateRange] = useState({
    start: subDays(new Date(), 30),
    end: new Date(),
  });
  const [selectedMetric, setSelectedMetric] = useState<'propositions' | 'activity' | 'performance'>('propositions');

  // Fetch analytics data
  const { data, isLoading, error } = useQuery<AnalyticsData>(
    ['analytics', dateRange],
    () => getAnalytics(dateRange),
    {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
    }
  );

  // Memoized calculations
  const growthRate = useMemo(() => {
    if (!data?.timeSeries || data.timeSeries.length < 2) return 0;
    
    const recent = data.timeSeries.slice(-7).reduce((sum, d) => sum + d.newPropositions, 0);
    const previous = data.timeSeries.slice(-14, -7).reduce((sum, d) => sum + d.newPropositions, 0);
    
    return previous > 0 ? ((recent - previous) / previous) * 100 : 0;
  }, [data]);

  const approvalRate = useMemo(() => {
    if (!data?.overview) return 0;
    
    const total = data.overview.approvedPropositions + data.overview.rejectedPropositions;
    return total > 0 ? (data.overview.approvedPropositions / total) * 100 : 0;
  }, [data]);

  // Export functionality
  const handleExport = useCallback((format: 'csv' | 'pdf' | 'json') => {
    // Implementation for exporting analytics data
    console.log(`Exporting analytics in ${format} format`);
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <LoadingSpinner size="large" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
            Erro ao carregar análises
          </h2>
          <p className="text-gray-600 dark:text-gray-400">
            Tente novamente mais tarde
          </p>
        </div>
      </div>
    );
  }

  return (
    <PerformanceProfiler id="AnalyticsDashboard">
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <div className="container mx-auto px-4 py-8">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
              Análises e Relatórios
            </h1>
            
            <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
              <DateRangePicker
                startDate={dateRange.start}
                endDate={dateRange.end}
                onChange={setDateRange}
              />
              
              <ExportButton onExport={handleExport} />
            </div>
          </div>

          {/* Overview Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <MetricCard
              title="Total de Proposições"
              value={data.overview.totalPropositions}
              change={growthRate}
              icon="document"
              color="primary"
            />
            
            <MetricCard
              title="Em Tramitação"
              value={data.overview.activePropositions}
              subtitle={`${((data.overview.activePropositions / data.overview.totalPropositions) * 100).toFixed(1)}% do total`}
              icon="clock"
              color="secondary"
            />
            
            <MetricCard
              title="Taxa de Aprovação"
              value={`${approvalRate.toFixed(1)}%`}
              subtitle={`${data.overview.approvedPropositions} aprovadas`}
              icon="check"
              color="tertiary"
            />
            
            <MetricCard
              title="Tempo Médio"
              value={`${data.overview.averageProcessingDays} dias`}
              subtitle="Processamento"
              icon="calendar"
              color="quaternary"
            />
          </div>

          {/* Tab Navigation */}
          <div className="flex gap-2 mb-6 overflow-x-auto">
            <button
              onClick={() => setSelectedMetric('propositions')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedMetric === 'propositions'
                  ? 'bg-blue-600 text-white'
                  : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300'
              }`}
            >
              Proposições
            </button>
            <button
              onClick={() => setSelectedMetric('activity')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedMetric === 'activity'
                  ? 'bg-blue-600 text-white'
                  : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300'
              }`}
            >
              Atividade
            </button>
            <button
              onClick={() => setSelectedMetric('performance')}
              className={`px-4 py-2 rounded-lg font-medium transition-colors ${
                selectedMetric === 'performance'
                  ? 'bg-blue-600 text-white'
                  : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300'
              }`}
            >
              Desempenho
            </button>
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Time Series Chart */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
            >
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                Evolução Temporal
              </h3>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={data.timeSeries}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis 
                    dataKey="date" 
                    tickFormatter={(date) => format(new Date(date), 'dd/MM', { locale: ptBR })}
                  />
                  <YAxis />
                  <Tooltip 
                    labelFormatter={(date) => format(new Date(date), 'dd/MM/yyyy', { locale: ptBR })}
                  />
                  <Legend />
                  <Area
                    type="monotone"
                    dataKey="newPropositions"
                    name="Novas Proposições"
                    stroke={COLORS.primary}
                    fill={COLORS.primary}
                    fillOpacity={0.6}
                  />
                  <Area
                    type="monotone"
                    dataKey="statusChanges"
                    name="Mudanças de Status"
                    stroke={COLORS.secondary}
                    fill={COLORS.secondary}
                    fillOpacity={0.6}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </motion.div>

            {/* Propositions by Type */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
            >
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                Proposições por Tipo
              </h3>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={data.propositionsByType}
                    dataKey="count"
                    nameKey="type"
                    cx="50%"
                    cy="50%"
                    outerRadius={100}
                    label={({ percentage }) => `${percentage.toFixed(0)}%`}
                  >
                    {data.propositionsByType.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </motion.div>

            {/* Author Activity */}
            {selectedMetric === 'activity' && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 lg:col-span-2"
              >
                <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                  Atividade por Autor
                </h3>
                <ResponsiveContainer width="100%" height={400}>
                  <BarChart data={data.authorActivity.slice(0, 10)}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis 
                      dataKey="author" 
                      angle={-45}
                      textAnchor="end"
                      height={100}
                    />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="propositions" name="Total" fill={COLORS.primary} />
                    <Bar dataKey="approved" name="Aprovadas" fill={COLORS.secondary} />
                    <Bar dataKey="pending" name="Pendentes" fill={COLORS.tertiary} />
                  </BarChart>
                </ResponsiveContainer>
              </motion.div>
            )}

            {/* Topic Analysis Treemap */}
            {selectedMetric === 'propositions' && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
              >
                <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                  Análise de Tópicos
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <Treemap
                    data={data.topicAnalysis}
                    dataKey="count"
                    aspectRatio={isMobile ? 1 : 4 / 3}
                    fill={COLORS.primary}
                  >
                    <Tooltip />
                  </Treemap>
                </ResponsiveContainer>
              </motion.div>
            )}

            {/* Performance Radar */}
            {selectedMetric === 'performance' && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
                className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
              >
                <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                  Métricas de Desempenho
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <RadarChart data={data.performanceMetrics}>
                    <PolarGrid />
                    <PolarAngleAxis dataKey="metric" />
                    <PolarRadiusAxis angle={90} domain={[0, 100]} />
                    <Radar
                      name="Atual"
                      dataKey="value"
                      stroke={COLORS.primary}
                      fill={COLORS.primary}
                      fillOpacity={0.6}
                    />
                    <Radar
                      name="Meta"
                      dataKey="target"
                      stroke={COLORS.secondary}
                      fill={COLORS.secondary}
                      fillOpacity={0.3}
                    />
                    <Legend />
                    <Tooltip />
                  </RadarChart>
                </ResponsiveContainer>
              </motion.div>
            )}

            {/* Search Trends */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="bg-white dark:bg-gray-800 rounded-lg shadow p-6"
            >
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                Tendências de Busca
              </h3>
              <div className="space-y-3">
                {data.searchTrends.slice(0, 10).map((trend, index) => (
                  <div key={trend.term} className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-medium text-gray-500 dark:text-gray-400 w-6">
                        {index + 1}
                      </span>
                      <span className="text-sm font-medium text-gray-900 dark:text-white">
                        {trend.term}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        {trend.searches} buscas
                      </span>
                      <span className={`text-sm font-medium ${
                        trend.growth > 0 ? 'text-green-600' : 'text-red-600'
                      }`}>
                        {trend.growth > 0 ? '+' : ''}{trend.growth.toFixed(1)}%
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          </div>

          {/* Trending Topics */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6 }}
            className="mt-6 bg-white dark:bg-gray-800 rounded-lg shadow p-6"
          >
            <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
              Tópicos em Alta
            </h3>
            <div className="flex flex-wrap gap-2">
              {data.overview.trendingTopics.map((topic) => (
                <span
                  key={topic}
                  className="px-3 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300 rounded-full text-sm font-medium"
                >
                  {topic}
                </span>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </PerformanceProfiler>
  );
};

export default Analytics;