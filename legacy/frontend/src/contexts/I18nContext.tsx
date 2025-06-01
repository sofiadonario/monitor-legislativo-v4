import React, { createContext, useContext, useState, useEffect } from 'react';

export type Language = 'en' | 'pt';

interface I18nContextType {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string) => string;
}

const I18nContext = createContext<I18nContextType | undefined>(undefined);

const translations = {
  en: {
    // Navigation
    'nav.dashboard': 'Dashboard',
    'nav.lexmlSearch': 'LexML Search',
    'nav.advancedSearch': 'Advanced Search',
    'nav.analytics': 'Analytics',
    
    // Dashboard
    'dashboard.title': 'Monitor Legislativo v4',
    'dashboard.subtitle': 'Brazilian Legislative Monitoring Platform',
    'dashboard.searchPlaceholder': 'Search legislation...',
    'dashboard.searchButton': 'Search',
    
    // Analytics
    'analytics.title': 'Analytics Dashboard',
    'analytics.localAnalytics': 'Local Analytics',
    'analytics.documents': 'Documents',
    'analytics.states': 'States',
    'analytics.documentTypes': 'Document Types',
    'analytics.dateRange': 'Date Range',
    'analytics.overview': 'Overview',
    'analytics.distributions': 'Statistical Distributions',
    'analytics.geographic': 'Geographic Analysis',
    'analytics.timeseries': 'Time Series',
    'analytics.network': 'Network Analysis',
    'analytics.reports': 'Custom Reports',
    'analytics.dataSource': 'Data Source Information',
    'analytics.basedOn': 'Analytics based on {count} legislative documents from the Brazilian transport legislation database.',
    'analytics.coverage': 'Coverage period: {start} - {end}',
    
    // Analytics Tabs
    'analytics.statisticalDistributions': 'Statistical Distributions Analysis',
    'analytics.statisticalDesc': 'Statistical analysis of document distributions across various dimensions',
    'analytics.interactiveGeo': 'Interactive Geographic Analysis',
    'analytics.geoDesc': 'Spatial distribution and geographic patterns of legislative documents',
    'analytics.timeSeriesAnalysis': 'Time Series Analysis',
    'analytics.timeDesc': 'Temporal patterns and trends in legislative document creation',
    'analytics.networkAnalysis': 'Network Analysis',
    'analytics.networkDesc': 'Relationships and connections between documents, keywords, and jurisdictions',
    'analytics.customReports': 'Custom Report Generation',
    'analytics.reportsDesc': 'Generate comprehensive analytical reports based on current data',
    
    // Common
    'common.loading': 'Loading...',
    'common.error': 'Error',
    'common.retry': 'Retry',
    'common.close': 'Close',
    'common.save': 'Save',
    'common.cancel': 'Cancel',
    'common.total': 'Total',
    'common.date': 'Date',
    'common.type': 'Type',
    'common.status': 'Status',
    'common.state': 'State',
    'common.municipality': 'Municipality',
    
    // Language
    'language.switch': 'Switch Language',
    'language.english': 'English',
    'language.portuguese': 'Português'
  },
  pt: {
    // Navigation
    'nav.dashboard': 'Painel',
    'nav.lexmlSearch': 'Busca LexML',
    'nav.advancedSearch': 'Busca Avançada',
    'nav.analytics': 'Analytics',
    
    // Dashboard
    'dashboard.title': 'Monitor Legislativo v4',
    'dashboard.subtitle': 'Plataforma de Monitoramento Legislativo Brasileiro',
    'dashboard.searchPlaceholder': 'Buscar legislação...',
    'dashboard.searchButton': 'Buscar',
    
    // Analytics
    'analytics.title': 'Painel de Analytics',
    'analytics.localAnalytics': 'Analytics Local',
    'analytics.documents': 'Documentos',
    'analytics.states': 'Estados',
    'analytics.documentTypes': 'Tipos de Documento',
    'analytics.dateRange': 'Período',
    'analytics.overview': 'Visão Geral',
    'analytics.distributions': 'Distribuições Estatísticas',
    'analytics.geographic': 'Análise Geográfica',
    'analytics.timeseries': 'Séries Temporais',
    'analytics.network': 'Análise de Rede',
    'analytics.reports': 'Relatórios Personalizados',
    'analytics.dataSource': 'Informações da Fonte de Dados',
    'analytics.basedOn': 'Analytics baseado em {count} documentos legislativos da base de dados de legislação de transporte brasileira.',
    'analytics.coverage': 'Período de cobertura: {start} - {end}',
    
    // Analytics Tabs
    'analytics.statisticalDistributions': 'Análise de Distribuições Estatísticas',
    'analytics.statisticalDesc': 'Análise estatística das distribuições de documentos em várias dimensões',
    'analytics.interactiveGeo': 'Análise Geográfica Interativa',
    'analytics.geoDesc': 'Distribuição espacial e padrões geográficos dos documentos legislativos',
    'analytics.timeSeriesAnalysis': 'Análise de Séries Temporais',
    'analytics.timeDesc': 'Padrões temporais e tendências na criação de documentos legislativos',
    'analytics.networkAnalysis': 'Análise de Rede',
    'analytics.networkDesc': 'Relacionamentos e conexões entre documentos, palavras-chave e jurisdições',
    'analytics.customReports': 'Geração de Relatórios Personalizados',
    'analytics.reportsDesc': 'Gere relatórios analíticos abrangentes baseados nos dados atuais',
    
    // Common
    'common.loading': 'Carregando...',
    'common.error': 'Erro',
    'common.retry': 'Tentar Novamente',
    'common.close': 'Fechar',
    'common.save': 'Salvar',
    'common.cancel': 'Cancelar',
    'common.total': 'Total',
    'common.date': 'Data',
    'common.type': 'Tipo',
    'common.status': 'Status',
    'common.state': 'Estado',
    'common.municipality': 'Município',
    
    // Language
    'language.switch': 'Mudar Idioma',
    'language.english': 'English',
    'language.portuguese': 'Português'
  }
};

export const I18nProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [language, setLanguage] = useState<Language>(() => {
    const stored = localStorage.getItem('monitor-legislativo-language');
    if (stored === 'en' || stored === 'pt') return stored;
    
    // Auto-detect browser language
    const browserLang = navigator.language.toLowerCase();
    if (browserLang.startsWith('pt')) return 'pt';
    return 'en';
  });

  useEffect(() => {
    localStorage.setItem('monitor-legislativo-language', language);
    document.documentElement.lang = language;
  }, [language]);

  const t = (key: string): string => {
    const value = translations[language][key as keyof typeof translations[typeof language]];
    if (value) return value;
    
    // Fallback to English if key not found in current language
    const fallback = translations.en[key as keyof typeof translations.en];
    if (fallback) return fallback;
    
    // Return key if no translation found
    console.warn(`Translation missing for key: ${key}`);
    return key;
  };

  return (
    <I18nContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </I18nContext.Provider>
  );
};

export const useI18n = (): I18nContextType => {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error('useI18n must be used within an I18nProvider');
  }
  return context;
};