import React from 'react';

const SimpleDashboard: React.FC = () => {
  return (
    <div style={{ 
      padding: '2rem', 
      backgroundColor: '#f8f9fa', 
      borderRadius: '8px',
      margin: '1rem 0'
    }}>
      <h2>📊 Monitor Legislativo Dashboard</h2>
      <p>Brazilian Legislative Monitoring System - Simple Version</p>
      
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
        gap: '1rem',
        margin: '2rem 0'
      }}>
        <div style={{ 
          padding: '1rem', 
          backgroundColor: 'white', 
          borderRadius: '6px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3>📋 Proposições</h3>
          <p style={{ fontSize: '2rem', margin: '0.5rem 0', color: '#007bff' }}>1,234</p>
          <p style={{ color: '#6c757d', fontSize: '0.9rem' }}>Total de proposições</p>
        </div>
        
        <div style={{ 
          padding: '1rem', 
          backgroundColor: 'white', 
          borderRadius: '6px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3>🏛️ Órgãos</h3>
          <p style={{ fontSize: '2rem', margin: '0.5rem 0', color: '#28a745' }}>27</p>
          <p style={{ color: '#6c757d', fontSize: '0.9rem' }}>Estados monitorados</p>
        </div>
        
        <div style={{ 
          padding: '1rem', 
          backgroundColor: 'white', 
          borderRadius: '6px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h3>📈 Atualizações</h3>
          <p style={{ fontSize: '2rem', margin: '0.5rem 0', color: '#ffc107' }}>42</p>
          <p style={{ color: '#6c757d', fontSize: '0.9rem' }}>Hoje</p>
        </div>
      </div>
      
      <div style={{ 
        marginTop: '2rem',
        padding: '1rem',
        backgroundColor: '#e7f3ff',
        borderRadius: '6px',
        borderLeft: '4px solid #007bff'
      }}>
        <h4>🚀 Sistema Funcionando</h4>
        <ul style={{ margin: '0.5rem 0', paddingLeft: '1.5rem' }}>
          <li>✅ Dashboard carregado via Suspense</li>
          <li>✅ Componente isolado e seguro</li>
          <li>✅ Sem dependências complexas</li>
          <li>✅ Pronto para expansão gradual</li>
        </ul>
      </div>
      
      <p style={{ 
        marginTop: '1rem', 
        fontSize: '0.9rem', 
        color: '#6c757d',
        textAlign: 'center'
      }}>
        Este é um dashboard simplificado. A versão completa com mapa interativo 
        será adicionada gradualmente.
      </p>
    </div>
  );
};

export default SimpleDashboard;