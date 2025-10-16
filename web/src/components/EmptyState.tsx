/**
 * EmptyState Component
 * Displays helpful messages when no data is available
 */

import React from 'react';

export interface EmptyStateProps {
  title: string;
  description?: string;
  icon?: React.ReactNode;
  action?: React.ReactNode;
}

export function EmptyState({
  title,
  description,
  icon,
  action,
}: EmptyStateProps) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 24px',
        textAlign: 'center',
        color: '#6b7280',
      }}
    >
      {icon && (
        <div
          style={{
            fontSize: '48px',
            marginBottom: '16px',
            opacity: 0.5,
          }}
        >
          {icon}
        </div>
      )}

      <h3
        style={{
          fontSize: '18px',
          fontWeight: 600,
          color: '#374151',
          marginBottom: '8px',
        }}
      >
        {title}
      </h3>

      {description && (
        <p
          style={{
            fontSize: '14px',
            maxWidth: '400px',
            marginBottom: action ? '24px' : '0',
          }}
        >
          {description}
        </p>
      )}

      {action && <div>{action}</div>}
    </div>
  );
}

/**
 * Loading State Component
 */
export function LoadingState({ message = 'Carregando...' }: { message?: string }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 24px',
        textAlign: 'center',
      }}
    >
      <div
        style={{
          width: '40px',
          height: '40px',
          border: '4px solid #e5e7eb',
          borderTopColor: '#3b82f6',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite',
          marginBottom: '16px',
        }}
      />
      <p style={{ color: '#6b7280', fontSize: '14px' }}>{message}</p>

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

/**
 * Error State Component
 */
export interface ErrorStateProps {
  error: Error | { message: string };
  onRetry?: () => void;
}

export function ErrorState({ error, onRetry }: ErrorStateProps) {
  return (
    <EmptyState
      icon="⚠️"
      title="Erro ao carregar dados"
      description={error.message || 'Ocorreu um erro inesperado. Por favor, tente novamente.'}
      action={
        onRetry && (
          <button
            onClick={onRetry}
            style={{
              padding: '8px 16px',
              backgroundColor: '#3b82f6',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              fontSize: '14px',
              cursor: 'pointer',
              fontWeight: 500,
            }}
          >
            Tentar novamente
          </button>
        )
      }
    />
  );
}

/**
 * No Results State
 */
export function NoResultsState({ query }: { query?: string }) {
  return (
    <EmptyState
      icon="🔍"
      title="Nenhum resultado encontrado"
      description={
        query
          ? `Não encontramos resultados para "${query}". Tente outros termos de busca.`
          : 'Não há documentos que correspondam aos seus critérios de busca.'
      }
    />
  );
}
