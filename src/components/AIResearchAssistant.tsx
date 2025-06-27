/**
 * AI Research Assistant Component
 * Frontend interface for AI-powered research assistance
 */

import React, { useState, useEffect, useRef } from 'react';
import { aiAgentsService, AgentStatus, QueryResponse } from '../services/aiAgentsService';
import { documentAnalysisService, DocumentSummary, CitationResult } from '../services/documentAnalysisService';
import { LoadingSpinner } from './LoadingSpinner';

interface Message {
  id: string;
  type: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  metadata?: {
    cost_cents?: number;
    from_cache?: boolean;
    processing_time_ms?: number;
    citations?: CitationResult[];
    summary?: DocumentSummary;
  };
}

interface AIResearchAssistantProps {
  selectedDocuments?: Array<Record<string, any>>;
  onDocumentAnalyzed?: (analysis: any) => void;
  className?: string;
}

const AIResearchAssistant: React.FC<AIResearchAssistantProps> = ({
  selectedDocuments = [],
  onDocumentAnalyzed,
  className = ''
}) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [isAgentInitialized, setIsAgentInitialized] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [availableFeatures, setAvailableFeatures] = useState<string[]>([]);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const agentId = 'research_assistant_main';

  useEffect(() => {
    initializeAgent();
    checkServiceHealth();
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const initializeAgent = async () => {
    try {
      setIsLoading(true);
      
      // Try to get existing agent status first
      try {
        const status = await aiAgentsService.getAgentStatus(agentId);
        setAgentStatus(status);
        setIsAgentInitialized(true);
        addSystemMessage('AI Research Assistant connected successfully!');
      } catch {
        // Agent doesn't exist, create new one
        await aiAgentsService.createResearchAssistant(agentId, 15.0);
        const status = await aiAgentsService.getAgentStatus(agentId);
        setAgentStatus(status);
        setIsAgentInitialized(true);
        addSystemMessage('New AI Research Assistant created and ready to help with Brazilian legislative research!');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to initialize AI agent';
      setError(errorMessage);
      addSystemMessage(`Error: ${errorMessage}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const checkServiceHealth = async () => {
    try {
      const [aiHealth, analysisHealth] = await Promise.all([
        aiAgentsService.checkHealth(),
        documentAnalysisService.checkHealth()
      ]);

      const features: string[] = [];
      if (aiHealth.ai_agents_available) features.push('AI Conversation');
      if (analysisHealth.ai_document_analysis_available) features.push('Document Analysis', 'Citation Generation');
      
      setAvailableFeatures(features);
    } catch (err) {
      console.warn('Could not check service health:', err);
    }
  };

  const addSystemMessage = (content: string, type: 'info' | 'error' = 'info') => {
    const message: Message = {
      id: Date.now().toString(),
      type: 'system',
      content,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, message]);
  };

  const addUserMessage = (content: string) => {
    const message: Message = {
      id: Date.now().toString(),
      type: 'user',
      content,
      timestamp: new Date()
    };
    setMessages(prev => [...prev, message]);
  };

  const addAssistantMessage = (response: QueryResponse, additionalData?: any) => {
    const message: Message = {
      id: Date.now().toString(),
      type: 'assistant',
      content: response.response,
      timestamp: new Date(),
      metadata: {
        cost_cents: response.cost_cents,
        from_cache: response.from_cache,
        processing_time_ms: response.response_time_ms,
        ...additionalData
      }
    };
    setMessages(prev => [...prev, message]);
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || !isAgentInitialized || isLoading) return;

    const userMessage = inputMessage.trim();
    setInputMessage('');
    addUserMessage(userMessage);
    setIsLoading(true);
    setError(null);

    try {
      // Prepare context with selected documents
      const context: Record<string, any> = {};
      if (selectedDocuments.length > 0) {
        context.selected_documents = selectedDocuments.map(doc => ({
          urn: doc.urn,
          title: doc.title,
          type: doc.tipo_documento,
          authority: doc.autoridade
        }));
        context.document_count = selectedDocuments.length;
      }

      // Send query to AI agent
      const response = await aiAgentsService.askResearchQuestion(agentId, userMessage, context);
      
      // Check if request involves document analysis
      const needsAnalysis = userMessage.toLowerCase().includes('analis') || 
                          userMessage.toLowerCase().includes('resumo') ||
                          userMessage.toLowerCase().includes('citação') ||
                          userMessage.toLowerCase().includes('citation');

      let additionalData: any = {};

      // Perform document analysis if needed and documents are selected
      if (needsAnalysis && selectedDocuments.length > 0) {
        try {
          const analysisPromises = selectedDocuments.slice(0, 3).map(async (doc) => {
            const [summary, citation] = await Promise.all([
              documentAnalysisService.summarizeDocument(doc),
              documentAnalysisService.generateABNTCitation(doc, userMessage)
            ]);
            return { summary, citation };
          });

          const analyses = await Promise.all(analysisPromises);
          additionalData.summaries = analyses.map(a => a.summary);
          additionalData.citations = analyses.map(a => a.citation);

          if (onDocumentAnalyzed) {
            analyses.forEach(analysis => onDocumentAnalyzed(analysis));
          }
        } catch (analysisError) {
          console.warn('Document analysis failed:', analysisError);
        }
      }

      addAssistantMessage(response, additionalData);

      // Update agent status
      const updatedStatus = await aiAgentsService.getAgentStatus(agentId);
      setAgentStatus(updatedStatus);

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to send message';
      setError(errorMessage);
      addSystemMessage(`Error: ${errorMessage}`, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const suggestedQuestions = [
    "Analise os documentos selecionados e identifique os principais temas de transporte.",
    "Gere citações ABNT para os documentos selecionados.",
    "Quais são as tendências regulatórias no transporte brasileiro?",
    "Compare a legislação federal e estadual de transporte.",
    "Identifique oportunidades de pesquisa nos documentos."
  ];

  const handleSuggestedQuestion = (question: string) => {
    setInputMessage(question);
  };

  return (
    <div className={`ai-research-assistant ${className}`}>
      <div className="assistant-header">
        <div className="header-info">
          <h3>🤖 AI Research Assistant</h3>
          {agentStatus && (
            <div className="agent-status">
              <span className={`status-indicator ${agentStatus.status}`}></span>
              <small>
                Cost: {(agentStatus.cost_summary.monthly_cost_cents / 100).toFixed(2)}¢ | 
                Memory: {agentStatus.memory_stats.short_term_entries + agentStatus.memory_stats.long_term_entries} entries
              </small>
            </div>
          )}
        </div>
        
        {availableFeatures.length > 0 && (
          <div className="available-features">
            <small>Available: {availableFeatures.join(', ')}</small>
          </div>
        )}
      </div>

      <div className="messages-container">
        {messages.map((message) => (
          <div key={message.id} className={`message ${message.type}`}>
            <div className="message-content">
              <div className="content-text">{message.content}</div>
              
              {message.metadata && (
                <div className="message-metadata">
                  {message.metadata.cost_cents !== undefined && (
                    <span className="cost">Cost: {message.metadata.cost_cents.toFixed(4)}¢</span>
                  )}
                  {message.metadata.from_cache && (
                    <span className="cache-hit">Cached</span>
                  )}
                  {message.metadata.processing_time_ms && (
                    <span className="processing-time">{message.metadata.processing_time_ms.toFixed(0)}ms</span>
                  )}
                </div>
              )}

              {message.metadata?.citations && (
                <div className="citations-section">
                  <h4>Generated Citations:</h4>
                  {message.metadata.citations.map((citation, index) => (
                    <div key={index} className="citation-item">
                      <div className="citation-text">{citation.citation_text}</div>
                      <div className="citation-metadata">
                        Style: {citation.citation_style.toUpperCase()} | 
                        Quality: {(citation.quality_score * 100).toFixed(0)}%
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {message.metadata?.summaries && (
                <div className="summaries-section">
                  <h4>Document Summaries:</h4>
                  {message.metadata.summaries.map((summary, index) => (
                    <div key={index} className="summary-item">
                      <h5>{summary.title}</h5>
                      <p>{summary.summary_text}</p>
                      {summary.key_points.length > 0 && (
                        <ul className="key-points">
                          {summary.key_points.map((point, pointIndex) => (
                            <li key={pointIndex}>{point}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
            
            <div className="message-timestamp">
              {message.timestamp.toLocaleTimeString()}
            </div>
          </div>
        ))}
        
        {isLoading && (
          <div className="message assistant loading">
            <LoadingSpinner size="small" />
            <span>AI Research Assistant is thinking...</span>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {messages.length === 0 && selectedDocuments.length === 0 && (
        <div className="suggested-questions">
          <h4>Try asking:</h4>
          {suggestedQuestions.map((question, index) => (
            <button
              key={index}
              className="suggested-question"
              onClick={() => handleSuggestedQuestion(question)}
              disabled={isLoading || !isAgentInitialized}
            >
              {question}
            </button>
          ))}
        </div>
      )}

      {selectedDocuments.length > 0 && (
        <div className="context-info">
          <small>
            📄 {selectedDocuments.length} document{selectedDocuments.length !== 1 ? 's' : ''} selected for analysis
          </small>
        </div>
      )}

      <div className="input-container">
        <textarea
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder={
            isAgentInitialized 
              ? "Ask me about Brazilian legislative research, document analysis, or citations..."
              : "Initializing AI Research Assistant..."
          }
          disabled={isLoading || !isAgentInitialized}
          rows={3}
          className="message-input"
        />
        <button
          onClick={handleSendMessage}
          disabled={isLoading || !isAgentInitialized || !inputMessage.trim()}
          className="send-button"
        >
          {isLoading ? <LoadingSpinner size="small" /> : '📤 Send'}
        </button>
      </div>

      {error && (
        <div className="error-message">
          <strong>Error:</strong> {error}
          <button onClick={() => setError(null)} className="close-error">×</button>
        </div>
      )}
    </div>
  );
};

export default AIResearchAssistant;