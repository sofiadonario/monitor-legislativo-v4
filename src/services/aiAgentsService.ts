/**
 * AI Agents Service
 * Frontend service for managing AI agents and their interactions
 */

import apiClient from './apiClient';
import { API_ENDPOINTS } from '../config/api';

export interface AgentConfig {
  agent_id: string;
  role: string;
  max_short_term_memory?: number;
  max_long_term_memory?: number;
  cost_budget_monthly?: number;
  temperature?: number;
  model?: string;
}

export interface QueryRequest {
  query: string;
  context?: Record<string, any>;
  include_memory?: boolean;
}

export interface QueryResponse {
  agent_id: string;
  query: string;
  response: string;
  model_used: string;
  tokens_input: number;
  tokens_output: number;
  cost_cents: number;
  response_time_ms: number;
  from_cache: boolean;
  memory_context_used: boolean;
}

export interface AgentStatus {
  agent_id: string;
  role: string;
  status: string;
  memory_stats: Record<string, any>;
  cost_summary: Record<string, any>;
  configuration: Record<string, any>;
}

export interface SystemStatus {
  manager_status: string;
  active_agents: number;
  total_monthly_cost_cents: number;
  system_health: string;
  agents: Record<string, any>;
}

export interface MemorySearchRequest {
  agent_id: string;
  keywords: string[];
  limit?: number;
}

export interface AgentRole {
  role: string;
  name: string;
  description: string;
}

export class AIAgentsService {
  /**
   * Create a new AI agent
   */
  async createAgent(config: AgentConfig): Promise<{ status: string; message: string; agent_id: string; role: string }> {
    return apiClient.post(API_ENDPOINTS.ai.agents, config);
  }

  /**
   * Query an AI agent
   */
  async queryAgent(agentId: string, request: QueryRequest): Promise<QueryResponse> {
    const endpoint = API_ENDPOINTS.ai.query.replace('{agent_id}', agentId);
    return apiClient.post(endpoint, request);
  }

  /**
   * Get agent status
   */
  async getAgentStatus(agentId: string): Promise<AgentStatus> {
    const endpoint = API_ENDPOINTS.ai.status.replace('{agent_id}', agentId);
    return apiClient.get(endpoint);
  }

  /**
   * Get system status
   */
  async getSystemStatus(): Promise<SystemStatus> {
    return apiClient.get(API_ENDPOINTS.ai.systemStatus);
  }

  /**
   * Search agent memory
   */
  async searchMemory(request: MemorySearchRequest): Promise<{
    status: string;
    agent_id: string;
    keywords: string[];
    results_count: number;
    memory_entries: any[];
  }> {
    return apiClient.post(API_ENDPOINTS.ai.memorySearch, request);
  }

  /**
   * Optimize agent memory
   */
  async optimizeMemory(agentId: string, options: {
    remove_duplicates?: boolean;
    cleanup_expired?: boolean;
  } = {}): Promise<{
    status: string;
    agent_id: string;
    cleanup_results: Record<string, any>;
    optimization_scheduled: boolean;
    message: string;
  }> {
    return apiClient.post(API_ENDPOINTS.ai.memoryOptimize, {
      agent_id: agentId,
      ...options
    });
  }

  /**
   * Get memory performance stats
   */
  async getMemoryPerformance(agentId: string): Promise<{
    status: string;
    performance_stats: Record<string, any>;
  }> {
    const endpoint = API_ENDPOINTS.ai.memoryPerformance.replace('{agent_id}', agentId);
    return apiClient.get(endpoint);
  }

  /**
   * Backup agent memory
   */
  async backupMemory(agentId: string): Promise<{
    status: string;
    agent_id: string;
    backup_id: string;
    message: string;
  }> {
    const endpoint = API_ENDPOINTS.ai.memoryBackup.replace('{agent_id}', agentId);
    return apiClient.post(endpoint, {});
  }

  /**
   * Get available agent roles
   */
  async getAvailableRoles(): Promise<{
    available_roles: AgentRole[];
    total_roles: number;
  }> {
    return apiClient.get(API_ENDPOINTS.ai.roles);
  }

  /**
   * Check AI agents service health
   */
  async checkHealth(): Promise<{
    status: string;
    ai_agents_available: boolean;
    active_agents?: number;
    system_health?: string;
    features_available?: string[];
    supported_roles?: string[];
    message?: string;
    error?: string;
  }> {
    return apiClient.get(API_ENDPOINTS.ai.health);
  }

  /**
   * Helper method to create a research assistant agent
   */
  async createResearchAssistant(agentId: string, budget: number = 10.0): Promise<{ status: string; message: string; agent_id: string; role: string }> {
    return this.createAgent({
      agent_id: agentId,
      role: 'research_assistant',
      cost_budget_monthly: budget,
      temperature: 0.1,
      model: 'gpt-4o-mini'
    });
  }

  /**
   * Helper method to create a citation specialist agent
   */
  async createCitationSpecialist(agentId: string, budget: number = 5.0): Promise<{ status: string; message: string; agent_id: string; role: string }> {
    return this.createAgent({
      agent_id: agentId,
      role: 'citation_specialist',
      cost_budget_monthly: budget,
      temperature: 0.05,
      model: 'gpt-4o-mini'
    });
  }

  /**
   * Helper method for research queries
   */
  async askResearchQuestion(agentId: string, question: string, context?: Record<string, any>): Promise<QueryResponse> {
    return this.queryAgent(agentId, {
      query: question,
      context,
      include_memory: true
    });
  }
}

export const aiAgentsService = new AIAgentsService();