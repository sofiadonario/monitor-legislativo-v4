/**
 * AI Cost Monitor Service - Frontend cost tracking for LLM usage
 * Provides real-time cost monitoring and budget alerts
 */

import { API_BASE_URL } from '../config/api';

export interface CostSummary {
  today_cost: number;
  today_requests: number;
  monthly_projection: number;
  daily_limit: number;
  budget_usage_percent: number;
  cost_per_request: number;
}

export interface DailyCosts {
  [date: string]: {
    date: string;
    total_cost: number;
    request_count: number;
    token_count: number;
  };
}

export interface CostAlert {
  type: 'warning' | 'critical' | 'info';
  message: string;
  cost: number;
  threshold: number;
}

/**
 * AI Cost Monitor Service Class
 */
class AICostMonitorService {
  private baseUrl: string;
  private alerts: CostAlert[] = [];

  constructor() {
    this.baseUrl = `${API_BASE_URL}/api/v1/ai-agents`;
  }

  /**
   * Get current cost summary
   */
  async getCostSummary(): Promise<CostSummary | null> {
    try {
      const response = await fetch(`${this.baseUrl}/cost-summary`);
      
      if (!response.ok) {
        throw new Error(`Failed to get cost summary: ${response.statusText}`);
      }

      const data = await response.json();
      return data.success ? data.data : null;
    } catch (error) {
      console.error('Failed to get cost summary:', error);
      return null;
    }
  }

  /**
   * Get daily costs for the last N days
   */
  async getDailyCosts(days: number = 7): Promise<DailyCosts | null> {
    try {
      const response = await fetch(`${this.baseUrl}/daily-costs?days=${days}`);
      
      if (!response.ok) {
        throw new Error(`Failed to get daily costs: ${response.statusText}`);
      }

      const data = await response.json();
      return data.success ? data.data : null;
    } catch (error) {
      console.error('Failed to get daily costs:', error);
      return null;
    }
  }

  /**
   * Check for cost alerts
   */
  async checkCostAlerts(): Promise<CostAlert[]> {
    const summary = await this.getCostSummary();
    if (!summary) return [];

    const alerts: CostAlert[] = [];

    // Budget usage alerts
    if (summary.budget_usage_percent >= 90) {
      alerts.push({
        type: 'critical',
        message: `Daily budget usage at ${summary.budget_usage_percent.toFixed(1)}%`,
        cost: summary.today_cost,
        threshold: summary.daily_limit
      });
    } else if (summary.budget_usage_percent >= 75) {
      alerts.push({
        type: 'warning',
        message: `Daily budget usage at ${summary.budget_usage_percent.toFixed(1)}%`,
        cost: summary.today_cost,
        threshold: summary.daily_limit
      });
    }

    // Monthly projection alerts
    if (summary.monthly_projection > 30) { // $30/month limit
      alerts.push({
        type: 'warning',
        message: `Monthly projection: $${summary.monthly_projection.toFixed(2)} (exceeds $30 budget)`,
        cost: summary.monthly_projection,
        threshold: 30
      });
    }

    // High cost per request alerts
    if (summary.cost_per_request > 0.01) {
      alerts.push({
        type: 'info',
        message: `High cost per request: $${summary.cost_per_request.toFixed(4)}`,
        cost: summary.cost_per_request,
        threshold: 0.01
      });
    }

    this.alerts = alerts;
    return alerts;
  }

  /**
   * Get cost efficiency metrics
   */
  async getCostEfficiency(): Promise<{
    cache_hit_rate: number;
    cost_savings_today: number;
    cost_savings_projected: number;
    efficiency_score: number;
  } | null> {
    try {
      // Get cache statistics
      const cacheResponse = await fetch(`${API_BASE_URL}/api/v1/semantic-cache/statistics`);
      const agentResponse = await fetch(`${this.baseUrl}/health`);
      
      if (!cacheResponse.ok || !agentResponse.ok) {
        return null;
      }

      const cacheData = await cacheResponse.json();
      const agentData = await agentResponse.json();

      const cache_hit_rate = agentData.cache_hit_rate || 0;
      const total_cost = agentData.total_cost_usd || 0;
      
      // Calculate savings based on cache hit rate
      const theoretical_cost_without_cache = total_cost / (1 - cache_hit_rate);
      const cost_savings_today = theoretical_cost_without_cache - total_cost;
      const cost_savings_projected = cost_savings_today * 30; // Monthly

      // Efficiency score (0-100)
      const efficiency_score = Math.min(100, cache_hit_rate * 100 + (cost_savings_today / 0.1) * 10);

      return {
        cache_hit_rate,
        cost_savings_today,
        cost_savings_projected,
        efficiency_score
      };
    } catch (error) {
      console.error('Failed to get cost efficiency:', error);
      return null;
    }
  }

  /**
   * Format cost for display
   */
  formatCost(cost: number): string {
    if (cost < 0.001) {
      return `$${(cost * 1000).toFixed(2)}‰`; // Per mille for very small costs
    } else if (cost < 1) {
      return `$${cost.toFixed(4)}`;
    } else {
      return `$${cost.toFixed(2)}`;
    }
  }

  /**
   * Get cost trend (increasing/decreasing/stable)
   */
  async getCostTrend(): Promise<'increasing' | 'decreasing' | 'stable' | null> {
    const dailyCosts = await this.getDailyCosts(7);
    if (!dailyCosts) return null;

    const dates = Object.keys(dailyCosts).sort();
    if (dates.length < 3) return null;

    const recent = dates.slice(-3);
    const costs = recent.map(date => dailyCosts[date].total_cost);

    // Simple trend analysis
    const firstHalf = costs.slice(0, Math.floor(costs.length / 2));
    const secondHalf = costs.slice(Math.floor(costs.length / 2));

    const firstAvg = firstHalf.reduce((a, b) => a + b, 0) / firstHalf.length;
    const secondAvg = secondHalf.reduce((a, b) => a + b, 0) / secondHalf.length;

    const changePercent = ((secondAvg - firstAvg) / firstAvg) * 100;

    if (changePercent > 10) return 'increasing';
    if (changePercent < -10) return 'decreasing';
    return 'stable';
  }

  /**
   * Estimate costs for different usage scenarios
   */
  estimateCosts(requestsPerDay: number): {
    daily: number;
    monthly: number;
    yearly: number;
    with_cache: number;
    savings: number;
  } {
    const avgCostPerRequest = 0.003; // $0.003 per request average
    const cacheHitRate = 0.75; // 75% cache hit rate

    const dailyCost = requestsPerDay * avgCostPerRequest;
    const dailyCostWithCache = dailyCost * (1 - cacheHitRate);
    
    return {
      daily: dailyCost,
      monthly: dailyCost * 30,
      yearly: dailyCost * 365,
      with_cache: dailyCostWithCache * 30, // Monthly with cache
      savings: (dailyCost - dailyCostWithCache) * 30 // Monthly savings
    };
  }

  /**
   * Get current alerts
   */
  getCurrentAlerts(): CostAlert[] {
    return this.alerts;
  }

  /**
   * Clear alerts
   */
  clearAlerts(): void {
    this.alerts = [];
  }

  /**
   * Check if costs are within budget
   */
  async isWithinBudget(): Promise<boolean> {
    const summary = await this.getCostSummary();
    return summary ? summary.budget_usage_percent < 90 : true;
  }

  /**
   * Get usage recommendations
   */
  async getUsageRecommendations(): Promise<string[]> {
    const recommendations: string[] = [];
    const summary = await this.getCostSummary();
    const efficiency = await this.getCostEfficiency();

    if (!summary) return recommendations;

    // High usage recommendations
    if (summary.budget_usage_percent > 80) {
      recommendations.push("Consider reducing AI analysis frequency");
      recommendations.push("Enable more aggressive semantic caching");
    }

    // Cache efficiency recommendations
    if (efficiency && efficiency.cache_hit_rate < 0.6) {
      recommendations.push("Cache hit rate is low - review similarity thresholds");
      recommendations.push("Consider pre-caching common analysis types");
    }

    // Cost per request recommendations
    if (summary.cost_per_request > 0.005) {
      recommendations.push("High cost per request - optimize prompts for shorter responses");
      recommendations.push("Use batch processing for multiple documents");
    }

    // Monthly projection recommendations
    if (summary.monthly_projection > 25) {
      recommendations.push("Monthly projection exceeds budget - implement daily limits");
      recommendations.push("Consider using GPT-3.5-turbo instead of GPT-4");
    }

    return recommendations;
  }
}

// Create and export singleton instance
export const aiCostMonitor = new AICostMonitorService();

// Export service
export default aiCostMonitor;