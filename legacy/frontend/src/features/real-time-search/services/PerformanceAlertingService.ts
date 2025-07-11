/**
 * Performance Alerting Service
 * Monitors performance metrics and triggers alerts when thresholds are exceeded
 */

interface AlertThreshold {
  metric: string;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  value: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  duration?: number; // Time in ms the condition must persist
  cooldown?: number; // Minimum time between alerts in ms
}

interface Alert {
  id: string;
  metric: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  value: number;
  threshold: number;
  timestamp: number;
  acknowledged: boolean;
  resolved: boolean;
  resolvedAt?: number;
}

interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  thresholds: AlertThreshold[];
  actions: AlertAction[];
}

interface AlertAction {
  type: 'notification' | 'email' | 'webhook' | 'console' | 'storage';
  config: Record<string, any>;
}

interface PerformanceData {
  api: {
    responseTime: number;
    successRate: number;
    errorRate: number;
    requestsPerMinute: number;
    availability: number;
  };
  cache: {
    hitRate: number;
    memoryUsage: number;
    evictions: number;
  };
  circuit: {
    status: string;
    failureCount: number;
  };
  user: {
    averageSearchTime: number;
    bounceRate: number;
  };
}

export class PerformanceAlertingService {
  private alerts: Map<string, Alert> = new Map();
  private alertRules: AlertRule[] = [];
  private thresholdStates: Map<string, { startTime: number; lastAlert: number }> = new Map();
  private isMonitoring = false;
  private monitoringInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.initializeDefaultRules();
    this.loadStoredAlerts();
  }

  /**
   * Start performance monitoring
   */
  startMonitoring(intervalMs: number = 30000) {
    if (this.isMonitoring) return;

    this.isMonitoring = true;
    this.monitoringInterval = setInterval(() => {
      this.checkMetrics();
    }, intervalMs);

    console.log('Performance monitoring started');
  }

  /**
   * Stop performance monitoring
   */
  stopMonitoring() {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
    this.isMonitoring = false;
    console.log('Performance monitoring stopped');
  }

  /**
   * Check current metrics against alert rules
   */
  private async checkMetrics() {
    try {
      const metrics = await this.getCurrentMetrics();
      
      for (const rule of this.alertRules) {
        if (!rule.enabled) continue;

        for (const threshold of rule.thresholds) {
          this.evaluateThreshold(rule, threshold, metrics);
        }
      }
    } catch (error) {
      console.error('Failed to check metrics:', error);
    }
  }

  /**
   * Get current performance metrics
   */
  private async getCurrentMetrics(): Promise<PerformanceData> {
    // Simulate fetching current metrics - in real implementation, 
    // this would fetch from PerformanceMetrics component or services
    const mockMetrics: PerformanceData = {
      api: {
        responseTime: Math.random() * 1000 + 200,
        successRate: 95 + Math.random() * 5,
        errorRate: Math.random() * 5,
        requestsPerMinute: Math.random() * 50 + 10,
        availability: 95 + Math.random() * 5
      },
      cache: {
        hitRate: 70 + Math.random() * 30,
        memoryUsage: Math.random() * 100,
        evictions: Math.random() * 10
      },
      circuit: {
        status: Math.random() > 0.9 ? 'OPEN' : 'CLOSED',
        failureCount: Math.random() * 5
      },
      user: {
        averageSearchTime: Math.random() * 2000 + 500,
        bounceRate: Math.random() * 20
      }
    };

    return mockMetrics;
  }

  /**
   * Evaluate a threshold against current metrics
   */
  private evaluateThreshold(rule: AlertRule, threshold: AlertThreshold, metrics: PerformanceData) {
    const value = this.getMetricValue(threshold.metric, metrics);
    if (value === null) return;

    const conditionMet = this.evaluateCondition(value, threshold.operator, threshold.value);
    const thresholdKey = `${rule.id}-${threshold.metric}`;

    if (conditionMet) {
      const state = this.thresholdStates.get(thresholdKey);
      const now = Date.now();

      if (!state) {
        // First time condition is met
        this.thresholdStates.set(thresholdKey, { startTime: now, lastAlert: 0 });
      } else {
        // Check if duration requirement is met
        const duration = threshold.duration || 0;
        const timeSinceMet = now - state.startTime;
        const timeSinceLastAlert = now - state.lastAlert;
        const cooldown = threshold.cooldown || 300000; // 5 minutes default

        if (timeSinceMet >= duration && timeSinceLastAlert >= cooldown) {
          this.triggerAlert(rule, threshold, value);
          state.lastAlert = now;
        }
      }
    } else {
      // Condition not met, reset threshold state
      this.thresholdStates.delete(thresholdKey);
      
      // Check if there's an existing alert to resolve
      this.resolveAlert(rule.id, threshold.metric);
    }
  }

  /**
   * Get metric value from performance data
   */
  private getMetricValue(metric: string, data: PerformanceData): number | null {
    const parts = metric.split('.');
    let value: any = data;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return null;
      }
    }

    return typeof value === 'number' ? value : null;
  }

  /**
   * Evaluate condition
   */
  private evaluateCondition(value: number, operator: string, threshold: number): boolean {
    switch (operator) {
      case 'gt': return value > threshold;
      case 'gte': return value >= threshold;
      case 'lt': return value < threshold;
      case 'lte': return value <= threshold;
      case 'eq': return value === threshold;
      default: return false;
    }
  }

  /**
   * Trigger an alert
   */
  private triggerAlert(rule: AlertRule, threshold: AlertThreshold, value: number) {
    const alertId = this.generateAlertId();
    const alert: Alert = {
      id: alertId,
      metric: threshold.metric,
      severity: threshold.severity,
      message: this.generateAlertMessage(rule.name, threshold, value),
      value,
      threshold: threshold.value,
      timestamp: Date.now(),
      acknowledged: false,
      resolved: false
    };

    this.alerts.set(alertId, alert);
    this.saveAlerts();

    // Execute alert actions
    for (const action of rule.actions) {
      this.executeAlertAction(action, alert);
    }

    console.warn(`🚨 Alert triggered: ${alert.message}`);
  }

  /**
   * Resolve an alert
   */
  private resolveAlert(ruleId: string, metric: string) {
    for (const [alertId, alert] of this.alerts.entries()) {
      if (alert.metric === metric && !alert.resolved) {
        alert.resolved = true;
        alert.resolvedAt = Date.now();
        
        console.info(`✅ Alert resolved: ${alert.message}`);
        break;
      }
    }
    this.saveAlerts();
  }

  /**
   * Execute alert action
   */
  private executeAlertAction(action: AlertAction, alert: Alert) {
    switch (action.type) {
      case 'notification':
        this.sendBrowserNotification(alert);
        break;
      case 'console':
        console.warn(`Alert: ${alert.message}`, alert);
        break;
      case 'storage':
        this.storeAlert(alert);
        break;
      case 'webhook':
        this.sendWebhook(action.config.url, alert);
        break;
      default:
        console.warn(`Unknown alert action type: ${action.type}`);
    }
  }

  /**
   * Send browser notification
   */
  private sendBrowserNotification(alert: Alert) {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(`Performance Alert - ${alert.severity.toUpperCase()}`, {
        body: alert.message,
        icon: this.getSeverityIcon(alert.severity),
        tag: alert.id
      });
    } else if ('Notification' in window && Notification.permission !== 'denied') {
      Notification.requestPermission().then(permission => {
        if (permission === 'granted') {
          this.sendBrowserNotification(alert);
        }
      });
    }
  }

  /**
   * Store alert in localStorage
   */
  private storeAlert(alert: Alert) {
    const stored = localStorage.getItem('lexml_performance_alerts');
    const alerts = stored ? JSON.parse(stored) : [];
    alerts.push(alert);
    
    // Keep only last 100 alerts
    if (alerts.length > 100) {
      alerts.splice(0, alerts.length - 100);
    }
    
    localStorage.setItem('lexml_performance_alerts', JSON.stringify(alerts));
  }

  /**
   * Send webhook notification
   */
  private async sendWebhook(url: string, alert: Alert) {
    try {
      await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert,
          timestamp: new Date().toISOString(),
          service: 'LexML Monitor'
        })
      });
    } catch (error) {
      console.error('Failed to send webhook:', error);
    }
  }

  /**
   * Generate alert message
   */
  private generateAlertMessage(ruleName: string, threshold: AlertThreshold, value: number): string {
    const metricDisplayName = this.getMetricDisplayName(threshold.metric);
    const operator = this.getOperatorDisplayName(threshold.operator);
    
    return `${ruleName}: ${metricDisplayName} is ${value.toFixed(2)} (${operator} ${threshold.value})`;
  }

  /**
   * Get display name for metric
   */
  private getMetricDisplayName(metric: string): string {
    const displayNames: Record<string, string> = {
      'api.responseTime': 'API Response Time',
      'api.successRate': 'API Success Rate',
      'api.errorRate': 'API Error Rate',
      'cache.hitRate': 'Cache Hit Rate',
      'cache.memoryUsage': 'Cache Memory Usage',
      'circuit.status': 'Circuit Breaker Status',
      'user.bounceRate': 'User Bounce Rate'
    };
    
    return displayNames[metric] || metric;
  }

  /**
   * Get display name for operator
   */
  private getOperatorDisplayName(operator: string): string {
    const operators: Record<string, string> = {
      'gt': 'greater than',
      'gte': 'greater than or equal to',
      'lt': 'less than',
      'lte': 'less than or equal to',
      'eq': 'equal to'
    };
    
    return operators[operator] || operator;
  }

  /**
   * Get severity icon
   */
  private getSeverityIcon(severity: string): string {
    const icons: Record<string, string> = {
      'low': '🟡',
      'medium': '🟠',
      'high': '🔴',
      'critical': '💥'
    };
    
    return icons[severity] || '⚠️';
  }

  /**
   * Initialize default alert rules
   */
  private initializeDefaultRules() {
    this.alertRules = [
      {
        id: 'api-performance',
        name: 'API Performance',
        description: 'Monitor API response time and success rate',
        enabled: true,
        thresholds: [
          {
            metric: 'api.responseTime',
            operator: 'gt',
            value: 1000,
            severity: 'medium',
            duration: 60000,
            cooldown: 300000
          },
          {
            metric: 'api.responseTime',
            operator: 'gt',
            value: 2000,
            severity: 'high',
            duration: 30000,
            cooldown: 180000
          },
          {
            metric: 'api.successRate',
            operator: 'lt',
            value: 95,
            severity: 'high',
            duration: 120000,
            cooldown: 300000
          }
        ],
        actions: [
          { type: 'notification', config: {} },
          { type: 'console', config: {} },
          { type: 'storage', config: {} }
        ]
      },
      {
        id: 'cache-performance',
        name: 'Cache Performance',
        description: 'Monitor cache hit rate and memory usage',
        enabled: true,
        thresholds: [
          {
            metric: 'cache.hitRate',
            operator: 'lt',
            value: 70,
            severity: 'medium',
            duration: 300000,
            cooldown: 600000
          },
          {
            metric: 'cache.memoryUsage',
            operator: 'gt',
            value: 90,
            severity: 'high',
            duration: 60000,
            cooldown: 300000
          }
        ],
        actions: [
          { type: 'notification', config: {} },
          { type: 'storage', config: {} }
        ]
      },
      {
        id: 'user-experience',
        name: 'User Experience',
        description: 'Monitor user experience metrics',
        enabled: true,
        thresholds: [
          {
            metric: 'user.bounceRate',
            operator: 'gt',
            value: 50,
            severity: 'medium',
            duration: 600000,
            cooldown: 1800000
          }
        ],
        actions: [
          { type: 'console', config: {} },
          { type: 'storage', config: {} }
        ]
      }
    ];
  }

  /**
   * Load stored alerts
   */
  private loadStoredAlerts() {
    try {
      const stored = localStorage.getItem('lexml_active_alerts');
      if (stored) {
        const alertsArray = JSON.parse(stored);
        alertsArray.forEach((alert: Alert) => {
          this.alerts.set(alert.id, alert);
        });
      }
    } catch (error) {
      console.warn('Failed to load stored alerts:', error);
    }
  }

  /**
   * Save alerts to storage
   */
  private saveAlerts() {
    try {
      const alertsArray = Array.from(this.alerts.values());
      localStorage.setItem('lexml_active_alerts', JSON.stringify(alertsArray));
    } catch (error) {
      console.warn('Failed to save alerts:', error);
    }
  }

  /**
   * Generate unique alert ID
   */
  private generateAlertId(): string {
    return `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get all active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.alerts.values()).filter(alert => !alert.resolved);
  }

  /**
   * Get all alerts (including resolved)
   */
  getAllAlerts(): Alert[] {
    return Array.from(this.alerts.values());
  }

  /**
   * Acknowledge an alert
   */
  acknowledgeAlert(alertId: string): boolean {
    const alert = this.alerts.get(alertId);
    if (alert) {
      alert.acknowledged = true;
      this.saveAlerts();
      return true;
    }
    return false;
  }

  /**
   * Add custom alert rule
   */
  addAlertRule(rule: Omit<AlertRule, 'id'>): string {
    const ruleId = `rule-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const newRule: AlertRule = { ...rule, id: ruleId };
    this.alertRules.push(newRule);
    this.saveAlertRules();
    return ruleId;
  }

  /**
   * Update alert rule
   */
  updateAlertRule(ruleId: string, updates: Partial<AlertRule>): boolean {
    const ruleIndex = this.alertRules.findIndex(rule => rule.id === ruleId);
    if (ruleIndex !== -1) {
      this.alertRules[ruleIndex] = { ...this.alertRules[ruleIndex], ...updates };
      this.saveAlertRules();
      return true;
    }
    return false;
  }

  /**
   * Save alert rules
   */
  private saveAlertRules() {
    try {
      localStorage.setItem('lexml_alert_rules', JSON.stringify(this.alertRules));
    } catch (error) {
      console.warn('Failed to save alert rules:', error);
    }
  }

  /**
   * Get alert statistics
   */
  getAlertStats() {
    const alerts = this.getAllAlerts();
    const now = Date.now();
    const last24h = now - 24 * 60 * 60 * 1000;
    
    return {
      total: alerts.length,
      active: alerts.filter(a => !a.resolved).length,
      last24h: alerts.filter(a => a.timestamp > last24h).length,
      bySeverity: {
        low: alerts.filter(a => a.severity === 'low').length,
        medium: alerts.filter(a => a.severity === 'medium').length,
        high: alerts.filter(a => a.severity === 'high').length,
        critical: alerts.filter(a => a.severity === 'critical').length
      },
      acknowledged: alerts.filter(a => a.acknowledged).length,
      resolved: alerts.filter(a => a.resolved).length
    };
  }
}

// Global alerting service instance
export const performanceAlertingService = new PerformanceAlertingService();

// Export utility functions
export const startPerformanceMonitoring = (intervalMs?: number) => {
  performanceAlertingService.startPerformanceMonitoring(intervalMs);
};

export const stopPerformanceMonitoring = () => {
  performanceAlertingService.stopMonitoring();
};

export const getActiveAlerts = () => {
  return performanceAlertingService.getActiveAlerts();
};

export const acknowledgeAlert = (alertId: string) => {
  return performanceAlertingService.acknowledgeAlert(alertId);
};