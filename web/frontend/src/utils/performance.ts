/**
 * Frontend Performance Monitoring Utilities
 * Tracks Web Vitals, custom metrics, and performance optimizations
 */

import { getCLS, getFCP, getFID, getLCP, getTTFB } from 'web-vitals';

interface PerformanceMetric {
  name: string;
  value: number;
  rating: 'good' | 'needs-improvement' | 'poor';
  timestamp: number;
}

interface PerformanceReport {
  metrics: PerformanceMetric[];
  userAgent: string;
  url: string;
  timestamp: number;
  connectionType?: string;
  deviceMemory?: number;
}

class PerformanceMonitorClass {
  private metrics: PerformanceMetric[] = [];
  private observers: PerformanceObserver[] = [];
  private reportCallback?: (report: PerformanceReport) => void;
  private reportInterval?: NodeJS.Timeout;

  init(options?: {
    reportCallback?: (report: PerformanceReport) => void;
    reportIntervalMs?: number;
  }) {
    this.reportCallback = options?.reportCallback;

    // Start collecting Web Vitals
    this.collectWebVitals();

    // Setup Performance Observer for custom metrics
    this.setupPerformanceObserver();

    // Setup reporting interval
    if (options?.reportIntervalMs) {
      this.reportInterval = setInterval(() => {
        this.report();
      }, options.reportIntervalMs);
    }

    // Monitor long tasks
    this.monitorLongTasks();

    // Monitor resource timing
    this.monitorResourceTiming();
  }

  private collectWebVitals() {
    // Cumulative Layout Shift
    getCLS((metric) => {
      this.addMetric({
        name: 'CLS',
        value: metric.value,
        rating: metric.rating || 'needs-improvement',
        timestamp: Date.now(),
      });
    });

    // First Contentful Paint
    getFCP((metric) => {
      this.addMetric({
        name: 'FCP',
        value: metric.value,
        rating: metric.rating || 'needs-improvement',
        timestamp: Date.now(),
      });
    });

    // First Input Delay
    getFID((metric) => {
      this.addMetric({
        name: 'FID',
        value: metric.value,
        rating: metric.rating || 'needs-improvement',
        timestamp: Date.now(),
      });
    });

    // Largest Contentful Paint
    getLCP((metric) => {
      this.addMetric({
        name: 'LCP',
        value: metric.value,
        rating: metric.rating || 'needs-improvement',
        timestamp: Date.now(),
      });
    });

    // Time to First Byte
    getTTFB((metric) => {
      this.addMetric({
        name: 'TTFB',
        value: metric.value,
        rating: metric.rating || 'needs-improvement',
        timestamp: Date.now(),
      });
    });
  }

  private setupPerformanceObserver() {
    if (!('PerformanceObserver' in window)) return;

    // Monitor navigation timing
    try {
      const navigationObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.entryType === 'navigation') {
            const navEntry = entry as PerformanceNavigationTiming;
            
            // DNS lookup time
            this.addMetric({
              name: 'DNS_Lookup',
              value: navEntry.domainLookupEnd - navEntry.domainLookupStart,
              rating: this.getRating(navEntry.domainLookupEnd - navEntry.domainLookupStart, 50, 100),
              timestamp: Date.now(),
            });

            // TCP connection time
            this.addMetric({
              name: 'TCP_Connection',
              value: navEntry.connectEnd - navEntry.connectStart,
              rating: this.getRating(navEntry.connectEnd - navEntry.connectStart, 50, 150),
              timestamp: Date.now(),
            });

            // DOM Content Loaded
            this.addMetric({
              name: 'DOM_Content_Loaded',
              value: navEntry.domContentLoadedEventEnd - navEntry.domContentLoadedEventStart,
              rating: this.getRating(
                navEntry.domContentLoadedEventEnd - navEntry.domContentLoadedEventStart,
                500,
                1500
              ),
              timestamp: Date.now(),
            });
          }
        }
      });

      navigationObserver.observe({ entryTypes: ['navigation'] });
      this.observers.push(navigationObserver);
    } catch (e) {
      console.error('Failed to setup navigation observer:', e);
    }
  }

  private monitorLongTasks() {
    if (!('PerformanceObserver' in window) || !PerformanceObserver.supportedEntryTypes?.includes('longtask')) {
      return;
    }

    try {
      const longTaskObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          console.warn('Long task detected:', {
            duration: entry.duration,
            startTime: entry.startTime,
            name: entry.name,
          });

          this.addMetric({
            name: 'Long_Task',
            value: entry.duration,
            rating: 'poor',
            timestamp: Date.now(),
          });
        }
      });

      longTaskObserver.observe({ entryTypes: ['longtask'] });
      this.observers.push(longTaskObserver);
    } catch (e) {
      console.error('Failed to setup long task observer:', e);
    }
  }

  private monitorResourceTiming() {
    if (!('PerformanceObserver' in window)) return;

    try {
      const resourceObserver = new PerformanceObserver((list) => {
        const entries = list.getEntries() as PerformanceResourceTiming[];
        
        // Group by resource type
        const resourcesByType: { [key: string]: number[] } = {};
        
        for (const entry of entries) {
          const type = entry.initiatorType || 'other';
          if (!resourcesByType[type]) {
            resourcesByType[type] = [];
          }
          resourcesByType[type].push(entry.duration);
        }

        // Calculate average load time by type
        for (const [type, durations] of Object.entries(resourcesByType)) {
          const avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
          
          this.addMetric({
            name: `Resource_${type}_Avg_Load`,
            value: avgDuration,
            rating: this.getRating(avgDuration, 100, 300),
            timestamp: Date.now(),
          });
        }
      });

      resourceObserver.observe({ entryTypes: ['resource'] });
      this.observers.push(resourceObserver);
    } catch (e) {
      console.error('Failed to setup resource observer:', e);
    }
  }

  private getRating(value: number, goodThreshold: number, poorThreshold: number): 'good' | 'needs-improvement' | 'poor' {
    if (value <= goodThreshold) return 'good';
    if (value <= poorThreshold) return 'needs-improvement';
    return 'poor';
  }

  private addMetric(metric: PerformanceMetric) {
    this.metrics.push(metric);
    
    // Keep only last 100 metrics to prevent memory issues
    if (this.metrics.length > 100) {
      this.metrics = this.metrics.slice(-100);
    }
  }

  // Public API

  measureTime(name: string): () => void {
    const startTime = performance.now();
    
    return () => {
      const duration = performance.now() - startTime;
      this.addMetric({
        name: `Custom_${name}`,
        value: duration,
        rating: this.getRating(duration, 100, 500),
        timestamp: Date.now(),
      });
    };
  }

  mark(name: string) {
    if ('performance' in window && 'mark' in performance) {
      performance.mark(name);
    }
  }

  measure(name: string, startMark: string, endMark?: string) {
    if ('performance' in window && 'measure' in performance) {
      try {
        if (endMark) {
          performance.measure(name, startMark, endMark);
        } else {
          performance.measure(name, startMark);
        }
        
        const measures = performance.getEntriesByName(name, 'measure');
        const latestMeasure = measures[measures.length - 1];
        
        if (latestMeasure) {
          this.addMetric({
            name: `Measure_${name}`,
            value: latestMeasure.duration,
            rating: this.getRating(latestMeasure.duration, 100, 500),
            timestamp: Date.now(),
          });
        }
      } catch (e) {
        console.error('Failed to measure:', e);
      }
    }
  }

  reportWebVitals() {
    // Report current metrics
    this.report();
  }

  private report() {
    if (!this.reportCallback || this.metrics.length === 0) return;

    const report: PerformanceReport = {
      metrics: [...this.metrics],
      userAgent: navigator.userAgent,
      url: window.location.href,
      timestamp: Date.now(),
    };

    // Add connection info if available
    if ('connection' in navigator) {
      const conn = (navigator as any).connection;
      report.connectionType = conn.effectiveType;
    }

    // Add device memory if available
    if ('deviceMemory' in navigator) {
      report.deviceMemory = (navigator as any).deviceMemory;
    }

    this.reportCallback(report);
    
    // Clear reported metrics
    this.metrics = [];
  }

  getMetrics(): PerformanceMetric[] {
    return [...this.metrics];
  }

  cleanup() {
    // Disconnect all observers
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];

    // Clear reporting interval
    if (this.reportInterval) {
      clearInterval(this.reportInterval);
    }

    // Clear metrics
    this.metrics = [];
  }
}

// Singleton instance
export const PerformanceMonitor = new PerformanceMonitorClass();

// React performance profiler component
import React, { Profiler, ProfilerOnRenderCallback } from 'react';

interface PerformanceProfilerProps {
  id: string;
  children: React.ReactNode;
}

export const PerformanceProfiler: React.FC<PerformanceProfilerProps> = ({ id, children }) => {
  const onRender: ProfilerOnRenderCallback = (
    id,
    phase,
    actualDuration,
    baseDuration,
    startTime,
    commitTime,
    interactions
  ) => {
    // Only log slow renders in development
    if (process.env.NODE_ENV === 'development' && actualDuration > 16) {
      console.warn(`Slow render detected in ${id}:`, {
        phase,
        actualDuration,
        baseDuration,
        interactions: Array.from(interactions),
      });
    }

    // Record render metric
    PerformanceMonitor.addMetric({
      name: `React_Render_${id}`,
      value: actualDuration,
      rating: PerformanceMonitor.getRating(actualDuration, 16, 50),
      timestamp: Date.now(),
    });
  };

  return (
    <Profiler id={id} onRender={onRender}>
      {children}
    </Profiler>
  );
};

// Utility functions for performance optimization

export const debounce = <T extends (...args: any[]) => any>(
  func: T,
  wait: number
): ((...args: Parameters<T>) => void) => {
  let timeout: NodeJS.Timeout;

  return (...args: Parameters<T>) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
};

export const throttle = <T extends (...args: any[]) => any>(
  func: T,
  limit: number
): ((...args: Parameters<T>) => void) => {
  let inThrottle: boolean;

  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
};

// Lazy load images with Intersection Observer
export const lazyLoadImage = (imageSrc: string, placeholderSrc?: string): Promise<string> => {
  return new Promise((resolve) => {
    const img = new Image();
    img.src = imageSrc;
    img.onload = () => resolve(imageSrc);
    img.onerror = () => resolve(placeholderSrc || '');
  });
};

// Request idle callback polyfill
export const requestIdleCallback =
  window.requestIdleCallback ||
  function (cb: IdleRequestCallback) {
    const start = Date.now();
    return setTimeout(() => {
      cb({
        didTimeout: false,
        timeRemaining: () => Math.max(0, 50 - (Date.now() - start)),
      });
    }, 1);
  };

export const cancelIdleCallback =
  window.cancelIdleCallback ||
  function (id: number) {
    clearTimeout(id);
  };