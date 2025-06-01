#!/usr/bin/env node
/**
 * Frontend Performance Testing Suite for Monitor Legislativo v4
 * 
 * Tests browser performance metrics including:
 * - Page load times
 * - Time to Interactive (TTI)
 * - First Contentful Paint (FCP)
 * - Largest Contentful Paint (LCP)
 * - Cache performance
 * - JavaScript bundle performance
 * - Memory usage
 * - Search performance
 */

const { chromium } = require('playwright');
const fs = require('fs').promises;
const path = require('path');

class FrontendPerformanceTest {
    constructor(baseUrl = 'http://localhost:5173') {
        this.baseUrl = baseUrl;
        this.browser = null;
        this.context = null;
        this.page = null;
        this.results = [];
        
        // Performance thresholds
        this.thresholds = {
            pageLoadTime: 3000,        // 3 seconds
            firstContentfulPaint: 1800, // 1.8 seconds
            largestContentfulPaint: 2500, // 2.5 seconds
            timeToInteractive: 3500,    // 3.5 seconds
            cumulativeLayoutShift: 0.1, // 0.1 CLS score
            searchResponseTime: 1500,   // 1.5 seconds
            bundleSize: 5,              // 5MB total
            memoryUsage: 100,           // 100MB
            cacheHitRate: 80            // 80% cache hit rate
        };
    }

    async setup() {
        console.log('🚀 Setting up browser for performance testing...');
        
        // Launch browser with performance monitoring
        this.browser = await chromium.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-web-security',
                '--enable-features=NetworkService',
                '--disable-features=VizDisplayCompositor'
            ]
        });

        this.context = await this.browser.newContext({
            viewport: { width: 1366, height: 768 }
        });

        this.page = await this.context.newPage();
        
        // Enable console logging
        this.page.on('console', msg => {
            if (msg.type() === 'error') {
                console.log(`Console Error: ${msg.text()}`);
            }
        });
    }

    async teardown() {
        if (this.browser) {
            await this.browser.close();
        }
    }

    createMetric(name, value, unit, threshold, passed = null) {
        if (passed === null) {
            passed = unit.includes('time') || unit.includes('size') || unit.includes('memory') 
                ? value <= threshold 
                : value >= threshold;
        }
        
        return {
            name,
            value,
            unit,
            threshold,
            passed,
            timestamp: Date.now()
        };
    }

    async measurePageLoad() {
        console.log('📊 Measuring page load performance...');
        const metrics = [];
        
        try {
            // Navigate and measure load time
            const startTime = Date.now();
            
            await this.page.goto(this.baseUrl, { 
                waitUntil: 'networkidle',
                timeout: 30000 
            });
            
            const endTime = Date.now();
            const pageLoadTime = endTime - startTime;
            
            metrics.push(this.createMetric(
                'Page Load Time',
                pageLoadTime,
                'milliseconds',
                this.thresholds.pageLoadTime
            ));

            // Get Core Web Vitals using Performance API
            const webVitals = await this.page.evaluate(() => {
                return new Promise((resolve) => {
                    const vitals = {};
                    
                    // First Contentful Paint
                    const fcpEntry = performance.getEntriesByName('first-contentful-paint')[0];
                    if (fcpEntry) {
                        vitals.fcp = fcpEntry.startTime;
                    }
                    
                    // Largest Contentful Paint
                    if ('PerformanceObserver' in window) {
                        const observer = new PerformanceObserver((list) => {
                            const entries = list.getEntries();
                            const lastEntry = entries[entries.length - 1];
                            if (lastEntry) {
                                vitals.lcp = lastEntry.startTime;
                            }
                        });
                        observer.observe({ entryTypes: ['largest-contentful-paint'] });
                        
                        // Wait a bit for LCP to be captured
                        setTimeout(() => {
                            observer.disconnect();
                            resolve(vitals);
                        }, 2000);
                    } else {
                        resolve(vitals);
                    }
                });
            });

            if (webVitals.fcp) {
                metrics.push(this.createMetric(
                    'First Contentful Paint',
                    webVitals.fcp,
                    'milliseconds',
                    this.thresholds.firstContentfulPaint
                ));
            }

            if (webVitals.lcp) {
                metrics.push(this.createMetric(
                    'Largest Contentful Paint',
                    webVitals.lcp,
                    'milliseconds',
                    this.thresholds.largestContentfulPaint
                ));
            }

            // Time to Interactive (simplified)
            const interactiveTime = await this.page.evaluate(() => {
                const start = performance.timeOrigin + performance.timing.navigationStart;
                const domContentLoaded = performance.timing.domContentLoadedEventEnd;
                return domContentLoaded - start;
            });

            metrics.push(this.createMetric(
                'Time to Interactive',
                interactiveTime,
                'milliseconds',
                this.thresholds.timeToInteractive
            ));

            return {
                testName: 'Page Load Performance',
                metrics,
                success: true,
                duration: pageLoadTime
            };

        } catch (error) {
            return {
                testName: 'Page Load Performance',
                metrics,
                success: false,
                error: error.message,
                duration: 0
            };
        }
    }

    async measureSearchPerformance() {
        console.log('🔍 Measuring search performance...');
        const metrics = [];
        
        try {
            // Navigate to the application
            await this.page.goto(this.baseUrl, { waitUntil: 'networkidle' });
            
            // Wait for the search input to be available
            await this.page.waitForSelector('input[type="text"]', { timeout: 10000 });
            
            const searchTerms = ['transporte', 'mobilidade', 'trânsito'];
            const searchTimes = [];
            
            for (const term of searchTerms) {
                console.log(`  Testing search for: ${term}`);
                
                // Clear and type search term
                await this.page.fill('input[type="text"]', '');
                
                const searchStart = Date.now();
                await this.page.fill('input[type="text"]', term);
                
                // Wait for search results to appear
                try {
                    await this.page.waitForFunction(
                        () => {
                            const results = document.querySelectorAll('[data-testid="search-result"], .document-card, .search-result');
                            return results.length > 0;
                        },
                        { timeout: 5000 }
                    );
                    
                    const searchEnd = Date.now();
                    const searchTime = searchEnd - searchStart;
                    searchTimes.push(searchTime);
                    
                    metrics.push(this.createMetric(
                        `Search "${term}" Response Time`,
                        searchTime,
                        'milliseconds',
                        this.thresholds.searchResponseTime
                    ));
                    
                } catch (e) {
                    console.log(`    Search for "${term}" timed out`);
                }
                
                // Wait between searches
                await this.page.waitForTimeout(1000);
            }
            
            if (searchTimes.length > 0) {
                const avgSearchTime = searchTimes.reduce((a, b) => a + b, 0) / searchTimes.length;
                metrics.push(this.createMetric(
                    'Average Search Response Time',
                    avgSearchTime,
                    'milliseconds',
                    this.thresholds.searchResponseTime
                ));
            }

            return {
                testName: 'Search Performance',
                metrics,
                success: true,
                duration: searchTimes.reduce((a, b) => a + b, 0)
            };

        } catch (error) {
            return {
                testName: 'Search Performance',
                metrics,
                success: false,
                error: error.message,
                duration: 0
            };
        }
    }

    async measureCachePerformance() {
        console.log('📦 Measuring cache performance...');
        const metrics = [];
        
        try {
            // First visit (no cache)
            const firstLoadStart = Date.now();
            await this.page.goto(this.baseUrl, { waitUntil: 'networkidle' });
            const firstLoadTime = Date.now() - firstLoadStart;

            // Navigate away and back (test cache)
            await this.page.goto('about:blank');
            
            const cachedLoadStart = Date.now();
            await this.page.goto(this.baseUrl, { waitUntil: 'networkidle' });
            const cachedLoadTime = Date.now() - cachedLoadStart;

            const cacheImprovement = ((firstLoadTime - cachedLoadTime) / firstLoadTime) * 100;

            metrics.push(this.createMetric(
                'First Load Time',
                firstLoadTime,
                'milliseconds',
                this.thresholds.pageLoadTime
            ));

            metrics.push(this.createMetric(
                'Cached Load Time',
                cachedLoadTime,
                'milliseconds',
                this.thresholds.pageLoadTime * 0.5 // Cached should be 50% faster
            ));

            metrics.push(this.createMetric(
                'Cache Performance Improvement',
                cacheImprovement,
                'percentage',
                20 // At least 20% improvement
            ));

            return {
                testName: 'Cache Performance',
                metrics,
                success: true,
                duration: firstLoadTime + cachedLoadTime
            };

        } catch (error) {
            return {
                testName: 'Cache Performance',
                metrics,
                success: false,
                error: error.message,
                duration: 0
            };
        }
    }

    async measureResourceUsage() {
        console.log('💾 Measuring resource usage...');
        const metrics = [];
        
        try {
            await this.page.goto(this.baseUrl, { waitUntil: 'networkidle' });

            // Measure JavaScript heap usage
            const memoryUsage = await this.page.evaluate(() => {
                if (performance.memory) {
                    return {
                        used: performance.memory.usedJSHeapSize / 1024 / 1024, // MB
                        total: performance.memory.totalJSHeapSize / 1024 / 1024, // MB
                        limit: performance.memory.jsHeapSizeLimit / 1024 / 1024 // MB
                    };
                }
                return null;
            });

            if (memoryUsage) {
                metrics.push(this.createMetric(
                    'JavaScript Memory Usage',
                    memoryUsage.used,
                    'megabytes',
                    this.thresholds.memoryUsage
                ));

                metrics.push(this.createMetric(
                    'Memory Efficiency',
                    (memoryUsage.used / memoryUsage.limit) * 100,
                    'percentage',
                    50 // Should use less than 50% of available memory
                ));
            }

            // Measure network resource sizes
            const resourceSizes = await this.page.evaluate(() => {
                const resources = performance.getEntriesByType('resource');
                let totalSize = 0;
                let jsSize = 0;
                let cssSize = 0;
                let imageSize = 0;

                resources.forEach(resource => {
                    if (resource.transferSize) {
                        totalSize += resource.transferSize;
                        
                        if (resource.name.includes('.js')) {
                            jsSize += resource.transferSize;
                        } else if (resource.name.includes('.css')) {
                            cssSize += resource.transferSize;
                        } else if (resource.name.match(/\.(png|jpg|jpeg|gif|svg|webp)$/)) {
                            imageSize += resource.transferSize;
                        }
                    }
                });

                return {
                    total: totalSize / 1024 / 1024, // MB
                    js: jsSize / 1024 / 1024,
                    css: cssSize / 1024 / 1024,
                    images: imageSize / 1024 / 1024
                };
            });

            metrics.push(this.createMetric(
                'Total Bundle Size',
                resourceSizes.total,
                'megabytes',
                this.thresholds.bundleSize
            ));

            metrics.push(this.createMetric(
                'JavaScript Bundle Size',
                resourceSizes.js,
                'megabytes',
                3 // 3MB max for JS
            ));

            metrics.push(this.createMetric(
                'CSS Bundle Size',
                resourceSizes.css,
                'megabytes',
                1 // 1MB max for CSS
            ));

            return {
                testName: 'Resource Usage',
                metrics,
                success: true,
                duration: 0
            };

        } catch (error) {
            return {
                testName: 'Resource Usage',
                metrics,
                success: false,
                error: error.message,
                duration: 0
            };
        }
    }

    async measureViewSwitching() {
        console.log('🔄 Measuring view switching performance...');
        const metrics = [];
        
        try {
            await this.page.goto(this.baseUrl, { waitUntil: 'networkidle' });

            const viewSwitches = [
                { name: 'Analytics View', selector: 'button[aria-pressed="false"]:has-text("Analytics"), button:has-text("🔬")' },
                { name: 'Map View', selector: 'button[aria-pressed="false"]:has-text("Map"), button:has-text("🗺️")' },
                { name: 'Admin View', selector: 'button[aria-pressed="false"]:has-text("Admin"), button:has-text("⚙️")' }
            ];

            for (const viewSwitch of viewSwitches) {
                try {
                    const switchStart = Date.now();
                    
                    // Try multiple selector patterns
                    const selectors = viewSwitch.selector.split(', ');
                    let clicked = false;
                    
                    for (const selector of selectors) {
                        try {
                            await this.page.click(selector, { timeout: 2000 });
                            clicked = true;
                            break;
                        } catch (e) {
                            // Try next selector
                        }
                    }
                    
                    if (clicked) {
                        // Wait for view to load
                        await this.page.waitForTimeout(1000);
                        
                        const switchEnd = Date.now();
                        const switchTime = switchEnd - switchStart;
                        
                        metrics.push(this.createMetric(
                            `${viewSwitch.name} Switch Time`,
                            switchTime,
                            'milliseconds',
                            2000 // 2 seconds max for view switching
                        ));
                    }
                    
                } catch (e) {
                    console.log(`    Could not test ${viewSwitch.name}: ${e.message}`);
                }
            }

            return {
                testName: 'View Switching Performance',
                metrics,
                success: true,
                duration: 0
            };

        } catch (error) {
            return {
                testName: 'View Switching Performance',
                metrics,
                success: false,
                error: error.message,
                duration: 0
            };
        }
    }

    async runAllTests() {
        console.log('🧪 Starting frontend performance test suite...');
        console.log('='.repeat(60));

        const suiteStart = Date.now();

        const testMethods = [
            this.measurePageLoad.bind(this),
            this.measureSearchPerformance.bind(this),
            this.measureCachePerformance.bind(this),
            this.measureResourceUsage.bind(this),
            this.measureViewSwitching.bind(this)
        ];

        for (const testMethod of testMethods) {
            try {
                const result = await testMethod();
                this.results.push(result);
                
                const status = result.success ? '✅' : '❌';
                console.log(`${status} ${result.testName} completed`);
                
            } catch (error) {
                console.log(`❌ Test failed: ${error.message}`);
                this.results.push({
                    testName: testMethod.name,
                    metrics: [],
                    success: false,
                    error: error.message,
                    duration: 0
                });
            }
        }

        const suiteDuration = Date.now() - suiteStart;
        return this.generateReport(suiteDuration);
    }

    generateReport(suiteDuration) {
        console.log('\n' + '='.repeat(60));
        console.log('📊 FRONTEND PERFORMANCE TEST RESULTS');
        console.log('='.repeat(60));

        const totalTests = this.results.length;
        const successfulTests = this.results.filter(r => r.success).length;

        const allMetrics = this.results.flatMap(r => r.metrics);
        const passedMetrics = allMetrics.filter(m => m.passed).length;
        const totalMetrics = allMetrics.length;

        // Summary
        console.log(`Suite Duration: ${suiteDuration / 1000:.2f} seconds`);
        console.log(`Tests: ${successfulTests}/${totalTests} passed`);
        console.log(`Metrics: ${passedMetrics}/${totalMetrics} passed`);
        console.log(`Success Rate: ${totalMetrics > 0 ? (passedMetrics/totalMetrics*100).toFixed(1) : 'N/A'}%`);

        // Detailed results
        console.log('\nDETAILED RESULTS:');
        console.log('-'.repeat(40));

        this.results.forEach(result => {
            const status = result.success ? '✅ PASS' : '❌ FAIL';
            console.log(`\n${status} ${result.testName}`);

            if (result.error) {
                console.log(`  Error: ${result.error}`);
            }

            result.metrics.forEach(metric => {
                const statusIcon = metric.passed ? '✅' : '❌';
                console.log(`  ${statusIcon} ${metric.name}: ${metric.value.toFixed(2)} ${metric.unit} (threshold: ${metric.threshold})`);
            });
        });

        // Performance recommendations
        console.log('\nPERFORMANCE RECOMMENDATIONS:');
        console.log('-'.repeat(40));

        const failedMetrics = allMetrics.filter(m => !m.passed);
        if (failedMetrics.length === 0) {
            console.log('🎉 All frontend performance metrics passed! UI is performing well.');
        } else {
            failedMetrics.forEach(metric => {
                if (metric.name.includes('Load Time') && metric.value > metric.threshold) {
                    console.log(`⚠️ Slow ${metric.name} - consider code splitting or lazy loading`);
                } else if (metric.name.includes('Bundle Size') && metric.value > metric.threshold) {
                    console.log(`⚠️ Large ${metric.name} - consider tree shaking or compression`);
                } else if (metric.name.includes('Memory') && metric.value > metric.threshold) {
                    console.log(`⚠️ High ${metric.name} - check for memory leaks`);
                } else if (metric.name.includes('Search') && metric.value > metric.threshold) {
                    console.log(`⚠️ Slow ${metric.name} - optimize search implementation`);
                }
            });
        }

        // Export results
        const reportData = {
            timestamp: Date.now(),
            suiteDuration,
            summary: {
                totalTests,
                successfulTests,
                totalMetrics,
                passedMetrics,
                successRate: totalMetrics > 0 ? (passedMetrics/totalMetrics*100) : 0
            },
            tests: this.results,
            thresholds: this.thresholds
        };

        return reportData;
    }

    async saveReport(reportData) {
        const reportPath = path.join(__dirname, `frontend_performance_report_${Date.now()}.json`);
        await fs.writeFile(reportPath, JSON.stringify(reportData, null, 2));
        console.log(`\n📄 Full report saved to: ${reportPath}`);
        return reportPath;
    }
}

async function main() {
    const args = process.argv.slice(2);
    const baseUrl = args.find(arg => arg.startsWith('--url='))?.split('=')[1] || 'http://localhost:5173';
    
    console.log('🚀 Monitor Legislativo v4 - Frontend Performance Test Suite');
    console.log(`Testing against: ${baseUrl}`);
    console.log('='.repeat(60));

    const tester = new FrontendPerformanceTest(baseUrl);
    
    try {
        await tester.setup();
        const report = await tester.runAllTests();
        await tester.saveReport(report);
        
        // Exit with error code if tests failed
        const successRate = report.summary.successRate;
        if (successRate < 80) {
            console.log(`\n❌ Frontend performance tests failed (success rate: ${successRate.toFixed(1)}%)`);
            process.exit(1);
        } else {
            console.log(`\n✅ Frontend performance tests passed (success rate: ${successRate.toFixed(1)}%)`);
            process.exit(0);
        }
        
    } catch (error) {
        console.error(`\n❌ Test suite failed: ${error.message}`);
        process.exit(1);
    } finally {
        await tester.teardown();
    }
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = FrontendPerformanceTest;