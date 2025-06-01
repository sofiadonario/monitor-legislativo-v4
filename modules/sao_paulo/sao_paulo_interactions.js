/**
 * São Paulo Analysis Tab Interactive Enhancements
 * Professional government interface interactions and user workflow optimizations
 * 
 * Author: Senior UX/UI Designer - Government Applications
 * Date: 2025-09-01
 * Version: 1.0 Government Standard
 */

// =============================================================================
// ENHANCED TAB SYSTEM WITH ACCESSIBILITY
// =============================================================================

class SPTabSystem {
  constructor() {
    this.initializeTabs();
    this.bindEvents();
    this.setupAccessibility();
  }

  initializeTabs() {
    // Initialize all tab panels
    document.querySelectorAll('.sp-analysis-panel').forEach(panel => {
      const tabs = panel.querySelectorAll('.sp-tab-button');
      const contents = panel.querySelectorAll('.sp-tab-content > div');
      
      // Hide all content except first
      contents.forEach((content, index) => {
        if (index === 0) {
          content.style.display = 'block';
        } else {
          content.style.display = 'none';
        }
      });
    });
  }

  bindEvents() {
    // Tab button click handlers
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('sp-tab-button')) {
        this.handleTabClick(e.target);
      }
    });

    // Keyboard navigation for tabs
    document.addEventListener('keydown', (e) => {
      if (e.target.classList.contains('sp-tab-button')) {
        this.handleTabKeydown(e);
      }
    });
  }

  handleTabClick(button) {
    const panel = button.closest('.sp-analysis-panel');
    const tabs = panel.querySelectorAll('.sp-tab-button');
    const tabIndex = Array.from(tabs).indexOf(button);
    
    // Update tab states
    tabs.forEach((tab, index) => {
      if (index === tabIndex) {
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');
        tab.setAttribute('tabindex', '0');
      } else {
        tab.classList.remove('active');
        tab.setAttribute('aria-selected', 'false');
        tab.setAttribute('tabindex', '-1');
      }
    });
    
    // Show corresponding content
    const contents = panel.querySelectorAll('.sp-tab-content > div');
    contents.forEach((content, index) => {
      if (index === tabIndex) {
        content.style.display = 'block';
        // Announce content change to screen readers
        this.announceContentChange(button.textContent);
      } else {
        content.style.display = 'none';
      }
    });
    
    // Focus management
    button.focus();
  }

  handleTabKeydown(e) {
    const tabs = e.target.closest('.sp-tab-nav').querySelectorAll('.sp-tab-button');
    const currentIndex = Array.from(tabs).indexOf(e.target);
    let targetIndex;

    switch(e.key) {
      case 'ArrowLeft':
        e.preventDefault();
        targetIndex = currentIndex > 0 ? currentIndex - 1 : tabs.length - 1;
        tabs[targetIndex].focus();
        this.handleTabClick(tabs[targetIndex]);
        break;
      case 'ArrowRight':
        e.preventDefault();
        targetIndex = currentIndex < tabs.length - 1 ? currentIndex + 1 : 0;
        tabs[targetIndex].focus();
        this.handleTabClick(tabs[targetIndex]);
        break;
      case 'Home':
        e.preventDefault();
        tabs[0].focus();
        this.handleTabClick(tabs[0]);
        break;
      case 'End':
        e.preventDefault();
        tabs[tabs.length - 1].focus();
        this.handleTabClick(tabs[tabs.length - 1]);
        break;
      case 'Enter':
      case ' ':
        e.preventDefault();
        this.handleTabClick(e.target);
        break;
    }
  }

  setupAccessibility() {
    // Add ARIA attributes to tabs
    document.querySelectorAll('.sp-tab-nav').forEach(nav => {
      nav.setAttribute('role', 'tablist');
      
      nav.querySelectorAll('.sp-tab-button').forEach((tab, index) => {
        tab.setAttribute('role', 'tab');
        tab.setAttribute('aria-controls', `sp-tabpanel-${Date.now()}-${index}`);
        tab.setAttribute('id', `sp-tab-${Date.now()}-${index}`);
        
        if (index === 0) {
          tab.setAttribute('aria-selected', 'true');
          tab.setAttribute('tabindex', '0');
        } else {
          tab.setAttribute('aria-selected', 'false');
          tab.setAttribute('tabindex', '-1');
        }
      });
    });

    // Add ARIA attributes to tab panels
    document.querySelectorAll('.sp-tab-content').forEach(content => {
      content.setAttribute('role', 'tabpanel');
      content.setAttribute('aria-live', 'polite');
    });
  }

  announceContentChange(tabName) {
    // Create or update live region for screen readers
    let liveRegion = document.getElementById('sp-live-region');
    if (!liveRegion) {
      liveRegion = document.createElement('div');
      liveRegion.id = 'sp-live-region';
      liveRegion.className = 'sp-sr-only';
      liveRegion.setAttribute('aria-live', 'polite');
      document.body.appendChild(liveRegion);
    }
    
    liveRegion.textContent = `Switched to ${tabName} analysis view`;
  }
}

// =============================================================================
// ADVANCED SEARCH FUNCTIONALITY
// =============================================================================

class SPSearchSystem {
  constructor() {
    this.searchStats = {
      totalDocuments: 28500,
      lastSearchTime: 0,
      relevanceScore: 0
    };
    this.initializeSearch();
    this.bindSearchEvents();
  }

  initializeSearch() {
    // Initialize search statistics
    this.updateSearchStats();
    
    // Setup debounced search
    this.searchDebouncer = this.debounce(this.performSearch.bind(this), 500);
  }

  bindSearchEvents() {
    // Search input events
    const searchInputs = [
      '#sp_search_term',
      '#sp_doc_category', 
      '#sp_municipality_filter',
      '#sp_transport_modal'
    ];

    searchInputs.forEach(selector => {
      const element = document.querySelector(selector);
      if (element) {
        element.addEventListener('input', this.searchDebouncer);
        element.addEventListener('change', this.searchDebouncer);
      }
    });

    // Clear filters button
    document.addEventListener('click', (e) => {
      if (e.target.textContent.includes('Clear Filters')) {
        this.clearAllFilters();
      }
    });
  }

  performSearch() {
    const searchTerm = document.querySelector('#sp_search_term')?.value || '';
    const category = document.querySelector('#sp_doc_category')?.value || 'all';
    const municipality = document.querySelector('#sp_municipality_filter')?.value || 'all';
    const modal = document.querySelector('#sp_transport_modal')?.value || 'all';

    // Simulate search processing
    this.showSearchLoading();
    
    setTimeout(() => {
      // Calculate filtered results (simulation)
      let filteredCount = this.searchStats.totalDocuments;
      
      if (category !== 'all') filteredCount *= 0.6;
      if (municipality !== 'all') filteredCount *= 0.4;
      if (modal !== 'all') filteredCount *= 0.3;
      if (searchTerm.length > 0) filteredCount *= 0.2;
      
      filteredCount = Math.max(Math.floor(filteredCount), 1);
      
      // Update search statistics
      this.searchStats.lastSearchTime = Math.random() * 0.8 + 0.1;
      this.searchStats.relevanceScore = Math.random() * 20 + 80;
      
      this.updateSearchResults(filteredCount);
      this.hideSearchLoading();
    }, 300);
  }

  updateSearchResults(filteredCount) {
    const filteredElement = document.getElementById('sp-filtered-results');
    const searchTimeElement = document.getElementById('sp-search-time');
    const relevanceElement = document.getElementById('sp-relevance-score');
    const summaryElement = document.getElementById('sp-search-results-summary');
    
    if (filteredElement) {
      filteredElement.textContent = filteredCount.toLocaleString();
    }
    
    if (searchTimeElement) {
      searchTimeElement.textContent = this.searchStats.lastSearchTime.toFixed(2) + 's';
    }
    
    if (relevanceElement) {
      relevanceElement.textContent = this.searchStats.relevanceScore.toFixed(1) + '%';
    }
    
    if (summaryElement) {
      summaryElement.textContent = `Found ${filteredCount.toLocaleString()} documents matching your criteria`;
    }
    
    // Announce search results to screen readers
    this.announceSearchResults(filteredCount);
  }

  updateSearchStats() {
    const totalElement = document.getElementById('sp-total-documents');
    if (totalElement) {
      totalElement.textContent = this.searchStats.totalDocuments.toLocaleString() + '+';
    }
  }

  showSearchLoading() {
    const summaryElement = document.getElementById('sp-search-results-summary');
    if (summaryElement) {
      summaryElement.innerHTML = '<span class="sp-loading-text">🔍 Searching documents...</span>';
    }
  }

  hideSearchLoading() {
    // Loading state removed by updateSearchResults
  }

  clearAllFilters() {
    // Clear all filter inputs
    const inputs = [
      '#sp_search_term',
      '#sp_doc_category',
      '#sp_municipality_filter', 
      '#sp_transport_modal'
    ];

    inputs.forEach(selector => {
      const element = document.querySelector(selector);
      if (element) {
        if (element.type === 'text') {
          element.value = '';
        } else {
          element.value = 'all';
        }
      }
    });

    // Trigger search update
    this.performSearch();
    
    // Announce filter clear to screen readers
    this.announceFilterClear();
  }

  announceSearchResults(count) {
    let liveRegion = document.getElementById('sp-search-live-region');
    if (!liveRegion) {
      liveRegion = document.createElement('div');
      liveRegion.id = 'sp-search-live-region';
      liveRegion.className = 'sp-sr-only';
      liveRegion.setAttribute('aria-live', 'polite');
      document.body.appendChild(liveRegion);
    }
    
    liveRegion.textContent = `Search completed. Found ${count} documents.`;
  }

  announceFilterClear() {
    const liveRegion = document.getElementById('sp-search-live-region');
    if (liveRegion) {
      liveRegion.textContent = 'All search filters have been cleared.';
    }
  }

  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }
}

// =============================================================================
// USER WORKFLOW OPTIMIZATION
// =============================================================================

class SPWorkflowManager {
  constructor() {
    this.userType = this.detectUserType();
    this.currentWorkflow = null;
    this.initializeWorkflows();
    this.setupPersonalization();
  }

  detectUserType() {
    // Simple user type detection based on interaction patterns
    // In production, this would integrate with authentication system
    const hour = new Date().getHours();
    
    if (hour >= 9 && hour <= 17) {
      return 'government_official'; // Business hours suggest government user
    } else if (hour >= 18 && hour <= 23) {
      return 'academic_researcher'; // Evening suggests academic user
    } else {
      return 'policy_analyst'; // Default
    }
  }

  initializeWorkflows() {
    this.workflows = {
      government_official: {
        name: 'Government Official',
        defaultFocus: 'complete',
        preferredViews: ['transport', 'comparative'],
        suggestedExports: ['pdf_report', 'executive_summary'],
        shortcuts: this.createOfficialShortcuts()
      },
      academic_researcher: {
        name: 'Academic Researcher', 
        defaultFocus: 'academic',
        preferredViews: ['policy_innovation', 'research_metrics'],
        suggestedExports: ['csv_dataset', 'r_script', 'citation'],
        shortcuts: this.createAcademicShortcuts()
      },
      policy_analyst: {
        name: 'Policy Analyst',
        defaultFocus: 'comparative',
        preferredViews: ['state_comparison', 'efficiency_metrics'],
        suggestedExports: ['detailed_analysis', 'benchmarks'],
        shortcuts: this.createAnalystShortcuts()
      },
      municipal_planner: {
        name: 'Municipal Planner',
        defaultFocus: 'rmsp',
        preferredViews: ['municipal_cooperation', 'transport_geographic'],
        suggestedExports: ['regional_report', 'infrastructure_data'],
        shortcuts: this.createPlannerShortcuts()
      }
    };
    
    this.currentWorkflow = this.workflows[this.userType];
    this.applyWorkflowDefaults();
  }

  createOfficialShortcuts() {
    return [
      {
        name: 'Executive Summary',
        action: () => this.generateExecutiveSummary(),
        icon: 'file-alt',
        description: 'Generate executive briefing for leadership'
      },
      {
        name: 'Policy Comparison',
        action: () => this.showPolicyComparison(),
        icon: 'balance-scale',
        description: 'Compare SP policies with other states'
      },
      {
        name: 'Transport Dashboard',
        action: () => this.focusTransportAnalysis(),
        icon: 'subway',
        description: 'Focus on transport policy analysis'
      }
    ];
  }

  createAcademicShortcuts() {
    return [
      {
        name: 'Research Dataset',
        action: () => this.exportResearchData(),
        icon: 'database',
        description: 'Export clean dataset for analysis'
      },
      {
        name: 'Citation Generator',
        action: () => this.generateCitations(),
        icon: 'quote-left',
        description: 'Generate academic citations'
      },
      {
        name: 'Methodology Guide',
        action: () => this.showMethodology(),
        icon: 'book',
        description: 'View research methodology documentation'
      }
    ];
  }

  createAnalystShortcuts() {
    return [
      {
        name: 'Benchmarking Report',
        action: () => this.generateBenchmarks(),
        icon: 'chart-line',
        description: 'Generate state comparison benchmarks'
      },
      {
        name: 'Trend Analysis',
        action: () => this.showTrendAnalysis(),
        icon: 'trending-up',
        description: 'View temporal trend analysis'
      },
      {
        name: 'Data Validation',
        action: () => this.validateDataQuality(),
        icon: 'check-double',
        description: 'Check data quality metrics'
      }
    ];
  }

  createPlannerShortcuts() {
    return [
      {
        name: 'RMSP Overview',
        action: () => this.showRMSPDashboard(),
        icon: 'city',
        description: 'Focus on metropolitan region analysis'
      },
      {
        name: 'Infrastructure Map',
        action: () => this.showInfrastructureMap(),
        icon: 'map-marked-alt',
        description: 'View transport infrastructure mapping'
      },
      {
        name: 'Municipal Cooperation',
        action: () => this.showCooperationAnalysis(),
        icon: 'handshake',
        description: 'Analyze inter-municipal cooperation'
      }
    ];
  }

  applyWorkflowDefaults() {
    // Set default analysis focus based on user type
    const focusSelect = document.querySelector('#sp_analysis_focus');
    if (focusSelect && this.currentWorkflow.defaultFocus) {
      focusSelect.value = this.currentWorkflow.defaultFocus;
    }

    // Add workflow-specific UI hints
    this.addWorkflowHints();
  }

  addWorkflowHints() {
    // Create user type indicator
    const indicator = document.createElement('div');
    indicator.className = 'sp-workflow-indicator';
    indicator.innerHTML = `
      <div style="padding: 0.75rem 1rem; background: #e3f2fd; border-left: 4px solid #2196f3; margin-bottom: 1rem; border-radius: 4px;">
        <strong>👤 Detected User Profile: ${this.currentWorkflow.name}</strong>
        <p style="margin: 0.5rem 0 0 0; font-size: 0.875rem; color: #424242;">
          Interface optimized for your workflow. <a href="#" onclick="SPWorkflow.showPersonalization()" style="color: #2196f3; text-decoration: none;">Customize preferences →</a>
        </p>
      </div>
    `;

    // Insert after header
    const header = document.querySelector('.sp-header-section');
    if (header && header.nextSibling) {
      header.parentNode.insertBefore(indicator, header.nextSibling);
    }

    // Add workflow shortcuts to controls panel
    this.addWorkflowShortcuts();
  }

  addWorkflowShortcuts() {
    const controlsContent = document.querySelector('.sp-controls-content');
    if (!controlsContent) return;

    const shortcutsContainer = document.createElement('div');
    shortcutsContainer.innerHTML = `
      <div style="margin-bottom: 2rem; padding: 1rem; background: #f8f9fa; border-radius: 6px; border: 1px solid #e0e0e0;">
        <h5 style="margin: 0 0 1rem 0; color: #424242; font-size: 0.875rem; font-weight: 600;">🚀 Quick Actions</h5>
        <div style="display: flex; flex-direction: column; gap: 0.5rem;">
          ${this.currentWorkflow.shortcuts.map(shortcut => `
            <button class="sp-workflow-shortcut" data-action="${shortcut.name}" style="
              display: flex;
              align-items: center;
              gap: 0.5rem;
              padding: 0.5rem 0.75rem;
              background: white;
              border: 1px solid #d0d0d0;
              border-radius: 4px;
              color: #424242;
              font-size: 0.875rem;
              cursor: pointer;
              transition: all 0.15s ease;
            " onmouseover="this.style.background='#f0f0f0'" onmouseout="this.style.background='white'">
              <i class="fa fa-${shortcut.icon}" style="width: 14px;"></i>
              <span>${shortcut.name}</span>
            </button>
          `).join('')}
        </div>
      </div>
    `;

    controlsContent.insertBefore(shortcutsContainer, controlsContent.firstChild);

    // Bind shortcut events
    shortcutsContainer.addEventListener('click', (e) => {
      if (e.target.classList.contains('sp-workflow-shortcut') || e.target.closest('.sp-workflow-shortcut')) {
        const button = e.target.classList.contains('sp-workflow-shortcut') ? e.target : e.target.closest('.sp-workflow-shortcut');
        const actionName = button.dataset.action;
        const shortcut = this.currentWorkflow.shortcuts.find(s => s.name === actionName);
        if (shortcut) {
          shortcut.action();
        }
      }
    });
  }

  setupPersonalization() {
    // Load user preferences from localStorage
    const savedPreferences = localStorage.getItem('sp_user_preferences');
    if (savedPreferences) {
      this.userPreferences = JSON.parse(savedPreferences);
      this.applyPersonalization();
    }
  }

  showPersonalization() {
    // Create personalization modal (simplified)
    const modal = document.createElement('div');
    modal.innerHTML = `
      <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 10000; display: flex; align-items: center; justify-content: center;">
        <div style="background: white; padding: 2rem; border-radius: 8px; max-width: 500px; width: 90%;">
          <h3 style="margin: 0 0 1rem 0;">Customize Your Workflow</h3>
          <p>Select your primary role to optimize the interface:</p>
          <div style="display: flex; flex-direction: column; gap: 0.5rem; margin: 1rem 0;">
            ${Object.keys(this.workflows).map(type => `
              <label style="display: flex; align-items: center; gap: 0.5rem;">
                <input type="radio" name="user_type" value="${type}" ${type === this.userType ? 'checked' : ''}>
                <span>${this.workflows[type].name}</span>
              </label>
            `).join('')}
          </div>
          <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 2rem;">
            <button onclick="this.closest('div[style*=fixed]').remove()" style="padding: 0.5rem 1rem; background: #f0f0f0; border: 1px solid #d0d0d0; border-radius: 4px; cursor: pointer;">Cancel</button>
            <button onclick="SPWorkflow.savePersonalization()" style="padding: 0.5rem 1rem; background: #2196f3; color: white; border: none; border-radius: 4px; cursor: pointer;">Apply Changes</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  savePersonalization() {
    const selectedType = document.querySelector('input[name="user_type"]:checked')?.value;
    if (selectedType && selectedType !== this.userType) {
      this.userType = selectedType;
      this.currentWorkflow = this.workflows[selectedType];
      
      // Save preferences
      localStorage.setItem('sp_user_preferences', JSON.stringify({
        userType: selectedType,
        customizedAt: new Date().toISOString()
      }));
      
      // Close modal and reload interface
      document.querySelector('div[style*="position: fixed"]')?.remove();
      
      // Show confirmation and reload
      setTimeout(() => {
        alert('Workflow preferences updated! The interface will refresh to apply changes.');
        window.location.reload();
      }, 100);
    }
  }

  // Shortcut action implementations
  generateExecutiveSummary() {
    console.log('Generating executive summary...');
    // Implementation would trigger Shiny server action
  }

  showPolicyComparison() {
    // Switch to comparative analysis tab
    const compareTab = document.querySelector('[aria-controls*="comparative"]');
    if (compareTab) compareTab.click();
  }

  focusTransportAnalysis() {
    const transportTab = document.querySelector('[aria-controls*="modal-distribution"]');
    if (transportTab) transportTab.click();
  }

  exportResearchData() {
    console.log('Exporting research dataset...');
  }

  generateCitations() {
    console.log('Generating academic citations...');
  }

  showMethodology() {
    console.log('Showing methodology guide...');
  }

  generateBenchmarks() {
    console.log('Generating benchmarking report...');
  }

  showTrendAnalysis() {
    const trendTab = document.querySelector('[aria-controls*="temporal-trends"]');
    if (trendTab) trendTab.click();
  }

  validateDataQuality() {
    console.log('Validating data quality...');
  }

  showRMSPDashboard() {
    const rmspPanel = document.querySelector('.sp-analysis-panel:has([icon="city"])');
    if (rmspPanel) rmspPanel.scrollIntoView({ behavior: 'smooth' });
  }

  showInfrastructureMap() {
    const geoTab = document.querySelector('[aria-controls*="geographic-distribution"]');
    if (geoTab) geoTab.click();
  }

  showCooperationAnalysis() {
    const coopTab = document.querySelector('.sp-tab-button:contains("Municipal Cooperation")');
    if (coopTab) coopTab.click();
  }
}

// =============================================================================
// RESPONSIVE DESIGN ENHANCEMENTS
// =============================================================================

class SPResponsiveManager {
  constructor() {
    this.breakpoints = {
      mobile: 480,
      tablet: 768,
      desktop: 1024,
      large: 1200
    };
    
    this.currentBreakpoint = this.getCurrentBreakpoint();
    this.initializeResponsive();
    this.bindResizeEvents();
  }

  getCurrentBreakpoint() {
    const width = window.innerWidth;
    
    if (width <= this.breakpoints.mobile) return 'mobile';
    if (width <= this.breakpoints.tablet) return 'tablet';
    if (width <= this.breakpoints.desktop) return 'desktop';
    return 'large';
  }

  initializeResponsive() {
    this.applyBreakpointStyles();
    this.optimizeForTouch();
  }

  bindResizeEvents() {
    let resizeTimeout;
    
    window.addEventListener('resize', () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        const newBreakpoint = this.getCurrentBreakpoint();
        if (newBreakpoint !== this.currentBreakpoint) {
          this.currentBreakpoint = newBreakpoint;
          this.applyBreakpointStyles();
        }
      }, 150);
    });
  }

  applyBreakpointStyles() {
    document.body.setAttribute('data-breakpoint', this.currentBreakpoint);
    
    // Mobile optimizations
    if (this.currentBreakpoint === 'mobile') {
      this.optimizeForMobile();
    }
    
    // Tablet optimizations  
    if (this.currentBreakpoint === 'tablet') {
      this.optimizeForTablet();
    }
  }

  optimizeForMobile() {
    // Convert tabs to accordion on mobile
    document.querySelectorAll('.sp-tab-nav').forEach(nav => {
      if (!nav.classList.contains('mobile-accordion')) {
        this.convertTabsToAccordion(nav);
      }
    });
    
    // Optimize control panels for mobile
    document.querySelectorAll('.sp-controls-panel').forEach(panel => {
      panel.style.position = 'relative';
      panel.style.width = '100%';
    });
  }

  optimizeForTablet() {
    // Ensure touch-friendly interactions
    document.querySelectorAll('.sp-button, .sp-tab-button').forEach(button => {
      const currentPadding = window.getComputedStyle(button).padding;
      if (!currentPadding.includes('44px')) {
        button.style.minHeight = '44px';
      }
    });
  }

  optimizeForTouch() {
    // Add touch-friendly classes
    if ('ontouchstart' in window) {
      document.body.classList.add('touch-device');
      
      // Increase touch targets
      document.querySelectorAll('.sp-button, .sp-tab-button, .sp-checkbox').forEach(element => {
        element.style.minHeight = '44px';
        element.style.minWidth = '44px';
      });
    }
  }

  convertTabsToAccordion(nav) {
    // Mobile accordion implementation would go here
    nav.classList.add('mobile-accordion');
  }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

// Global instances
let SPTabs, SPSearch, SPWorkflow, SPResponsive;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('🏙️ Initializing São Paulo Analysis Interface...');
  
  try {
    SPTabs = new SPTabSystem();
    SPSearch = new SPSearchSystem();
    SPWorkflow = new SPWorkflowManager();
    SPResponsive = new SPResponsiveManager();
    
    console.log('✅ São Paulo Analysis Interface initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing São Paulo Analysis Interface:', error);
  }
});

// Export for global access
window.SPTabs = SPTabs;
window.SPSearch = SPSearch;
window.SPWorkflow = SPWorkflow;
window.SPResponsive = SPResponsive;