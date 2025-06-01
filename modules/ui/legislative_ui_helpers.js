// LEGISLATIVE UI HELPERS
// ======================
// JavaScript helpers for Legislative Analytics UI components

// Custom message handler for updating div content
Shiny.addCustomMessageHandler("updateDiv", function(message) {
  var element = document.getElementById(message.id);
  if (element) {
    element.innerHTML = message.content;
  }
});

// Loading spinner styles
document.addEventListener('DOMContentLoaded', function() {
  // Add CSS for loading spinner
  var style = document.createElement('style');
  style.textContent = `
    .loading-spinner {
      text-align: center;
      padding: 20px;
      color: #3c8dbc;
    }
    
    .loading-spinner i {
      font-size: 18px;
      margin-right: 8px;
    }
    
    .module-status {
      font-family: monospace;
      font-size: 14px;
      padding: 10px;
      background-color: #f8f9fa;
      border-radius: 4px;
    }
    
    .module-status span {
      margin-right: 15px;
      padding: 4px 8px;
      border-radius: 3px;
    }
    
    .text-success {
      color: #28a745 !important;
      background-color: #d4edda;
    }
    
    .text-danger {
      color: #dc3545 !important;
      background-color: #f8d7da;
    }
    
    .alert-danger {
      color: #721c24;
      background-color: #f8d7da;
      border-color: #f5c6cb;
      padding: 12px;
      margin-bottom: 20px;
      border: 1px solid transparent;
      border-radius: 4px;
    }
    
    .legislative-metric {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 15px;
      border-radius: 8px;
      margin-bottom: 15px;
    }
    
    .legislative-metric h5 {
      margin-top: 0;
      color: #fff;
    }
    
    .analysis-progress {
      width: 100%;
      background-color: #e9ecef;
      border-radius: 4px;
      overflow: hidden;
    }
    
    .analysis-progress-bar {
      height: 4px;
      background: linear-gradient(90deg, #28a745, #20c997, #17a2b8);
      animation: progressAnimation 2s infinite;
    }
    
    @keyframes progressAnimation {
      0% { width: 0%; }
      50% { width: 70%; }
      100% { width: 100%; }
    }
  `;
  document.head.appendChild(style);
});

// Function to show analysis progress
function showAnalysisProgress(elementId) {
  var element = document.getElementById(elementId);
  if (element) {
    element.innerHTML = `
      <div class="analysis-progress">
        <div class="analysis-progress-bar"></div>
      </div>
      <p style="margin-top: 10px; text-align: center;">
        <i class="fa fa-cog fa-spin"></i> Processing legislative data...
      </p>
    `;
  }
}

// Function to update metric cards with animation
function updateMetricCard(elementId, value, subtitle, icon, color) {
  var element = document.getElementById(elementId);
  if (element) {
    element.style.transition = 'all 0.3s ease';
    element.style.transform = 'scale(1.05)';
    
    setTimeout(function() {
      element.innerHTML = `
        <div class="legislative-metric" style="background-color: ${color};">
          <div style="display: flex; align-items: center; justify-content: space-between;">
            <div>
              <h3 style="margin: 0; font-size: 2.2em;">${value}</h3>
              <p style="margin: 5px 0 0 0; opacity: 0.9;">${subtitle}</p>
            </div>
            <i class="fa ${icon}" style="font-size: 2.5em; opacity: 0.7;"></i>
          </div>
        </div>
      `;
      
      element.style.transform = 'scale(1)';
    }, 150);
  }
}

// Function to create interactive charts (placeholder for future enhancements)
function createLegislativeChart(elementId, data, chartType) {
  var element = document.getElementById(elementId);
  if (element && typeof Plotly !== 'undefined') {
    // Placeholder for Plotly integration
    console.log('Creating chart in element:', elementId, 'with data:', data);
  }
}

// Function to handle responsive design updates
function updateResponsiveLayout() {
  var tabs = document.querySelectorAll('.nav-tabs');
  tabs.forEach(function(tab) {
    if (window.innerWidth < 768) {
      tab.classList.add('nav-stacked');
    } else {
      tab.classList.remove('nav-stacked');
    }
  });
}

// Responsive layout updates on window resize
window.addEventListener('resize', updateResponsiveLayout);

// Initialize responsive layout
document.addEventListener('DOMContentLoaded', updateResponsiveLayout);

// Function to show success notification with custom styling
function showSuccessNotification(message) {
  if (typeof Shiny !== 'undefined') {
    Shiny.onInputChange('legislative_notification', {
      message: message,
      type: 'success',
      timestamp: new Date().getTime()
    });
  }
}

// Function to show error notification with custom styling
function showErrorNotification(message) {
  if (typeof Shiny !== 'undefined') {
    Shiny.onInputChange('legislative_notification', {
      message: message,
      type: 'error',
      timestamp: new Date().getTime()
    });
  }
}

// Export functions for use in other scripts
window.LegislativeUI = {
  showAnalysisProgress: showAnalysisProgress,
  updateMetricCard: updateMetricCard,
  createLegislativeChart: createLegislativeChart,
  showSuccessNotification: showSuccessNotification,
  showErrorNotification: showErrorNotification
};