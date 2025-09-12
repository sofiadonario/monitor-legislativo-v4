/*
===========================================================================
BRAZILIAN LEGISLATIVE MONITORING SYSTEM - UI COMPONENTS JAVASCRIPT
===========================================================================
Sprint 4A: Comprehensive UI/UX Enhancement
Government-grade interactions with WCAG 2.1 AA compliance
Mobile-first responsive behaviors for Brazilian legal professionals
===========================================================================
*/

(function() {
  'use strict';
  
  // ===========================================================================
  // ACCESSIBILITY UTILITIES
  // ===========================================================================
  
  /**
   * Screen reader announcements
   */
  function announceToScreenReader(message, priority = 'polite') {
    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', priority);
    announcement.setAttribute('aria-atomic', 'true');
    announcement.className = 'sr-status';
    announcement.textContent = message;
    
    document.body.appendChild(announcement);
    
    // Remove after announcement
    setTimeout(() => {
      document.body.removeChild(announcement);
    }, 1000);
  }
  
  /**
   * Focus trap for modals
   */
  function trapFocus(element) {
    const focusableElements = element.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    
    if (focusableElements.length === 0) return;
    
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    
    element.addEventListener('keydown', function(e) {
      if (e.key === 'Tab') {
        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            lastElement.focus();
            e.preventDefault();
          }
        } else {
          if (document.activeElement === lastElement) {
            firstElement.focus();
            e.preventDefault();
          }
        }
      }
    });
    
    // Focus first element
    firstElement.focus();
  }
  
  /**
   * Manage skip links
   */
  function initializeSkipLinks() {
    const skipLinks = document.querySelectorAll('.skip-link');
    
    skipLinks.forEach(link => {
      link.addEventListener('click', function(e) {
        e.preventDefault();
        const targetId = this.getAttribute('href').slice(1);
        const target = document.getElementById(targetId);
        
        if (target) {
          target.setAttribute('tabindex', '-1');
          target.focus();
          target.scrollIntoView();
          
          // Remove tabindex after focus
          target.addEventListener('blur', function() {
            this.removeAttribute('tabindex');
          }, { once: true });
        }
      });
    });
  }
  
  // ===========================================================================
  // RESPONSIVE BEHAVIORS
  // ===========================================================================
  
  /**
   * Mobile navigation toggle
   */
  function initializeMobileNavigation() {
    const toggleButton = document.querySelector('.navbar-toggle');
    const sidebar = document.querySelector('.main-sidebar');
    const body = document.body;
    
    if (toggleButton && sidebar) {
      toggleButton.addEventListener('click', function() {
        const isOpen = body.classList.contains('sidebar-open');
        
        if (isOpen) {
          body.classList.remove('sidebar-open');
          this.setAttribute('aria-expanded', 'false');
          announceToScreenReader('Menu fechado');
        } else {
          body.classList.add('sidebar-open');
          this.setAttribute('aria-expanded', 'true');
          announceToScreenReader('Menu aberto');
          
          // Focus first menu item
          const firstMenuItem = sidebar.querySelector('a[href]');
          if (firstMenuItem) {
            firstMenuItem.focus();
          }
        }
      });
      
      // Close sidebar when clicking outside
      document.addEventListener('click', function(e) {
        if (!sidebar.contains(e.target) && !toggleButton.contains(e.target)) {
          if (body.classList.contains('sidebar-open')) {
            body.classList.remove('sidebar-open');
            toggleButton.setAttribute('aria-expanded', 'false');
          }
        }
      });
      
      // Close sidebar on escape key
      document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && body.classList.contains('sidebar-open')) {
          body.classList.remove('sidebar-open');
          toggleButton.setAttribute('aria-expanded', 'false');
          toggleButton.focus();
        }
      });
    }
  }
  
  /**
   * Responsive table behaviors
   */
  function initializeResponsiveTables() {
    const tables = document.querySelectorAll('.accessible-table');
    
    tables.forEach(table => {
      // Add mobile scroll hint
      if (table.scrollWidth > table.clientWidth) {
        table.setAttribute('aria-label', 
          table.getAttribute('aria-label') + ' - Deslize para ver mais colunas');
      }
      
      // Keyboard navigation for table rows
      const rows = table.querySelectorAll('tbody tr');
      rows.forEach((row, index) => {
        row.setAttribute('tabindex', '0');
        row.setAttribute('role', 'row');
        
        row.addEventListener('keydown', function(e) {
          let targetRow;
          
          switch(e.key) {
            case 'ArrowUp':
              targetRow = rows[index - 1];
              break;
            case 'ArrowDown':
              targetRow = rows[index + 1];
              break;
            case 'Home':
              targetRow = rows[0];
              break;
            case 'End':
              targetRow = rows[rows.length - 1];
              break;
          }
          
          if (targetRow) {
            e.preventDefault();
            targetRow.focus();
          }
        });
      });
    });
  }
  
  // ===========================================================================
  // LOADING STATES AND PERFORMANCE
  // ===========================================================================
  
  /**
   * Enhanced loading indicators
   */
  function showLoading(container, message = 'Carregando...') {
    if (typeof container === 'string') {
      container = document.getElementById(container);
    }
    
    if (!container) return;
    
    const loadingOverlay = document.createElement('div');
    loadingOverlay.className = 'loading-overlay';
    loadingOverlay.setAttribute('role', 'status');
    loadingOverlay.setAttribute('aria-live', 'polite');
    loadingOverlay.setAttribute('aria-label', message);
    
    loadingOverlay.innerHTML = `
      <div class="loading-content">
        <div class="loading-spinner" aria-hidden="true"></div>
        <div class="loading-text">${message}</div>
      </div>
    `;
    
    container.style.position = 'relative';
    container.appendChild(loadingOverlay);
    
    // Announce to screen readers
    announceToScreenReader(message);
    
    return loadingOverlay;
  }
  
  function hideLoading(container) {
    if (typeof container === 'string') {
      container = document.getElementById(container);
    }
    
    if (!container) return;
    
    const loadingOverlay = container.querySelector('.loading-overlay');
    if (loadingOverlay) {
      loadingOverlay.remove();
      announceToScreenReader('Carregamento concluído');
    }
  }
  
  /**
   * Progressive image loading
   */
  function initializeProgressiveImages() {
    const images = document.querySelectorAll('img[data-src]');
    
    const imageObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src;
          img.classList.remove('lazy');
          imageObserver.unobserve(img);
        }
      });
    });
    
    images.forEach(img => imageObserver.observe(img));
  }
  
  // ===========================================================================
  // ERROR HANDLING
  // ===========================================================================
  
  /**
   * Enhanced error display
   */
  function showError(container, message, title = 'Erro', canRetry = false, retryCallback = null) {
    if (typeof container === 'string') {
      container = document.getElementById(container);
    }
    
    if (!container) return;
    
    const errorId = 'error_' + Math.random().toString(36).substr(2, 9);
    const retryId = 'retry_' + Math.random().toString(36).substr(2, 9);
    
    const errorHtml = `
      <div id="${errorId}" class="alert alert-danger" role="alert" aria-live="assertive">
        <h4 class="alert-heading">${title}</h4>
        <p>${message}</p>
        ${canRetry ? `
          <div class="alert-actions mt-3">
            <button id="${retryId}" type="button" class="btn btn-outline-primary btn-sm">
              <i class="fas fa-redo" aria-hidden="true"></i> Tentar Novamente
            </button>
          </div>
        ` : ''}
        <button type="button" class="btn btn-close" data-dismiss="alert" aria-label="Fechar alerta">
          <span aria-hidden="true">×</span>
        </button>
      </div>
    `;
    
    container.innerHTML = errorHtml;
    
    // Add retry functionality
    if (canRetry && retryCallback) {
      const retryButton = document.getElementById(retryId);
      if (retryButton) {
        retryButton.addEventListener('click', function() {
          container.innerHTML = '';
          retryCallback();
        });
      }
    }
    
    // Add dismiss functionality
    const closeButton = container.querySelector('.btn-close');
    if (closeButton) {
      closeButton.addEventListener('click', function() {
        const alert = this.closest('.alert');
        alert.style.transition = 'opacity 0.3s';
        alert.style.opacity = '0';
        setTimeout(() => alert.remove(), 300);
      });
    }
    
    // Announce error to screen readers
    announceToScreenReader(`${title}: ${message}`, 'assertive');
  }
  
  // ===========================================================================
  // FORM ENHANCEMENTS
  // ===========================================================================
  
  /**
   * Enhanced form validation
   */
  function initializeFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
      const inputs = form.querySelectorAll('input, textarea, select');
      
      inputs.forEach(input => {
        // Real-time validation
        input.addEventListener('blur', function() {
          validateField(this);
        });
        
        input.addEventListener('input', function() {
          if (this.classList.contains('is-invalid')) {
            validateField(this);
          }
        });
      });
      
      form.addEventListener('submit', function(e) {
        let isValid = true;
        
        inputs.forEach(input => {
          if (!validateField(input)) {
            isValid = false;
          }
        });
        
        if (!isValid) {
          e.preventDefault();
          
          // Focus first invalid field
          const firstInvalid = form.querySelector('.is-invalid');
          if (firstInvalid) {
            firstInvalid.focus();
            firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
          }
          
          announceToScreenReader('Por favor, corrija os erros no formulário', 'assertive');
        }
      });
    });
  }
  
  function validateField(field) {
    const value = field.value.trim();
    const isRequired = field.hasAttribute('required');
    const type = field.getAttribute('type');
    let isValid = true;
    let errorMessage = '';
    
    // Required validation
    if (isRequired && !value) {
      isValid = false;
      errorMessage = 'Este campo é obrigatório';
    }
    
    // Email validation
    if (type === 'email' && value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
      isValid = false;
      errorMessage = 'Por favor, insira um email válido';
    }
    
    // Update field state
    field.classList.toggle('is-invalid', !isValid);
    field.classList.toggle('is-valid', isValid && value);
    field.setAttribute('aria-invalid', isValid ? 'false' : 'true');
    
    // Update error message
    let errorElement = field.parentNode.querySelector('.form-error');
    if (!isValid) {
      if (!errorElement) {
        errorElement = document.createElement('div');
        errorElement.className = 'form-error';
        errorElement.setAttribute('role', 'alert');
        field.parentNode.appendChild(errorElement);
      }
      errorElement.textContent = errorMessage;
    } else if (errorElement) {
      errorElement.remove();
    }
    
    return isValid;
  }
  
  // ===========================================================================
  // MODAL ENHANCEMENTS
  // ===========================================================================
  
  /**
   * Enhanced modal behavior
   */
  function initializeModals() {
    const modals = document.querySelectorAll('.modal');
    
    modals.forEach(modal => {
      modal.addEventListener('shown.bs.modal', function() {
        trapFocus(this);
        announceToScreenReader(`Modal ${this.querySelector('.modal-title').textContent} aberto`);
      });
      
      modal.addEventListener('hidden.bs.modal', function() {
        // Return focus to trigger element
        const trigger = document.querySelector(`[data-target="#${this.id}"]`);
        if (trigger) {
          trigger.focus();
        }
        announceToScreenReader('Modal fechado');
      });
      
      // Close on escape key
      modal.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
          const bootstrapModal = bootstrap.Modal.getInstance(this);
          if (bootstrapModal) {
            bootstrapModal.hide();
          }
        }
      });
    });
  }
  
  // ===========================================================================
  // PERFORMANCE OPTIMIZATIONS
  // ===========================================================================
  
  /**
   * Debounce function for performance
   */
  function debounce(func, wait, immediate) {
    let timeout;
    return function executedFunction() {
      const context = this;
      const args = arguments;
      const later = function() {
        timeout = null;
        if (!immediate) func.apply(context, args);
      };
      const callNow = immediate && !timeout;
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
      if (callNow) func.apply(context, args);
    };
  }
  
  /**
   * Optimize scroll events
   */
  function initializeScrollOptimization() {
    let ticking = false;
    
    function updateScrollPosition() {
      const scrolled = window.pageYOffset;
      const header = document.querySelector('.main-header');
      
      if (header) {
        if (scrolled > 100) {
          header.classList.add('scrolled');
        } else {
          header.classList.remove('scrolled');
        }
      }
      
      ticking = false;
    }
    
    window.addEventListener('scroll', function() {
      if (!ticking) {
        requestAnimationFrame(updateScrollPosition);
        ticking = true;
      }
    });
  }
  
  // ===========================================================================
  // ACCESSIBILITY TESTING UTILITIES
  // ===========================================================================
  
  /**
   * Basic accessibility audit
   */
  function runAccessibilityAudit() {
    const issues = [];
    
    // Check for images without alt text
    const images = document.querySelectorAll('img:not([alt])');
    if (images.length > 0) {
      issues.push(`${images.length} imagens sem texto alternativo`);
    }
    
    // Check for form inputs without labels
    const inputs = document.querySelectorAll('input:not([aria-label]):not([aria-labelledby])');
    const unlabeledInputs = Array.from(inputs).filter(input => {
      return !input.closest('label') && !document.querySelector(`label[for="${input.id}"]`);
    });
    if (unlabeledInputs.length > 0) {
      issues.push(`${unlabeledInputs.length} campos de formulário sem rótulo`);
    }
    
    // Check for low contrast
    const elements = document.querySelectorAll('*');
    elements.forEach(el => {
      const styles = window.getComputedStyle(el);
      const color = styles.color;
      const backgroundColor = styles.backgroundColor;
      
      // Basic contrast check (simplified)
      if (color && backgroundColor && color !== 'rgba(0, 0, 0, 0)' && backgroundColor !== 'rgba(0, 0, 0, 0)') {
        // This would need a proper contrast ratio calculation
        // For now, just flag potential issues
      }
    });
    
    // Check for keyboard navigation
    const focusableElements = document.querySelectorAll('a, button, input, textarea, select, [tabindex]');
    const unnavigableElements = Array.from(focusableElements).filter(el => {
      return el.tabIndex === -1 && !el.hasAttribute('aria-hidden');
    });
    
    if (unnavigableElements.length > 0) {
      issues.push(`${unnavigableElements.length} elementos focáveis não navegáveis por teclado`);
    }
    
    return issues;
  }
  
  // ===========================================================================
  // INITIALIZATION
  // ===========================================================================
  
  /**
   * Initialize all UI components
   */
  function initializeUIComponents() {
    console.log('🚀 Inicializando componentes UI/UX - Sistema de Monitoramento Legislativo Brasileiro');
    
    // Basic functionality
    initializeSkipLinks();
    initializeMobileNavigation();
    initializeResponsiveTables();
    initializeFormValidation();
    initializeModals();
    
    // Performance optimizations
    initializeProgressiveImages();
    initializeScrollOptimization();
    
    // Accessibility features
    if (window.location.search.includes('debug=accessibility')) {
      const issues = runAccessibilityAudit();
      if (issues.length > 0) {
        console.warn('🔍 Problemas de acessibilidade encontrados:', issues);
      } else {
        console.log('✅ Auditoria básica de acessibilidade: nenhum problema encontrado');
      }
    }
    
    // Global error handler
    window.addEventListener('error', function(e) {
      console.error('❌ Erro JavaScript:', e.error);
      
      // Show user-friendly error for critical failures
      if (e.error && e.error.message.includes('critical')) {
        showError(
          document.body,
          'Ocorreu um erro no sistema. Por favor, recarregue a página.',
          'Erro do Sistema',
          true,
          () => window.location.reload()
        );
      }
    });
    
    console.log('✅ Componentes UI/UX inicializados com sucesso');
  }
  
  // ===========================================================================
  // EXPORT FOR SHINY
  // ===========================================================================
  
  // Make functions available globally for Shiny
  window.UIComponents = {
    showLoading: showLoading,
    hideLoading: hideLoading,
    showError: showError,
    announceToScreenReader: announceToScreenReader,
    runAccessibilityAudit: runAccessibilityAudit
  };
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeUIComponents);
  } else {
    initializeUIComponents();
  }
  
})();