/* ===================================================
   Monitor Legislativo v4 - Accessibility Framework
   WCAG 2.1 AA Compliant JavaScript Enhancements
   Brazilian Government Standards (eMAG) Compatible
   =================================================== */

(function(window, document) {
  'use strict';

  // Accessibility Manager
  const AccessibilityManager = {
    
    // Configuration
    config: {
      enableVoiceAnnouncements: true,
      enableKeyboardShortcuts: true,
      enableFocusTrap: true,
      enableHighContrast: false,
      screenReaderMode: false,
      language: 'pt-BR'
    },

    // ARIA Live Regions for Screen Reader Announcements
    liveRegions: {
      polite: null,
      assertive: null
    },

    // Focus Management
    focusStack: [],
    currentModal: null,

    // Keyboard Navigation State
    keyboardNavigation: {
      active: false,
      currentIndex: 0,
      focusableElements: []
    },

    /**
     * Initialize Accessibility Framework
     */
    init: function() {
      this.createLiveRegions();
      this.initKeyboardNavigation();
      this.initFocusManagement();
      this.initARIAEnhancements();
      this.initVoiceAnnouncements();
      this.initHighContrastMode();
      this.initResizeHandler();
      this.initErrorHandling();
      
      console.log('✅ Accessibility Framework initialized');
    },

    /**
     * Create ARIA Live Regions for Screen Reader Announcements
     */
    createLiveRegions: function() {
      // Polite announcements (don't interrupt)
      this.liveRegions.polite = document.createElement('div');
      this.liveRegions.polite.setAttribute('aria-live', 'polite');
      this.liveRegions.polite.setAttribute('aria-atomic', 'true');
      this.liveRegions.polite.className = 'sr-only';
      this.liveRegions.polite.id = 'aria-live-polite';

      // Assertive announcements (interrupt screen reader)
      this.liveRegions.assertive = document.createElement('div');
      this.liveRegions.assertive.setAttribute('aria-live', 'assertive');
      this.liveRegions.assertive.setAttribute('aria-atomic', 'true');
      this.liveRegions.assertive.className = 'sr-only';
      this.liveRegions.assertive.id = 'aria-live-assertive';

      document.body.appendChild(this.liveRegions.polite);
      document.body.appendChild(this.liveRegions.assertive);
    },

    /**
     * Announce Message to Screen Readers
     * @param {string} message - Message to announce
     * @param {string} priority - 'polite' or 'assertive'
     */
    announce: function(message, priority = 'polite') {
      if (!this.config.enableVoiceAnnouncements) return;
      
      const region = this.liveRegions[priority];
      if (region) {
        // Clear and set new message
        region.textContent = '';
        setTimeout(() => {
          region.textContent = message;
        }, 100);
      }
    },

    /**
     * Initialize Keyboard Navigation
     */
    initKeyboardNavigation: function() {
      const self = this;

      // Global keyboard event handler
      document.addEventListener('keydown', function(e) {
        self.handleGlobalKeyboard(e);
      });

      // Focus indicators
      document.addEventListener('keydown', function(e) {
        if (e.key === 'Tab') {
          document.body.classList.add('keyboard-navigation');
        }
      });

      document.addEventListener('mousedown', function() {
        document.body.classList.remove('keyboard-navigation');
      });

      // Skip links
      this.createSkipLinks();
    },

    /**
     * Create Skip Navigation Links
     */
    createSkipLinks: function() {
      const skipContainer = document.createElement('div');
      skipContainer.className = 'skip-links';
      skipContainer.innerHTML = `
        <a href="#main-content" class="skip-link">Pular para o conteúdo principal</a>
        <a href="#main-navigation" class="skip-link">Pular para a navegação</a>
        <a href="#search" class="skip-link">Pular para a busca</a>
      `;
      
      document.body.insertBefore(skipContainer, document.body.firstChild);
    },

    /**
     * Handle Global Keyboard Shortcuts
     * @param {KeyboardEvent} e - Keyboard event
     */
    handleGlobalKeyboard: function(e) {
      // Alt + 1: Main content
      if (e.altKey && e.key === '1') {
        e.preventDefault();
        this.focusElement('#main-content');
        this.announce('Navegando para o conteúdo principal');
      }
      
      // Alt + 2: Navigation
      if (e.altKey && e.key === '2') {
        e.preventDefault();
        this.focusElement('#main-navigation');
        this.announce('Navegando para o menu principal');
      }
      
      // Alt + 3: Search
      if (e.altKey && e.key === '3') {
        e.preventDefault();
        this.focusElement('#search_query');
        this.announce('Navegando para o campo de busca');
      }
      
      // Escape key: Close modals/overlays
      if (e.key === 'Escape') {
        this.handleEscapeKey(e);
      }
      
      // F6: Navigate between page regions
      if (e.key === 'F6') {
        e.preventDefault();
        this.navigatePageRegions(e.shiftKey);
      }

      // Ctrl/Cmd + K: Global search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        this.focusElement('#global_search');
        this.announce('Campo de busca global ativado');
      }
    },

    /**
     * Navigate Between Page Regions
     * @param {boolean} reverse - Navigate in reverse order
     */
    navigatePageRegions: function(reverse = false) {
      const regions = [
        '#main-navigation',
        '#main-content', 
        '#sidebar',
        '#footer'
      ];
      
      const currentFocus = document.activeElement;
      let currentIndex = -1;
      
      // Find current region
      regions.forEach((region, index) => {
        const element = document.querySelector(region);
        if (element && element.contains(currentFocus)) {
          currentIndex = index;
        }
      });
      
      // Navigate to next region
      const nextIndex = reverse 
        ? (currentIndex - 1 + regions.length) % regions.length
        : (currentIndex + 1) % regions.length;
        
      this.focusElement(regions[nextIndex]);
      
      const regionNames = [
        'navegação principal',
        'conteúdo principal',
        'barra lateral',
        'rodapé'
      ];
      
      this.announce(`Navegando para ${regionNames[nextIndex]}`);
    },

    /**
     * Handle Escape Key Press
     * @param {KeyboardEvent} e - Keyboard event
     */
    handleEscapeKey: function(e) {
      // Close current modal
      if (this.currentModal) {
        this.closeModal(this.currentModal);
        return;
      }
      
      // Close dropdowns
      const openDropdowns = document.querySelectorAll('.dropdown.show, .dropdown-menu.show');
      if (openDropdowns.length > 0) {
        openDropdowns.forEach(dropdown => {
          dropdown.classList.remove('show');
        });
        this.announce('Menu suspenso fechado');
        return;
      }
      
      // Clear search if focused
      const searchInput = document.querySelector('#search_query:focus');
      if (searchInput && searchInput.value) {
        searchInput.value = '';
        this.announce('Campo de busca limpo');
        return;
      }
    },

    /**
     * Focus Element with Error Handling
     * @param {string} selector - CSS selector
     */
    focusElement: function(selector) {
      const element = document.querySelector(selector);
      if (element) {
        // Make element focusable if needed
        if (!element.hasAttribute('tabindex') && 
            !['INPUT', 'BUTTON', 'SELECT', 'TEXTAREA', 'A'].includes(element.tagName)) {
          element.setAttribute('tabindex', '-1');
        }
        
        element.focus();
        return true;
      }
      return false;
    },

    /**
     * Initialize Focus Management
     */
    initFocusManagement: function() {
      const self = this;
      
      // Modal focus trap
      document.addEventListener('focusin', function(e) {
        if (self.currentModal && !self.currentModal.contains(e.target)) {
          e.preventDefault();
          self.focusFirstElementInModal(self.currentModal);
        }
      });

      // Track focus for accessibility announcements
      document.addEventListener('focus', function(e) {
        const element = e.target;
        const role = element.getAttribute('role');
        const ariaLabel = element.getAttribute('aria-label');
        const title = element.getAttribute('title');
        
        // Announce important focus changes
        if (role || ariaLabel || title) {
          const announcement = ariaLabel || title || `${role} focado`;
          self.announce(announcement, 'polite');
        }
      }, true);
    },

    /**
     * Open Modal with Focus Management
     * @param {Element} modal - Modal element
     */
    openModal: function(modal) {
      // Save current focus
      this.focusStack.push(document.activeElement);
      
      // Set current modal
      this.currentModal = modal;
      
      // Show modal
      modal.style.display = 'block';
      modal.setAttribute('aria-hidden', 'false');
      
      // Focus first focusable element
      this.focusFirstElementInModal(modal);
      
      // Announce modal opening
      const modalTitle = modal.querySelector('.modal-title, h1, h2, h3');
      if (modalTitle) {
        this.announce(`Modal aberto: ${modalTitle.textContent}`, 'assertive');
      }
    },

    /**
     * Close Modal with Focus Management
     * @param {Element} modal - Modal element
     */
    closeModal: function(modal) {
      // Hide modal
      modal.style.display = 'none';
      modal.setAttribute('aria-hidden', 'true');
      
      // Clear current modal
      this.currentModal = null;
      
      // Restore focus
      const previousFocus = this.focusStack.pop();
      if (previousFocus && previousFocus.focus) {
        previousFocus.focus();
      }
      
      this.announce('Modal fechado', 'polite');
    },

    /**
     * Focus First Element in Modal
     * @param {Element} modal - Modal element
     */
    focusFirstElementInModal: function(modal) {
      const focusableElements = modal.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      
      if (focusableElements.length > 0) {
        focusableElements[0].focus();
      }
    },

    /**
     * Initialize ARIA Enhancements
     */
    initARIAEnhancements: function() {
      const self = this;
      
      // Enhanced button accessibility
      document.addEventListener('click', function(e) {
        const button = e.target.closest('button, .btn');
        if (button && !button.disabled) {
          // Announce button action
          const buttonText = button.textContent.trim() || 
                           button.getAttribute('aria-label') ||
                           button.getAttribute('title');
          
          if (buttonText) {
            // Delay to allow action to complete
            setTimeout(() => {
              self.announce(`${buttonText} acionado`, 'polite');
            }, 500);
          }
        }
      });

      // Form validation announcements
      document.addEventListener('invalid', function(e) {
        const field = e.target;
        const fieldName = field.getAttribute('aria-label') || 
                         field.previousElementSibling?.textContent ||
                         field.placeholder ||
                         'Campo';
        
        self.announce(`${fieldName}: campo obrigatório não preenchido`, 'assertive');
      }, true);

      // Enhanced table accessibility
      this.enhanceTableAccessibility();
      
      // Enhanced form accessibility
      this.enhanceFormAccessibility();
    },

    /**
     * Enhance Table Accessibility
     */
    enhanceTableAccessibility: function() {
      const tables = document.querySelectorAll('table');
      
      tables.forEach(table => {
        // Add table caption if missing
        if (!table.caption) {
          const caption = document.createElement('caption');
          caption.textContent = 'Tabela de dados legislativos';
          caption.className = 'sr-only';
          table.insertBefore(caption, table.firstChild);
        }
        
        // Add scope to headers
        const headers = table.querySelectorAll('th');
        headers.forEach(header => {
          if (!header.hasAttribute('scope')) {
            header.setAttribute('scope', 'col');
          }
        });
        
        // Add table summary
        if (!table.hasAttribute('aria-describedby')) {
          const summary = document.createElement('div');
          summary.id = `table-summary-${Date.now()}`;
          summary.className = 'sr-only';
          summary.textContent = `Tabela com ${table.rows.length} linhas e ${table.rows[0]?.cells.length || 0} colunas`;
          table.parentNode.insertBefore(summary, table);
          table.setAttribute('aria-describedby', summary.id);
        }
      });
    },

    /**
     * Enhance Form Accessibility
     */
    enhanceFormAccessibility: function() {
      const forms = document.querySelectorAll('form');
      
      forms.forEach(form => {
        const fields = form.querySelectorAll('input, select, textarea');
        
        fields.forEach(field => {
          // Associate labels
          const label = form.querySelector(`label[for="${field.id}"]`) ||
                       field.closest('.form-group')?.querySelector('label');
          
          if (label && !field.hasAttribute('aria-labelledby')) {
            if (!label.id) {
              label.id = `label-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            }
            field.setAttribute('aria-labelledby', label.id);
          }
          
          // Add required indicators
          if (field.hasAttribute('required')) {
            field.setAttribute('aria-required', 'true');
            
            // Add visual indicator
            const label = document.querySelector(`label[for="${field.id}"]`);
            if (label && !label.querySelector('.required-indicator')) {
              const indicator = document.createElement('span');
              indicator.className = 'required-indicator';
              indicator.setAttribute('aria-label', 'obrigatório');
              indicator.textContent = ' *';
              indicator.style.color = 'var(--accent-danger)';
              label.appendChild(indicator);
            }
          }
          
          // Add field descriptions
          const helpText = field.closest('.form-group')?.querySelector('.form-text');
          if (helpText && !field.hasAttribute('aria-describedby')) {
            if (!helpText.id) {
              helpText.id = `help-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
            }
            field.setAttribute('aria-describedby', helpText.id);
          }
        });
      });
    },

    /**
     * Initialize Voice Announcements for Dynamic Content
     */
    initVoiceAnnouncements: function() {
      const self = this;
      
      // Observe DOM changes for dynamic content
      const observer = new MutationObserver(function(mutations) {
        mutations.forEach(mutation => {
          // Announce new content
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              self.announceNewContent(node);
            }
          });
        });
      });
      
      observer.observe(document.body, {
        childList: true,
        subtree: true
      });

      // Announce page load completion
      window.addEventListener('load', function() {
        setTimeout(() => {
          self.announce('Página carregada completamente', 'polite');
        }, 1000);
      });
    },

    /**
     * Announce New Dynamic Content
     * @param {Element} element - New element
     */
    announceNewContent: function(element) {
      // Announce loading states
      if (element.classList?.contains('loading')) {
        this.announce('Conteúdo sendo carregado', 'polite');
        return;
      }
      
      // Announce errors
      if (element.classList?.contains('error') || element.classList?.contains('alert-danger')) {
        const errorText = element.textContent?.trim();
        if (errorText) {
          this.announce(`Erro: ${errorText}`, 'assertive');
        }
        return;
      }
      
      // Announce success messages
      if (element.classList?.contains('success') || element.classList?.contains('alert-success')) {
        const successText = element.textContent?.trim();
        if (successText) {
          this.announce(`Sucesso: ${successText}`, 'polite');
        }
        return;
      }
      
      // Announce new data
      if (element.classList?.contains('data-updated')) {
        this.announce('Dados atualizados', 'polite');
        return;
      }
    },

    /**
     * Initialize High Contrast Mode
     */
    initHighContrastMode: function() {
      const self = this;
      
      // Check for user preference
      if (window.matchMedia('(prefers-contrast: high)').matches) {
        this.enableHighContrast();
      }
      
      // Toggle button
      const toggleButton = document.createElement('button');
      toggleButton.id = 'high-contrast-toggle';
      toggleButton.className = 'btn btn-outline accessibility-toggle';
      toggleButton.innerHTML = '<i class="fas fa-adjust" aria-hidden="true"></i> Alto Contraste';
      toggleButton.setAttribute('aria-label', 'Alternar modo de alto contraste');
      
      toggleButton.addEventListener('click', function() {
        self.toggleHighContrast();
      });
      
      // Add to header or accessibility menu
      const header = document.querySelector('.nav-main, header');
      if (header) {
        header.appendChild(toggleButton);
      }
    },

    /**
     * Toggle High Contrast Mode
     */
    toggleHighContrast: function() {
      this.config.enableHighContrast = !this.config.enableHighContrast;
      
      if (this.config.enableHighContrast) {
        this.enableHighContrast();
        this.announce('Modo de alto contraste ativado', 'polite');
      } else {
        this.disableHighContrast();
        this.announce('Modo de alto contraste desativado', 'polite');
      }
    },

    /**
     * Enable High Contrast Mode
     */
    enableHighContrast: function() {
      document.body.classList.add('high-contrast');
      localStorage.setItem('highContrast', 'enabled');
    },

    /**
     * Disable High Contrast Mode
     */
    disableHighContrast: function() {
      document.body.classList.remove('high-contrast');
      localStorage.setItem('highContrast', 'disabled');
    },

    /**
     * Initialize Resize Handler for Responsive Accessibility
     */
    initResizeHandler: function() {
      const self = this;
      let resizeTimeout;
      
      window.addEventListener('resize', function() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
          self.handleResize();
        }, 150);
      });
    },

    /**
     * Handle Window Resize for Accessibility
     */
    handleResize: function() {
      // Update mobile navigation
      const isMobile = window.innerWidth < 768;
      document.body.classList.toggle('mobile-view', isMobile);
      
      // Announce orientation change
      if (screen.orientation) {
        const orientation = screen.orientation.angle === 0 || screen.orientation.angle === 180 
          ? 'retrato' : 'paisagem';
        this.announce(`Orientação alterada para ${orientation}`, 'polite');
      }
    },

    /**
     * Initialize Error Handling
     */
    initErrorHandling: function() {
      const self = this;
      
      // Global error handler
      window.addEventListener('error', function(e) {
        self.announce('Ocorreu um erro na aplicação', 'assertive');
      });
      
      // Promise rejection handler
      window.addEventListener('unhandledrejection', function(e) {
        self.announce('Erro de carregamento detectado', 'assertive');
      });
    },

    /**
     * Page Loading Progress Announcement
     */
    announceLoadingProgress: function(progress, total, description = 'item') {
      const percentage = Math.round((progress / total) * 100);
      this.announce(`Carregando: ${percentage}% (${progress} de ${total} ${description})`, 'polite');
    },

    /**
     * Search Results Announcement
     */
    announceSearchResults: function(count, query) {
      if (count === 0) {
        this.announce(`Nenhum resultado encontrado para "${query}"`, 'assertive');
      } else if (count === 1) {
        this.announce(`1 resultado encontrado para "${query}"`, 'polite');
      } else {
        this.announce(`${count} resultados encontrados para "${query}"`, 'polite');
      }
    },

    /**
     * Form Submission Status
     */
    announceFormStatus: function(status, message) {
      const priority = status === 'error' ? 'assertive' : 'polite';
      this.announce(message, priority);
    },

    /**
     * Data Export Status
     */
    announceExportStatus: function(format, status) {
      if (status === 'complete') {
        this.announce(`Download do arquivo ${format} concluído`, 'polite');
      } else if (status === 'failed') {
        this.announce(`Erro no download do arquivo ${format}`, 'assertive');
      }
    }
  };

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      AccessibilityManager.init();
    });
  } else {
    AccessibilityManager.init();
  }

  // Expose to global scope for Shiny integration
  window.AccessibilityManager = AccessibilityManager;

})(window, document);