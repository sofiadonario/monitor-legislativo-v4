/**
 * Accessibility Service
 * WCAG 2.1 AA compliance utilities and focus management
 */

export class AccessibilityService {
  private focusTracker: Element | null = null;
  private announcementQueue: string[] = [];
  private isAnnouncing = false;

  /**
   * Announce text to screen readers
   */
  announceToScreenReader(message: string, priority: 'polite' | 'assertive' = 'polite') {
    this.announcementQueue.push(message);
    this.processAnnouncementQueue(priority);
  }

  /**
   * Process announcement queue to avoid overwhelming screen readers
   */
  private processAnnouncementQueue(priority: 'polite' | 'assertive') {
    if (this.isAnnouncing) return;
    
    this.isAnnouncing = true;
    const message = this.announcementQueue.join('. ');
    this.announcementQueue = [];

    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', priority);
    announcement.setAttribute('aria-atomic', 'true');
    announcement.className = 'sr-only';
    announcement.textContent = message;
    
    document.body.appendChild(announcement);
    
    setTimeout(() => {
      document.body.removeChild(announcement);
      this.isAnnouncing = false;
      
      // Process any queued announcements
      if (this.announcementQueue.length > 0) {
        this.processAnnouncementQueue(priority);
      }
    }, 1000);
  }

  /**
   * Focus management for modal dialogs and overlays
   */
  trapFocus(container: HTMLElement) {
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    
    const firstElement = focusableElements[0] as HTMLElement;
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement;

    const handleTabKey = (e: KeyboardEvent) => {
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
    };

    container.addEventListener('keydown', handleTabKey);
    
    // Return cleanup function
    return () => {
      container.removeEventListener('keydown', handleTabKey);
    };
  }

  /**
   * Store and restore focus for modals
   */
  storeFocus() {
    this.focusTracker = document.activeElement;
  }

  restoreFocus() {
    if (this.focusTracker && this.focusTracker instanceof HTMLElement) {
      this.focusTracker.focus();
      this.focusTracker = null;
    }
  }

  /**
   * Check color contrast ratio
   */
  checkColorContrast(foreground: string, background: string): {
    ratio: number;
    wcagAA: boolean;
    wcagAAA: boolean;
  } {
    const getLuminance = (color: string): number => {
      // Convert color to RGB values
      const rgb = this.hexToRgb(color);
      if (!rgb) return 0;

      const [r, g, b] = [rgb.r, rgb.g, rgb.b].map(c => {
        c = c / 255;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
      });

      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };

    const fgLuminance = getLuminance(foreground);
    const bgLuminance = getLuminance(background);
    
    const ratio = (Math.max(fgLuminance, bgLuminance) + 0.05) / 
                  (Math.min(fgLuminance, bgLuminance) + 0.05);

    return {
      ratio,
      wcagAA: ratio >= 4.5,
      wcagAAA: ratio >= 7
    };
  }

  private hexToRgb(hex: string): {r: number, g: number, b: number} | null {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result ? {
      r: parseInt(result[1], 16),
      g: parseInt(result[2], 16),
      b: parseInt(result[3], 16)
    } : null;
  }

  /**
   * Add skip links for keyboard navigation
   */
  addSkipLinks() {
    const skipLinks = document.createElement('div');
    skipLinks.className = 'skip-links';
    skipLinks.innerHTML = `
      <a href="#main-content" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 bg-blue-600 text-white px-4 py-2 rounded z-50">
        Ir para conteúdo principal
      </a>
      <a href="#search-form" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-32 bg-blue-600 text-white px-4 py-2 rounded z-50">
        Ir para busca
      </a>
      <a href="#search-results" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-48 bg-blue-600 text-white px-4 py-2 rounded z-50">
        Ir para resultados
      </a>
    `;
    
    document.body.prepend(skipLinks);
  }

  /**
   * Validate form accessibility
   */
  validateFormAccessibility(form: HTMLFormElement): string[] {
    const issues: string[] = [];
    
    // Check for labels
    const inputs = form.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
      const id = input.getAttribute('id');
      const ariaLabel = input.getAttribute('aria-label');
      const ariaLabelledBy = input.getAttribute('aria-labelledby');
      
      if (!id || (!ariaLabel && !ariaLabelledBy)) {
        const label = form.querySelector(`label[for="${id}"]`);
        if (!label) {
          issues.push(`Input missing accessible label: ${input.outerHTML.substring(0, 50)}...`);
        }
      }
    });

    // Check for fieldsets in radio/checkbox groups
    const radioGroups = form.querySelectorAll('input[type="radio"]');
    const checkboxGroups = form.querySelectorAll('input[type="checkbox"]');
    
    if (radioGroups.length > 1 || checkboxGroups.length > 1) {
      const fieldset = form.querySelector('fieldset');
      if (!fieldset) {
        issues.push('Radio/checkbox groups should be wrapped in fieldset with legend');
      }
    }

    return issues;
  }

  /**
   * Add live region for dynamic content updates
   */
  createLiveRegion(id: string, type: 'polite' | 'assertive' = 'polite'): HTMLElement {
    let region = document.getElementById(id);
    if (!region) {
      region = document.createElement('div');
      region.id = id;
      region.setAttribute('aria-live', type);
      region.setAttribute('aria-atomic', 'true');
      region.className = 'sr-only';
      document.body.appendChild(region);
    }
    return region;
  }

  /**
   * Update live region content
   */
  updateLiveRegion(id: string, content: string) {
    const region = document.getElementById(id);
    if (region) {
      region.textContent = content;
    }
  }

  /**
   * Check keyboard accessibility
   */
  checkKeyboardAccessibility(element: HTMLElement): string[] {
    const issues: string[] = [];
    
    // Check for interactive elements without tabindex
    const interactiveElements = element.querySelectorAll('div[onclick], span[onclick]');
    interactiveElements.forEach(el => {
      if (!el.getAttribute('tabindex') && !el.getAttribute('role')) {
        issues.push('Interactive element should have tabindex and role attributes');
      }
    });

    // Check for missing keyboard event handlers
    const clickHandlers = element.querySelectorAll('[onclick]');
    clickHandlers.forEach(el => {
      if (!el.getAttribute('onkeydown') && !el.getAttribute('onkeypress')) {
        issues.push('Element with click handler should also handle keyboard events');
      }
    });

    return issues;
  }

  /**
   * Add keyboard navigation support to custom elements
   */
  addKeyboardSupport(element: HTMLElement, handler: (event: KeyboardEvent) => void) {
    element.setAttribute('tabindex', '0');
    element.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        handler(e);
      }
    });
  }

  /**
   * Screen reader optimized text formatting
   */
  formatForScreenReader(text: string, type: 'number' | 'date' | 'time' | 'currency' = 'number'): string {
    switch (type) {
      case 'number':
        return text.replace(/\./g, ' vírgula ').replace(/,/g, ' e ');
      case 'date':
        // Convert DD/MM/YYYY to more readable format
        const dateMatch = text.match(/(\d{2})\/(\d{2})\/(\d{4})/);
        if (dateMatch) {
          const [, day, month, year] = dateMatch;
          const months = [
            'janeiro', 'fevereiro', 'março', 'abril', 'maio', 'junho',
            'julho', 'agosto', 'setembro', 'outubro', 'novembro', 'dezembro'
          ];
          return `${day} de ${months[parseInt(month) - 1]} de ${year}`;
        }
        return text;
      case 'time':
        return text.replace(':', ' horas e ').replace(/(\d+)$/, '$1 minutos');
      case 'currency':
        return text.replace('R$', 'reais ').replace(/\./g, ' ').replace(',', ' vírgulas ');
      default:
        return text;
    }
  }

  /**
   * Generate unique IDs for accessibility attributes
   */
  generateId(prefix: string = 'a11y'): string {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Global accessibility service instance
export const accessibilityService = new AccessibilityService();

// Export utility functions
export const announceToScreenReader = (message: string, priority?: 'polite' | 'assertive') => {
  accessibilityService.announceToScreenReader(message, priority);
};

export const trapFocus = (container: HTMLElement) => {
  return accessibilityService.trapFocus(container);
};

export const addKeyboardSupport = (element: HTMLElement, handler: (event: KeyboardEvent) => void) => {
  accessibilityService.addKeyboardSupport(element, handler);
};