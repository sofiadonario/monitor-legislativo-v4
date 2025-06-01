/**
 * Responsive Hook
 * Detects device type, screen size, and provides responsive utilities
 */

import { useState, useEffect, useCallback, useMemo } from 'react';
import { throttle } from '../utils/performance';

interface ResponsiveConfig {
  breakpoints?: {
    xs?: number;
    sm?: number;
    md?: number;
    lg?: number;
    xl?: number;
    '2xl'?: number;
  };
  throttleMs?: number;
}

interface ResponsiveState {
  // Screen dimensions
  width: number;
  height: number;
  
  // Breakpoint flags
  isXs: boolean;
  isSm: boolean;
  isMd: boolean;
  isLg: boolean;
  isXl: boolean;
  is2xl: boolean;
  
  // Convenience flags
  isMobile: boolean;
  isTablet: boolean;
  isDesktop: boolean;
  
  // Device info
  isTouchDevice: boolean;
  isRetina: boolean;
  orientation: 'portrait' | 'landscape';
  
  // Utilities
  isAbove: (breakpoint: keyof ResponsiveConfig['breakpoints']) => boolean;
  isBelow: (breakpoint: keyof ResponsiveConfig['breakpoints']) => boolean;
  isBetween: (min: keyof ResponsiveConfig['breakpoints'], max: keyof ResponsiveConfig['breakpoints']) => boolean;
}

const defaultBreakpoints = {
  xs: 475,
  sm: 640,
  md: 768,
  lg: 1024,
  xl: 1280,
  '2xl': 1536,
};

export function useResponsive(config: ResponsiveConfig = {}): ResponsiveState {
  const { 
    breakpoints = defaultBreakpoints, 
    throttleMs = 150 
  } = config;

  // Initialize state with SSR-safe values
  const [dimensions, setDimensions] = useState({
    width: typeof window !== 'undefined' ? window.innerWidth : 1024,
    height: typeof window !== 'undefined' ? window.innerHeight : 768,
  });

  // Memoize device detection
  const deviceInfo = useMemo(() => {
    if (typeof window === 'undefined') {
      return {
        isTouchDevice: false,
        isRetina: false,
      };
    }

    return {
      isTouchDevice: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
      isRetina: window.devicePixelRatio > 1,
    };
  }, []);

  // Update dimensions on resize
  useEffect(() => {
    const handleResize = throttle(() => {
      setDimensions({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    }, throttleMs);

    window.addEventListener('resize', handleResize);
    
    // Initial call to ensure correct dimensions
    handleResize();

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, [throttleMs]);

  // Calculate breakpoint flags
  const breakpointFlags = useMemo(() => {
    const { width } = dimensions;
    
    return {
      isXs: width < breakpoints.xs,
      isSm: width >= breakpoints.xs && width < breakpoints.sm,
      isMd: width >= breakpoints.sm && width < breakpoints.md,
      isLg: width >= breakpoints.md && width < breakpoints.lg,
      isXl: width >= breakpoints.lg && width < breakpoints.xl,
      is2xl: width >= breakpoints.xl,
    };
  }, [dimensions.width, breakpoints]);

  // Convenience flags
  const convenienceFlags = useMemo(() => {
    const { width } = dimensions;
    
    return {
      isMobile: width < breakpoints.md,
      isTablet: width >= breakpoints.md && width < breakpoints.lg,
      isDesktop: width >= breakpoints.lg,
    };
  }, [dimensions.width, breakpoints]);

  // Orientation
  const orientation = useMemo(() => {
    return dimensions.width > dimensions.height ? 'landscape' : 'portrait';
  }, [dimensions]);

  // Utility functions
  const isAbove = useCallback((breakpoint: keyof typeof breakpoints) => {
    return dimensions.width >= breakpoints[breakpoint];
  }, [dimensions.width, breakpoints]);

  const isBelow = useCallback((breakpoint: keyof typeof breakpoints) => {
    return dimensions.width < breakpoints[breakpoint];
  }, [dimensions.width, breakpoints]);

  const isBetween = useCallback((min: keyof typeof breakpoints, max: keyof typeof breakpoints) => {
    return dimensions.width >= breakpoints[min] && dimensions.width < breakpoints[max];
  }, [dimensions.width, breakpoints]);

  return {
    ...dimensions,
    ...breakpointFlags,
    ...convenienceFlags,
    ...deviceInfo,
    orientation,
    isAbove,
    isBelow,
    isBetween,
  };
}

// Hook for media queries
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const mediaQuery = window.matchMedia(query);
    
    // Set initial value
    setMatches(mediaQuery.matches);

    // Create listener
    const listener = (event: MediaQueryListEvent) => {
      setMatches(event.matches);
    };

    // Add listener (using addEventListener for better browser support)
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', listener);
    } else {
      // Fallback for older browsers
      mediaQuery.addListener(listener);
    }

    // Cleanup
    return () => {
      if (mediaQuery.removeEventListener) {
        mediaQuery.removeEventListener('change', listener);
      } else {
        mediaQuery.removeListener(listener);
      }
    };
  }, [query]);

  return matches;
}

// Hook for viewport dimensions with debouncing
export function useViewport(debounceMs: number = 100) {
  const [viewport, setViewport] = useState({
    width: typeof window !== 'undefined' ? window.innerWidth : 0,
    height: typeof window !== 'undefined' ? window.innerHeight : 0,
    vw: typeof window !== 'undefined' ? window.innerWidth / 100 : 0,
    vh: typeof window !== 'undefined' ? window.innerHeight / 100 : 0,
  });

  useEffect(() => {
    let timeoutId: NodeJS.Timeout;

    const updateViewport = () => {
      clearTimeout(timeoutId);
      
      timeoutId = setTimeout(() => {
        setViewport({
          width: window.innerWidth,
          height: window.innerHeight,
          vw: window.innerWidth / 100,
          vh: window.innerHeight / 100,
        });
      }, debounceMs);
    };

    window.addEventListener('resize', updateViewport);
    window.addEventListener('orientationchange', updateViewport);
    
    // Initial update
    updateViewport();

    return () => {
      clearTimeout(timeoutId);
      window.removeEventListener('resize', updateViewport);
      window.removeEventListener('orientationchange', updateViewport);
    };
  }, [debounceMs]);

  return viewport;
}

// Hook for safe area insets (for notched devices)
export function useSafeArea() {
  const [safeArea, setSafeArea] = useState({
    top: 0,
    right: 0,
    bottom: 0,
    left: 0,
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const updateSafeArea = () => {
      const computedStyle = getComputedStyle(document.documentElement);
      
      setSafeArea({
        top: parseInt(computedStyle.getPropertyValue('--safe-area-inset-top') || '0'),
        right: parseInt(computedStyle.getPropertyValue('--safe-area-inset-right') || '0'),
        bottom: parseInt(computedStyle.getPropertyValue('--safe-area-inset-bottom') || '0'),
        left: parseInt(computedStyle.getPropertyValue('--safe-area-inset-left') || '0'),
      });
    };

    // Update on orientation change
    window.addEventListener('orientationchange', updateSafeArea);
    
    // Initial update
    updateSafeArea();

    return () => {
      window.removeEventListener('orientationchange', updateSafeArea);
    };
  }, []);

  return safeArea;
}

// Responsive image loading hook
export function useResponsiveImage(
  srcSet: { [breakpoint: string]: string },
  fallbackSrc: string
) {
  const responsive = useResponsive();
  const [currentSrc, setCurrentSrc] = useState(fallbackSrc);

  useEffect(() => {
    // Determine which image to load based on screen size
    let selectedSrc = fallbackSrc;

    if (responsive.is2xl && srcSet['2xl']) {
      selectedSrc = srcSet['2xl'];
    } else if (responsive.isXl && srcSet.xl) {
      selectedSrc = srcSet.xl;
    } else if (responsive.isLg && srcSet.lg) {
      selectedSrc = srcSet.lg;
    } else if (responsive.isMd && srcSet.md) {
      selectedSrc = srcSet.md;
    } else if (responsive.isSm && srcSet.sm) {
      selectedSrc = srcSet.sm;
    } else if (srcSet.xs) {
      selectedSrc = srcSet.xs;
    }

    setCurrentSrc(selectedSrc);
  }, [responsive, srcSet, fallbackSrc]);

  return currentSrc;
}