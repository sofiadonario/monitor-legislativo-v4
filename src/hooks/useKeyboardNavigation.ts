import { useEffect, useCallback, useRef } from 'react';

export const useKeyboardNavigation = (onEscape?: () => void, onEnter?: () => void) => {
  const onEscapeRef = useRef(onEscape);
  const onEnterRef = useRef(onEnter);

  useEffect(() => {
    onEscapeRef.current = onEscape;
    onEnterRef.current = onEnter;
  });

  const handleKeyDown = useCallback((event: KeyboardEvent) => {
    switch (event.key) {
      case 'Escape':
        onEscapeRef.current?.();
        break;
      case 'Enter':
      case ' ':
        event.preventDefault();
        onEnterRef.current?.();
        break;
      case 'Tab':
        // Ensure proper tab order
        break;
    }
  }, []);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);
};