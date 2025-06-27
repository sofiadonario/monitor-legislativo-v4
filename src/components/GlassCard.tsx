import React, { ReactNode, HTMLAttributes } from 'react';
import '../styles/glassmorphism.css';

interface GlassCardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  variant?: 'light' | 'medium' | 'heavy' | 'blue' | 'green' | 'red' | 'purple' | 'academic' | 'research' | 'analysis';
  size?: 'compact' | 'normal' | 'large';
  interactive?: boolean;
  className?: string;
  animation?: 'fade-in' | 'slide-up' | 'scale-in' | 'none';
}

const GlassCard: React.FC<GlassCardProps> = ({
  children,
  variant = 'medium',
  size = 'normal',
  interactive = false,
  className = '',
  animation = 'none',
  ...props
}) => {
  const getVariantClass = () => {
    switch (variant) {
      case 'light':
        return 'glass-light';
      case 'heavy':
        return 'glass-heavy';
      case 'blue':
        return 'glass-blue';
      case 'green':
        return 'glass-green';
      case 'red':
        return 'glass-red';
      case 'purple':
        return 'glass-purple';
      case 'academic':
        return 'glass-academic';
      case 'research':
        return 'glass-research';
      case 'analysis':
        return 'glass-analysis';
      default:
        return 'glass-medium';
    }
  };

  const getSizeClass = () => {
    switch (size) {
      case 'compact':
        return 'glass-card-compact';
      case 'large':
        return 'glass-card-large';
      default:
        return '';
    }
  };

  const getAnimationClass = () => {
    switch (animation) {
      case 'fade-in':
        return 'glass-fade-in';
      case 'slide-up':
        return 'glass-slide-up';
      case 'scale-in':
        return 'glass-scale-in';
      default:
        return '';
    }
  };

  const classes = [
    'glass-card',
    getVariantClass(),
    getSizeClass(),
    interactive ? 'glass-interactive' : '',
    getAnimationClass(),
    className
  ].filter(Boolean).join(' ');

  return (
    <div className={classes} {...props}>
      {children}
    </div>
  );
};

export default GlassCard;