import React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';

const cardVariants = cva(
  'bg-white rounded-lg transition-all duration-200',
  {
    variants: {
      variant: {
        default: 'border border-neutral-200',
        elevated: 'shadow-md hover:shadow-lg',
        outlined: 'border-2 border-neutral-300',
        ghost: 'border border-transparent hover:border-neutral-200',
      },
      padding: {
        none: 'p-0',
        sm: 'p-4',
        md: 'p-6',
        lg: 'p-8',
      },
      clickable: {
        true: 'cursor-pointer hover:bg-neutral-50',
        false: '',
      },
    },
    defaultVariants: {
      variant: 'default',
      padding: 'md',
      clickable: false,
    },
  }
);

export interface CardProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof cardVariants> {
  header?: React.ReactNode;
  footer?: React.ReactNode;
}

export const Card = React.forwardRef<HTMLDivElement, CardProps>(
  ({ className, variant, padding, clickable, header, footer, children, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cardVariants({ variant, padding, clickable, className })}
        {...props}
      >
        {header && (
          <div className="border-b border-neutral-200 px-6 py-4 -mx-6 -mt-6 mb-6">
            {header}
          </div>
        )}
        {children}
        {footer && (
          <div className="border-t border-neutral-200 px-6 py-4 -mx-6 -mb-6 mt-6">
            {footer}
          </div>
        )}
      </div>
    );
  }
);

Card.displayName = 'Card';

export const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div className={`mb-4 ${className || ''}`} {...props} />
);

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  className,
  ...props
}) => (
  <h3 className={`text-lg font-semibold text-neutral-900 ${className || ''}`} {...props} />
);

export const CardDescription: React.FC<React.HTMLAttributes<HTMLParagraphElement>> = ({
  className,
  ...props
}) => (
  <p className={`text-sm text-neutral-600 mt-1 ${className || ''}`} {...props} />
);

export const CardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div className={className} {...props} />
);

export const CardFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => (
  <div className={`mt-6 flex items-center justify-end gap-2 ${className || ''}`} {...props} />
);