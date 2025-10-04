import React from 'react';
import { cn } from '../../utils';

const LoadingSpinner = ({ 
  size = 'medium', 
  message = '', 
  className = '',
  variant = 'primary'
}) => {
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12',
    xl: 'w-16 h-16',
  };

  const variantClasses = {
    primary: 'text-primary-600',
    secondary: 'text-gray-600',
    white: 'text-white',
    success: 'text-success-600',
    warning: 'text-warning-600',
    error: 'text-error-600',
  };

  return (
    <div className={cn('flex flex-col items-center justify-center', className)}>
      <div
        className={cn(
          'loading-spinner border-2 border-current border-r-transparent animate-spin',
          sizeClasses[size],
          variantClasses[variant]
        )}
      />
      {message && (
        <p className={cn(
          'mt-3 text-center',
          size === 'small' && 'text-xs',
          size === 'medium' && 'text-sm',
          size === 'large' && 'text-base',
          size === 'xl' && 'text-lg',
          variantClasses[variant]
        )}>
          {message}
        </p>
      )}
    </div>
  );
};

export default LoadingSpinner;
