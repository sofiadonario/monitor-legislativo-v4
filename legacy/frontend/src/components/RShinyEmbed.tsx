import React, { useEffect, useRef, useState } from 'react';
import { LoadingSpinner } from './LoadingSpinner';
import { getIframeSecurityAttributes, rShinyConfig } from '../config/rshiny';
import '../styles/components/RShinyEmbed.css';

interface RShinyEmbedProps {
  url: string;
  title?: string;
  height?: string;
  width?: string;
  onLoad?: () => void;
  onError?: (error: string) => void;
  className?: string;
}

const RShinyEmbed: React.FC<RShinyEmbedProps> = ({
  url,
  title = 'R Shiny Analytics',
  height = '600px',
  width = '100%',
  onLoad,
  onError,
  className = ''
}) => {
  const [isLoading, setIsLoading] = useState(true);
  const [hasError, setHasError] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    const iframe = iframeRef.current;
    if (!iframe) return;

    const handleLoad = () => {
      setIsLoading(false);
      setHasError(false);
      onLoad?.();
    };

    const handleError = () => {
      setIsLoading(false);
      setHasError(true);
      const error = 'Failed to load R Shiny application';
      setErrorMessage(error);
      onError?.(error);
    };

    iframe.addEventListener('load', handleLoad);
    iframe.addEventListener('error', handleError);

    // Check if iframe is accessible after a timeout
    const timeout = setTimeout(() => {
      if (isLoading) {
        setIsLoading(false);
        setHasError(true);
        const error = 'R Shiny application load timeout';
        setErrorMessage(error);
        onError?.(error);
      }
    }, rShinyConfig.loadTimeout);

    return () => {
      iframe.removeEventListener('load', handleLoad);
      iframe.removeEventListener('error', handleError);
      clearTimeout(timeout);
    };
  }, [url, isLoading, onLoad, onError]);

  const retryLoad = () => {
    setIsLoading(true);
    setHasError(false);
    setErrorMessage('');
    
    // Force iframe refresh with timestamp to avoid cache
    if (iframeRef.current) {
      const urlWithTimestamp = new URL(url);
      urlWithTimestamp.searchParams.set('_t', Date.now().toString());
      iframeRef.current.src = urlWithTimestamp.toString();
    }
  };

  // Get security attributes from configuration
  const securityAttributes = getIframeSecurityAttributes();

  if (hasError) {
    return (
      <div className={`r-shiny-embed-error ${className}`}>
        <div className="error-content">
          <div className="error-icon">⚠️</div>
          <h3>R Shiny Application Unavailable</h3>
          <p>{errorMessage}</p>
          <div className="error-details">
            <p>The R Shiny analytics application could not be loaded. This may be due to:</p>
            <ul>
              <li>The R Shiny server is temporarily unavailable</li>
              <li>Network connectivity issues</li>
              <li>Application deployment problems</li>
            </ul>
          </div>
          <div className="error-actions">
            <button onClick={retryLoad} className="retry-btn">
              🔄 Try Again
            </button>
            <a 
              href={url} 
              target="_blank" 
              rel="noopener noreferrer" 
              className="external-link-btn"
            >
              🔗 Open in New Tab
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`r-shiny-embed ${className}`}>
      {isLoading && (
        <div className="r-shiny-loading">
          <LoadingSpinner message="Loading R Shiny Analytics..." />
          <p className="loading-details">
            Connecting to R Shiny application at {new URL(url).hostname}
          </p>
        </div>
      )}
      
      <iframe
        ref={iframeRef}
        src={url}
        title={title}
        width={width}
        height={height}
        frameBorder="0"
        sandbox={securityAttributes.sandbox}
        allowFullScreen={securityAttributes.allowFullScreen}
        referrerPolicy={securityAttributes.referrerPolicy}
        loading={securityAttributes.loading}
        className={`r-shiny-iframe ${isLoading ? 'loading' : 'loaded'}`}
        style={{
          display: isLoading ? 'none' : 'block'
        }}
      />
      
      {!isLoading && !hasError && (
        <div className="r-shiny-controls">
          <button 
            onClick={retryLoad} 
            className="refresh-btn"
            title="Refresh R Shiny application"
          >
            🔄
          </button>
          <a 
            href={url} 
            target="_blank" 
            rel="noopener noreferrer" 
            className="external-btn"
            title="Open in new tab"
          >
            🔗
          </a>
        </div>
      )}
    </div>
  );
};

export default RShinyEmbed;