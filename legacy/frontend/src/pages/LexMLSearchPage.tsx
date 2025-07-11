/**
 * LexML Search Page
 * Full-page implementation of the real-time LexML Brasil search
 */

import React from 'react';
import { LexMLSearchContainer } from '../features/real-time-search';
import { LexMLDocument } from '../features/real-time-search/types/lexml-api.types';

interface LexMLSearchPageProps {
  className?: string;
}

export const LexMLSearchPage: React.FC<LexMLSearchPageProps> = ({ className = '' }) => {
  const handleDocumentSelect = (document: LexMLDocument) => {
    console.log('Document selected:', document);
    // Here you could integrate with routing, analytics, etc.
  };

  return (
    <div className={`min-h-screen bg-gray-50 ${className}`}>
      {/* Page Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">
                Monitor Legislativo v4
              </h1>
              <p className="text-gray-600 mt-1">
                Real-time Legislative Search powered by LexML Brasil
              </p>
            </div>
            
            {/* Navigation */}
            <nav className="flex items-center gap-4">
              <a
                href="/"
                className="text-gray-600 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
              >
                Dashboard
              </a>
              <a
                href="/search"
                className="bg-blue-600 text-white px-3 py-2 rounded-md text-sm font-medium"
              >
                Search
              </a>
              <a
                href="/about"
                className="text-gray-600 hover:text-gray-900 px-3 py-2 rounded-md text-sm font-medium"
              >
                About
              </a>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="py-8">
        <LexMLSearchContainer onDocumentSelect={handleDocumentSelect} />
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-16">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between text-sm text-gray-600">
            <div>
              <p>
                Monitor Legislativo v4 - Academic Research Platform
              </p>
              <p className="mt-1">
                Data provided by LexML Brasil (FREE government service)
              </p>
            </div>
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-1">
                🚀 Real-time API
              </span>
              <span className="flex items-center gap-1">
                ⚫ CSV Fallback
              </span>
              <span className="flex items-center gap-1">
                🏛️ Official Sources
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LexMLSearchPage;