/**
 * LocationSearchInput Component
 * Autocomplete search for Brazilian locations with geocoding
 */
import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Coordinates } from '../../types';
import { geographicService } from '../../services/geographicService';

interface LocationSearchInputProps {
  onLocationSelect: (location: Coordinates | null) => void;
  placeholder?: string;
  defaultLocation?: Coordinates | null;
}

interface LocationSuggestion {
  name: string;
  description: string;
  coordinates: Coordinates;
}

export const LocationSearchInput: React.FC<LocationSearchInputProps> = ({
  onLocationSelect,
  placeholder = 'Search for a location...',
  defaultLocation
}) => {
  const [query, setQuery] = useState('');
  const [suggestions, setSuggestions] = useState<LocationSuggestion[]>([]);
  const [loading, setLoading] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);
  const searchTimeout = useRef<NodeJS.Timeout>();

  // Common Brazilian city suggestions
  const defaultSuggestions: LocationSuggestion[] = [
    { name: 'São Paulo', description: 'São Paulo, SP', coordinates: { lat: -23.5505, lng: -46.6333 } },
    { name: 'Rio de Janeiro', description: 'Rio de Janeiro, RJ', coordinates: { lat: -22.9068, lng: -43.1729 } },
    { name: 'Brasília', description: 'Distrito Federal', coordinates: { lat: -15.8267, lng: -47.9218 } },
    { name: 'Salvador', description: 'Bahia, BA', coordinates: { lat: -12.9714, lng: -38.5014 } },
    { name: 'Fortaleza', description: 'Ceará, CE', coordinates: { lat: -3.7319, lng: -38.5267 } },
    { name: 'Belo Horizonte', description: 'Minas Gerais, MG', coordinates: { lat: -19.9245, lng: -43.9352 } },
    { name: 'Manaus', description: 'Amazonas, AM', coordinates: { lat: -3.1190, lng: -60.0217 } },
    { name: 'Curitiba', description: 'Paraná, PR', coordinates: { lat: -25.4289, lng: -49.2671 } },
    { name: 'Recife', description: 'Pernambuco, PE', coordinates: { lat: -8.0476, lng: -34.8770 } },
    { name: 'Porto Alegre', description: 'Rio Grande do Sul, RS', coordinates: { lat: -30.0346, lng: -51.2177 } }
  ];

  useEffect(() => {
    // Close suggestions when clicking outside
    const handleClickOutside = (event: MouseEvent) => {
      if (
        inputRef.current && !inputRef.current.contains(event.target as Node) &&
        suggestionsRef.current && !suggestionsRef.current.contains(event.target as Node)
      ) {
        setShowSuggestions(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const searchLocation = useCallback(async (searchQuery: string) => {
    if (searchQuery.length < 3) {
      setSuggestions(defaultSuggestions);
      return;
    }

    setLoading(true);
    try {
      // Try to geocode the address
      const coordinates = await geographicService.geocodeAddress(searchQuery);
      
      if (coordinates) {
        // Get address details from coordinates
        const address = await geographicService.reverseGeocode(coordinates);
        
        const suggestion: LocationSuggestion = {
          name: searchQuery,
          description: address ? address.formattedAddress : `${coordinates.lat.toFixed(4)}, ${coordinates.lng.toFixed(4)}`,
          coordinates
        };
        
        setSuggestions([suggestion, ...defaultSuggestions.filter(s => 
          s.name.toLowerCase().includes(searchQuery.toLowerCase())
        )]);
      } else {
        // Filter default suggestions
        setSuggestions(defaultSuggestions.filter(s => 
          s.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          s.description.toLowerCase().includes(searchQuery.toLowerCase())
        ));
      }
    } catch (error) {
      console.error('Location search failed:', error);
      setSuggestions(defaultSuggestions.filter(s => 
        s.name.toLowerCase().includes(searchQuery.toLowerCase())
      ));
    } finally {
      setLoading(false);
    }
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setQuery(value);
    setShowSuggestions(true);
    setSelectedIndex(-1);

    // Clear existing timeout
    if (searchTimeout.current) {
      clearTimeout(searchTimeout.current);
    }

    // Debounce search
    searchTimeout.current = setTimeout(() => {
      searchLocation(value);
    }, 300);
  };

  const handleSuggestionClick = (suggestion: LocationSuggestion) => {
    setQuery(suggestion.name);
    onLocationSelect(suggestion.coordinates);
    setShowSuggestions(false);
    setSelectedIndex(-1);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!showSuggestions || suggestions.length === 0) return;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex(prev => 
          prev < suggestions.length - 1 ? prev + 1 : prev
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex(prev => prev > 0 ? prev - 1 : -1);
        break;
      case 'Enter':
        e.preventDefault();
        if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
          handleSuggestionClick(suggestions[selectedIndex]);
        }
        break;
      case 'Escape':
        setShowSuggestions(false);
        setSelectedIndex(-1);
        break;
    }
  };

  const handleUseCurrentLocation = () => {
    if ('geolocation' in navigator) {
      setLoading(true);
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const coordinates: Coordinates = {
            lat: position.coords.latitude,
            lng: position.coords.longitude
          };
          
          try {
            const address = await geographicService.reverseGeocode(coordinates);
            setQuery(address ? address.formattedAddress : 'Current Location');
            onLocationSelect(coordinates);
            setShowSuggestions(false);
          } catch (error) {
            console.error('Reverse geocoding failed:', error);
            setQuery('Current Location');
            onLocationSelect(coordinates);
            setShowSuggestions(false);
          } finally {
            setLoading(false);
          }
        },
        (error) => {
          console.error('Geolocation error:', error);
          setLoading(false);
        }
      );
    }
  };

  return (
    <div className="location-search-input">
      <div className="location-search-input__container">
        <input
          ref={inputRef}
          type="text"
          value={query}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          onFocus={() => setShowSuggestions(true)}
          placeholder={placeholder}
          className="location-search-input__field"
        />
        {loading && (
          <div className="location-search-input__spinner"></div>
        )}
        <button
          onClick={handleUseCurrentLocation}
          className="location-search-input__gps-btn"
          title="Use current location"
          disabled={loading}
        >
          📍
        </button>
      </div>

      {showSuggestions && suggestions.length > 0 && (
        <div ref={suggestionsRef} className="location-search-input__suggestions">
          {suggestions.map((suggestion, index) => (
            <button
              key={`${suggestion.name}-${index}`}
              onClick={() => handleSuggestionClick(suggestion)}
              className={`location-search-input__suggestion ${
                index === selectedIndex ? 'active' : ''
              }`}
              onMouseEnter={() => setSelectedIndex(index)}
            >
              <span className="location-search-input__suggestion-name">
                {suggestion.name}
              </span>
              <span className="location-search-input__suggestion-description">
                {suggestion.description}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};