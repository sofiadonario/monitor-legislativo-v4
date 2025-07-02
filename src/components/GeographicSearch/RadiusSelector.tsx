/**
 * RadiusSelector Component
 * Interactive radius selection for geographic search
 */
import React from 'react';

interface RadiusSelectorProps {
  radius: number;
  onRadiusChange: (radius: number) => void;
  min?: number;
  max?: number;
  step?: number;
  disabled?: boolean;
}

const PRESET_RADII = [
  { value: 10, label: '10 km' },
  { value: 25, label: '25 km' },
  { value: 50, label: '50 km' },
  { value: 100, label: '100 km' },
  { value: 250, label: '250 km' },
  { value: 500, label: '500 km' }
];

export const RadiusSelector: React.FC<RadiusSelectorProps> = ({
  radius,
  onRadiusChange,
  min = 1,
  max = 1000,
  step = 1,
  disabled = false
}) => {
  const handleSliderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onRadiusChange(Number(e.target.value));
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = Number(e.target.value);
    if (!isNaN(value) && value >= min && value <= max) {
      onRadiusChange(value);
    }
  };

  const handlePresetClick = (value: number) => {
    onRadiusChange(value);
  };

  const getRadiusPercentage = () => {
    return ((radius - min) / (max - min)) * 100;
  };

  return (
    <div className={`radius-selector ${disabled ? 'disabled' : ''}`}>
      <div className="radius-selector__header">
        <label htmlFor="radius-slider">Search Radius</label>
        <div className="radius-selector__value">
          <input
            type="number"
            id="radius-input"
            value={radius}
            onChange={handleInputChange}
            min={min}
            max={max}
            step={step}
            disabled={disabled}
            className="radius-selector__input"
          />
          <span className="radius-selector__unit">km</span>
        </div>
      </div>

      <div className="radius-selector__slider-container">
        <input
          type="range"
          id="radius-slider"
          value={radius}
          onChange={handleSliderChange}
          min={min}
          max={max}
          step={step}
          disabled={disabled}
          className="radius-selector__slider"
          style={{
            background: `linear-gradient(to right, #4299e1 0%, #4299e1 ${getRadiusPercentage()}%, #e2e8f0 ${getRadiusPercentage()}%, #e2e8f0 100%)`
          }}
        />
        <div className="radius-selector__labels">
          <span>{min} km</span>
          <span>{max} km</span>
        </div>
      </div>

      <div className="radius-selector__presets">
        <span className="radius-selector__presets-label">Quick select:</span>
        <div className="radius-selector__preset-buttons">
          {PRESET_RADII.map(preset => (
            <button
              key={preset.value}
              onClick={() => handlePresetClick(preset.value)}
              className={`radius-selector__preset-btn ${radius === preset.value ? 'active' : ''}`}
              disabled={disabled}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      <div className="radius-selector__info">
        <p>
          Searching within <strong>{radius} kilometers</strong> of selected location
          {radius > 100 && (
            <span className="radius-selector__warning">
              ⚠️ Large radius may return many results
            </span>
          )}
        </p>
      </div>
    </div>
  );
};