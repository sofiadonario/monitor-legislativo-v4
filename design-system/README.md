# Monitor Legislativo Design System

## Overview

The Monitor Legislativo Design System provides a comprehensive set of design principles, components, and patterns to ensure consistency across all user interfaces of the legislative monitoring platform.

## Design Principles

### 1. Clarity First
- Information should be immediately understandable
- Use clear, concise language
- Avoid legal jargon when possible

### 2. Accessibility
- WCAG 2.1 AA compliance minimum
- High contrast ratios
- Keyboard navigation support
- Screen reader optimization

### 3. Responsiveness
- Mobile-first approach
- Fluid layouts
- Touch-friendly interactions

### 4. Performance
- Lightweight components
- Lazy loading
- Optimized assets

### 5. Trust & Authority
- Professional appearance
- Accurate information display
- Clear data sources

## Brand Identity

### Logo
- Primary: Full logo with text
- Icon: Simplified version for small spaces
- Monochrome variants available

### Colors
See `tokens/colors.json` for complete palette

### Typography
- Headings: Inter
- Body: Inter
- Monospace: JetBrains Mono

## Component Library

### Core Components
- Buttons
- Forms
- Cards
- Navigation
- Modals
- Tables
- Charts

### Specialized Components
- Document Viewer
- Timeline
- Vote Display
- Legislator Card
- Alert Banner

## Usage

### For Designers
1. Use Figma library: [Link to Figma]
2. Follow component guidelines
3. Maintain consistency

### For Developers
```bash
npm install @monitor-legislativo/design-system
```

```javascript
import { Button, Card } from '@monitor-legislativo/design-system';
```

## Contributing

See CONTRIBUTING.md for guidelines on proposing changes to the design system.

## Resources

- [Component Documentation](./components/)
- [Design Tokens](./tokens/)
- [Patterns Library](./patterns/)
- [Accessibility Guide](./accessibility.md)
- [Brand Guidelines](./brand.md)