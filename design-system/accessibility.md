# Accessibility Guidelines

## Overview
Monitor Legislativo is committed to providing an accessible experience for all users, including those with disabilities. This guide outlines our accessibility standards and implementation practices.

## WCAG 2.1 Compliance

We aim for WCAG 2.1 Level AA compliance across all interfaces.

### Key Principles

1. **Perceivable**: Information must be presentable in ways users can perceive
2. **Operable**: Interface components must be operable
3. **Understandable**: Information and UI operation must be understandable
4. **Robust**: Content must be robust enough for various assistive technologies

## Color & Contrast

### Contrast Ratios
- **Normal text**: 4.5:1 minimum
- **Large text** (18pt+): 3:1 minimum
- **UI components**: 3:1 minimum

### Color Usage
- Never rely solely on color to convey information
- Provide additional indicators (icons, text, patterns)
- Test with color blindness simulators

```tsx
// ❌ Bad: Color only
<Badge color="red">Rejeitado</Badge>

// ✅ Good: Color + Icon + Text
<Badge color="red">
  <XCircle className="mr-1" />
  Rejeitado
</Badge>
```

## Keyboard Navigation

### Focus Management
- All interactive elements must be keyboard accessible
- Focus order should be logical and predictable
- Focus indicators must be clearly visible

```css
/* Custom focus styles */
.focus-visible:focus {
  outline: 2px solid #3B82F6;
  outline-offset: 2px;
}
```

### Keyboard Shortcuts
- Provide keyboard shortcuts for common actions
- Document shortcuts clearly
- Allow users to customize shortcuts

```tsx
const shortcuts = {
  'cmd+k': 'Open search',
  'cmd+/': 'Show shortcuts',
  'esc': 'Close modal',
};
```

## Screen Readers

### Semantic HTML
Use proper HTML elements for their intended purpose:

```tsx
// ❌ Bad
<div onClick={handleClick}>Clique aqui</div>

// ✅ Good
<button onClick={handleClick}>Clique aqui</button>
```

### ARIA Labels
Provide context when visual cues aren't sufficient:

```tsx
<button
  aria-label="Remover filtro de tipo: Lei"
  onClick={() => removeFilter('type', 'lei')}
>
  <X className="h-4 w-4" />
</button>
```

### Live Regions
Announce dynamic content changes:

```tsx
<div
  role="status"
  aria-live="polite"
  aria-atomic="true"
>
  {results.length} resultados encontrados
</div>
```

## Forms

### Label Association
Every form control must have an associated label:

```tsx
<div>
  <label htmlFor="search">Buscar documento</label>
  <input
    id="search"
    type="search"
    aria-describedby="search-help"
  />
  <span id="search-help" className="text-sm text-neutral-600">
    Digite o número ou título do documento
  </span>
</div>
```

### Error Messages
Make errors clear and actionable:

```tsx
<div role="alert" aria-live="assertive">
  <p className="text-error-600">
    <AlertCircle className="inline mr-1" />
    O campo "Título" é obrigatório
  </p>
</div>
```

### Required Fields
Clearly indicate required fields:

```tsx
<label htmlFor="title">
  Título
  <span aria-label="obrigatório" className="text-error-500">*</span>
</label>
```

## Images & Media

### Alt Text
Provide meaningful alt text for all images:

```tsx
// Informative image
<img
  src="/legislator-photo.jpg"
  alt="Foto do Deputado João Silva"
/>

// Decorative image
<img
  src="/decorative-pattern.svg"
  alt=""
  role="presentation"
/>
```

### Video Captions
All video content must include captions:

```tsx
<video controls>
  <source src="session.mp4" type="video/mp4" />
  <track
    kind="captions"
    src="session-pt.vtt"
    srclang="pt"
    label="Português"
    default
  />
</video>
```

## Navigation

### Skip Links
Provide skip links for keyboard users:

```tsx
<a href="#main-content" className="skip-link">
  Pular para o conteúdo principal
</a>
```

### Breadcrumbs
Use proper ARIA markup for breadcrumbs:

```tsx
<nav aria-label="Breadcrumb">
  <ol className="breadcrumb">
    <li><a href="/">Início</a></li>
    <li><a href="/documents">Documentos</a></li>
    <li aria-current="page">Lei 14.133/2021</li>
  </ol>
</nav>
```

## Tables

### Table Headers
Associate data cells with headers:

```tsx
<table>
  <caption>Votações recentes</caption>
  <thead>
    <tr>
      <th scope="col">Documento</th>
      <th scope="col">Data</th>
      <th scope="col">Resultado</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">PL 1234/2021</th>
      <td>15/01/2024</td>
      <td>Aprovado</td>
    </tr>
  </tbody>
</table>
```

## Testing

### Automated Testing
- Use axe-core for automated accessibility testing
- Include accessibility tests in CI/CD pipeline
- Regular audits with Lighthouse

### Manual Testing
- Test with keyboard only
- Test with screen readers (NVDA, JAWS, VoiceOver)
- Test with browser zoom at 200%
- Test with Windows High Contrast mode

### User Testing
- Include users with disabilities in testing
- Gather feedback on accessibility features
- Iterate based on real user experiences

## Implementation Checklist

- [ ] Color contrast meets WCAG standards
- [ ] All interactive elements are keyboard accessible
- [ ] Forms have proper labels and error messages
- [ ] Images have appropriate alt text
- [ ] Dynamic content updates are announced
- [ ] Page has proper heading structure
- [ ] Focus indicators are visible
- [ ] Skip links are provided
- [ ] ARIA labels are used appropriately
- [ ] Content is readable at 200% zoom

## Resources

- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/)
- [WebAIM Resources](https://webaim.org/resources/)
- [A11y Project Checklist](https://www.a11yproject.com/checklist/)