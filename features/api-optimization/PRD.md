# Product Requirements Document (PRD)
## API Request Optimization for Monitor Legislativo v4

**Version**: 1.0  
**Date**: June 23, 2025  
**Author**: Senior Engineering Team  
**Status**: Planning Phase  
**Priority**: P1 - Critical Performance Issue  

---

## Executive Summary

**CRITICAL PERFORMANCE ISSUE IDENTIFIED**: The Monitor Legislativo v4 platform is generating excessive redundant API requests to the LexML Enhanced Research Engine, causing performance degradation, unnecessary backend load, and potential rate limiting issues. Console analysis reveals up to 20+ identical API calls triggered by rapid user interactions in the search interface.

**Business Impact**: This optimization will improve user experience, reduce backend costs, prevent rate limiting, and ensure sustainable platform performance within our $7-16/month budget constraints.

---

## 1. Problem Statement

### 1.1 Current Issue
The Dashboard component lacks debouncing mechanisms, causing every user interaction (typing, filter selection, checkbox clicks) to immediately trigger API requests to the LexML Enhanced Research Engine. This results in:

- **20+ redundant API calls** during normal user search interactions
- Potential rate limiting from backend services
- Degraded user experience with loading states
- Unnecessary network traffic and backend resource consumption
- Risk of exceeding Railway hosting budget limits

### 1.2 Root Cause Analysis

**Primary Issue**: Dashboard.tsx directly calls `legislativeDataService.fetchDocuments()` in a `useEffect` that triggers on every `filters` change without debouncing.

**Contributing Factors**:
1. **No Request Debouncing**: EnhancedSearch component immediately updates filters on every keystroke
2. **Missing Request Cancellation**: Previous API requests are not aborted when new ones are initiated
3. **Unused Infrastructure**: Existing `useLexMLSearch` hook with proper debouncing is not utilized
4. **Immediate Filter Updates**: Every UI interaction triggers instant API calls

### 1.3 Evidence from Console Logs
```
🔬 Connecting to LexML Enhanced Research Engine... (x20+)
✅ Backend connectivity confirmed, proceeding with enhanced search... (x20+)
🔄 Enhanced API returned no results, falling back to embedded real data (x20+)
```

---

## 2. Goals & Objectives

### 2.1 Primary Goals
- **Reduce API calls by 85%** through intelligent debouncing and request deduplication
- **Improve user experience** by eliminating unnecessary loading states
- **Maintain budget compliance** by reducing backend resource consumption
- **Prevent rate limiting** from external API services

### 2.2 Success Metrics
- **API Request Reduction**: From 20+ calls to 2-3 calls per search session
- **User Experience**: Eliminate loading flicker during typing
- **Performance**: Maintain <500ms response time for live searches
- **Resource Usage**: Reduce Railway backend requests by 85%
- **Error Rate**: Maintain 0% request failures due to rate limiting

### 2.3 Non-Goals
- Changing the existing search functionality or UI
- Modifying the LexML API integration logic
- Altering the fallback CSV data mechanism

---

## 3. Technical Analysis

### 3.1 Current Architecture Issues

```typescript
// PROBLEM: Dashboard.tsx (Lines 74-94)
useEffect(() => {
  const loadDocuments = async () => {
    // Immediate API call on every filter change
    await legislativeDataService.fetchDocuments(filters);
  };
  loadDocuments();
}, [filters]); // Triggers on every filter modification
```

```typescript
// PROBLEM: EnhancedSearch.tsx - Multiple immediate handlers
const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
  // Immediate filter update on every keystroke
  onFiltersChange({ ...filters, searchTerm: e.target.value });
};
```

### 3.2 Existing Infrastructure (Unused)

**Available Solution**: `useLexMLSearch` hook at `/features/real-time-search/hooks/useLexMLSearch.ts`

**Features Already Implemented**:
- ✅ Configurable debounce delay (500ms default)
- ✅ Request cancellation with AbortController
- ✅ Proper cleanup mechanisms
- ✅ Loading state management
- ✅ Error handling

**Problem**: Dashboard component bypasses this infrastructure entirely.

---

## 4. Proposed Solution

### 4.1 Implementation Strategy

**Approach**: Minimal, contained changes following the Senior Engineer Task Execution Rule.

**Core Solution**: Integrate existing `useLexMLSearch` debouncing infrastructure into Dashboard component without breaking existing functionality.

### 4.2 Technical Implementation

#### Phase 1: Dashboard Integration (2 hours)
```typescript
// SOLUTION: Dashboard.tsx
import { useLexMLSearch } from '../features/real-time-search/hooks/useLexMLSearch';

// Replace direct API calls with debounced hook
const { 
  searchResults, 
  isLoading, 
  error 
} = useLexMLSearch(filters, {
  debounceMs: 500,
  enableAutoSearch: true
});
```

#### Phase 2: Request Deduplication (1 hour)
```typescript
// ENHANCEMENT: legislativeDataService.ts
class LegislativeDataService {
  private requestCache = new Map<string, Promise<any>>();
  
  async fetchDocuments(filters: SearchFilters): Promise<LegislativeDocument[]> {
    const cacheKey = JSON.stringify(filters);
    
    // Return existing request if identical
    if (this.requestCache.has(cacheKey)) {
      return this.requestCache.get(cacheKey);
    }
    
    // Create new request with cleanup
    const request = this._performSearch(filters);
    this.requestCache.set(cacheKey, request);
    
    // Auto-cleanup after completion
    request.finally(() => this.requestCache.delete(cacheKey));
    
    return request;
  }
}
```

#### Phase 3: Enhanced Filter Batching (1 hour)
```typescript
// ENHANCEMENT: EnhancedSearch.tsx
const [pendingFilters, setPendingFilters] = useState<SearchFilters>(filters);

// Batch rapid filter changes
const debouncedFilterUpdate = useMemo(
  () => debounce((newFilters: SearchFilters) => {
    onFiltersChange(newFilters);
  }, 300),
  [onFiltersChange]
);

const handleFilterChange = (updates: Partial<SearchFilters>) => {
  const newFilters = { ...pendingFilters, ...updates };
  setPendingFilters(newFilters);
  debouncedFilterUpdate(newFilters);
};
```

---

## 5. Implementation Plan

### 5.1 Development Phases

**Phase 1: Core Debouncing Integration** (2 hours)
- [ ] Integrate `useLexMLSearch` hook into Dashboard component
- [ ] Replace direct `legislativeDataService.fetchDocuments` calls
- [ ] Test with existing search functionality
- [ ] Verify 500ms debounce behavior

**Phase 2: Request Deduplication** (1 hour)
- [ ] Add request caching to `legislativeDataService`
- [ ] Implement automatic cache cleanup
- [ ] Test identical request handling
- [ ] Verify memory management

**Phase 3: Filter Batching Enhancement** (1 hour)
- [ ] Add filter batching to EnhancedSearch component
- [ ] Implement 300ms batch delay for rapid interactions
- [ ] Test rapid typing and filter selection
- [ ] Verify UI responsiveness

**Phase 4: Testing & Validation** (1 hour)
- [ ] Console log verification (target: 2-3 requests max)
- [ ] User experience testing
- [ ] Performance metrics validation
- [ ] Budget impact assessment

### 5.2 Risk Mitigation

**Risk**: Breaking existing search functionality  
**Mitigation**: Use existing proven `useLexMLSearch` infrastructure, minimal changes to current logic

**Risk**: User experience degradation  
**Mitigation**: Maintain 300-500ms debounce (industry standard), preserve immediate UI feedback

**Risk**: Complex implementation  
**Mitigation**: Leverage existing debounce infrastructure, avoid creating new abstractions

---

## 6. Acceptance Criteria

### 6.1 Performance Requirements
- [ ] API requests reduced from 20+ to maximum 3 per search session
- [ ] Console logs show maximum 3 "🔬 Connecting to LexML..." messages
- [ ] No loading flicker during rapid typing
- [ ] Search results appear within 500ms of user stopping interaction

### 6.2 Functional Requirements
- [ ] All existing search functionality preserved
- [ ] Filter combinations work identically to current behavior
- [ ] CSV fallback mechanism unaffected
- [ ] Real-time search responsiveness maintained

### 6.3 Budget Requirements
- [ ] Railway backend request volume reduced by 85%
- [ ] No increase in hosting costs
- [ ] Memory usage remains within acceptable limits

---

## 7. Technical Specifications

### 7.1 Debounce Configuration
```typescript
const DEBOUNCE_SETTINGS = {
  searchInput: 500,     // Text input debounce
  filterChanges: 300,   // Checkbox/dropdown debounce
  requestCache: 1000    // Request deduplication window
};
```

### 7.2 Request Lifecycle
1. **User Input** → Local filter state update (immediate UI feedback)
2. **Debounce Timer** → 300-500ms delay
3. **Request Deduplication** → Check for identical pending requests
4. **API Call** → Execute if unique request
5. **Cache Management** → Auto-cleanup completed requests

### 7.3 Monitoring & Logging
```typescript
// Performance monitoring
console.log(`🎯 API Request: ${requestId} [${filters.searchTerm}]`);
console.log(`⚡ Request deduped: ${cacheHit ? 'HIT' : 'MISS'}`);
console.log(`📊 Active requests: ${this.requestCache.size}`);
```

---

## 8. Dependencies & Constraints

### 8.1 Technical Dependencies
- Existing `useLexMLSearch` hook (already implemented)
- Current `legislativeDataService` architecture
- React 18.3.1 hooks compatibility

### 8.2 Budget Constraints
- Must maintain $7-16/month hosting budget
- Railway request limits must be respected
- No additional third-party services

### 8.3 Timeline Constraints
- **Total Development Time**: 5 hours
- **Testing & Validation**: 1 hour
- **Deployment**: Immediate (GitHub Pages auto-deploy)

---

## 9. Success Measurement

### 9.1 Before/After Metrics

**Current State**:
- 20+ API requests per search session
- Continuous loading states during typing
- High backend resource usage

**Target State**:
- 2-3 API requests per search session
- Smooth typing experience with debounced requests
- 85% reduction in backend resource consumption

### 9.2 Validation Method
1. **Console Monitoring**: Count "🔬 Connecting to LexML..." messages
2. **Network Tab**: Verify request deduplication in browser DevTools
3. **User Testing**: Rapid typing and filter interaction scenarios
4. **Railway Metrics**: Monitor backend request volume reduction

---

## 10. Rollback Plan

### 10.1 Low-Risk Implementation
All changes are additive and use existing infrastructure. Rollback involves:
1. Revert Dashboard component to direct API calls
2. Remove request caching from legislativeDataService
3. Restore immediate filter updates in EnhancedSearch

### 10.2 Feature Flags
```typescript
const USE_DEBOUNCED_SEARCH = process.env.NODE_ENV === 'production';
```

---

## 11. Future Considerations

### 11.1 Advanced Optimizations (Future)
- Server-side search result caching
- Progressive search suggestions
- Search analytics and optimization
- Advanced request prioritization

### 11.2 Monitoring Infrastructure
- Real-time performance dashboards
- API usage analytics
- User experience metrics
- Budget tracking automation

---

## Conclusion

This optimization addresses a critical performance issue using existing infrastructure with minimal risk. The implementation leverages proven debouncing patterns already present in the codebase, ensuring reliable delivery within budget constraints while dramatically improving user experience and system efficiency.

**Estimated Impact**: 85% reduction in API requests, improved user experience, sustained budget compliance, and foundation for future performance optimizations.