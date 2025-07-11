# Monitor Legislativo v4 - Feature Reimplementation Plan

## Current Status ✅
- **Railway Deployment**: Working
- **Basic Shiny App**: Functional with sample data
- **Database**: PostgreSQL with 889 real documents migrated
- **Core UI**: Dashboard structure with navigation

## Phase 1: Database Connection (Priority: HIGH)
### Goal: Connect R Shiny app to Railway PostgreSQL

**Tasks:**
1. **Database Configuration**
   - Add `RPostgreSQL` or `RPostgres` package to Dockerfile
   - Create database connection module in `R/database.R`
   - Test connection with Railway DATABASE_URL

2. **Environment Variables**
   - Configure DATABASE_URL in Railway dashboard
   - Add connection pooling for performance
   - Implement connection retry logic

3. **Data Layer**
   - Create functions to query `lexml_parsed_enhanced` table
   - Add functions to query `documents` table
   - Add functions to query `legislative_data` table

**Success Criteria:**
- App connects to Railway PostgreSQL successfully
- Sample queries return real data from 889 documents
- Error handling for database connection failures

---

## Phase 2: Search Functionality (Priority: HIGH)
### Goal: Implement real document search

**Tasks:**
1. **Search Interface**
   - Add search input field to dashboard
   - Create filters for document type, state, date range
   - Add advanced search options

2. **Search Logic**
   - Implement full-text search on `titulo` and `conteudo`
   - Add filter queries for `tipo`, `estado`, `data_publicacao`
   - Create search result ranking/sorting

3. **Results Display**
   - Update DataTable to show search results
   - Add pagination for large result sets
   - Include document metadata (URN, date, type, state)

**Success Criteria:**
- Users can search through 889 real documents
- Filters work correctly
- Results are relevant and properly formatted

---

## Phase 3: Geographic Visualization (Priority: MEDIUM)
### Goal: Add interactive maps with Leaflet

**Tasks:**
1. **Leaflet Integration**
   - Add `leaflet` package back to Dockerfile (with proper system deps)
   - Create map visualization module in `R/map_generator.R`
   - Test leaflet package installation in Railway environment

2. **Geographic Data Processing**
   - Map state codes to geographic coordinates
   - Aggregate document counts by state
   - Create choropleth map showing document distribution

3. **Interactive Features**
   - Add clickable state regions
   - Show document counts on hover
   - Filter documents by clicking states

**Success Criteria:**
- Interactive map displays Brazilian states
- Document counts are visualized geographically
- Map interactions filter the document list

---

## Phase 4: Data Export (Priority: MEDIUM)
### Goal: Enable data export functionality

**Tasks:**
1. **Export Modules**
   - Add export buttons to UI
   - Implement CSV export functionality
   - Add Excel export with `openxlsx` package

2. **Export Options**
   - Export current search results
   - Export all documents
   - Export filtered datasets

3. **Academic Citations**
   - Generate proper citations for documents
   - Include URN references
   - Format according to academic standards

**Success Criteria:**
- Users can export search results in multiple formats
- Academic citations are properly formatted
- Exports include all relevant metadata

---

## Phase 5: Advanced Analytics (Priority: LOW)
### Goal: Add data analysis and visualization

**Tasks:**
1. **Analytics Dashboard**
   - Document trends over time with `plotly`
   - Document type distribution charts
   - Geographic distribution analysis

2. **Statistical Insights**
   - Document count by year, month
   - Most active states for legislation
   - Document type trends

3. **Interactive Plots**
   - Clickable charts that filter data
   - Zoom and pan functionality
   - Export charts as images

**Success Criteria:**
- Rich visualizations show document patterns
- Interactive charts enhance data exploration
- Analytics provide meaningful insights

---

## Phase 6: Performance & Polish (Priority: LOW)
### Goal: Optimize performance and user experience

**Tasks:**
1. **Performance Optimization**
   - Add database query caching
   - Implement lazy loading for large datasets
   - Optimize UI rendering

2. **User Experience**
   - Add loading indicators
   - Improve error messages
   - Add help documentation

3. **Production Features**
   - Add health check endpoint
   - Implement logging for debugging
   - Add usage analytics

**Success Criteria:**
- App responds quickly to user interactions
- Professional user interface
- Reliable in production environment

---

## Implementation Strategy

### Week 1: Database & Search
- **Day 1-2**: Implement database connection (Phase 1)
- **Day 3-5**: Basic search functionality (Phase 2)
- **Day 6-7**: Testing and bug fixes

### Week 2: Visualization & Export
- **Day 1-3**: Leaflet maps integration (Phase 3)
- **Day 4-5**: Data export features (Phase 4)
- **Day 6-7**: Testing and refinement

### Week 3: Analytics & Polish
- **Day 1-3**: Advanced analytics (Phase 5)
- **Day 4-5**: Performance optimization (Phase 6)
- **Day 6-7**: Final testing and documentation

## Risk Mitigation

### High-Risk Items:
1. **Leaflet Package**: May have system dependency issues
   - **Mitigation**: Test in separate Dockerfile, use fallback simple maps
   
2. **Database Performance**: 889 records should be fine, but queries might be slow
   - **Mitigation**: Add database indexes, implement query optimization

3. **Memory Usage**: R can be memory-intensive with large datasets
   - **Mitigation**: Implement pagination, lazy loading

### Rollback Strategy:
- Each phase is independent
- Can deploy without advanced features if needed
- Minimal app already working as fallback

## Success Metrics

### Technical Metrics:
- App loads within 3 seconds
- Search results return within 2 seconds
- No crashes under normal usage
- Database queries are optimized

### User Experience Metrics:
- All 889 documents are searchable
- Maps display correctly
- Export functions work reliably
- Professional appearance and usability

## Next Steps

1. **Immediate**: Start Phase 1 (Database Connection)
2. **This Week**: Complete Phases 1-2 (Database + Search)
3. **Next Week**: Add visualization and export features
4. **Following Week**: Polish and optimize

Each phase will be implemented incrementally with testing and deployment to Railway after each major milestone.