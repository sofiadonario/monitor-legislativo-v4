# Product Requirements Document (PRD)
## MackMonitor Data Consistency and Architecture Optimization

**Document Version:** 1.0  
**Date:** August 1, 2025  
**Product Owner:** Legislative Technology Team  
**Project:** MackMonitor Dashboard Critical Data Consistency Fix  

---

## Executive Summary

The MackMonitor legislative monitoring dashboard is experiencing critical data consistency issues that undermine its value proposition as a reliable research and policy analysis tool. Despite having successfully ingested 279,152+ legislative documents from the LexML Brasil system, the dashboard displays conflicting metrics across components, creating confusion for researchers and policymakers who depend on accurate, real-time legislative data.

**Business Impact:** High-severity issue affecting user trust, research accuracy, and decision-making capabilities for government stakeholders.

**Strategic Alignment:** This initiative directly supports the organizational mission of providing transparent, accurate legislative monitoring for academic research and public policy development.

---

## Problem Statement

### Current State Analysis

The MackMonitor dashboard exhibits multiple critical data consistency issues:

1. **Conflicting Data Sources:** 
   - Deployment status shows 279,152 documents
   - LexML overview component shows 0 documents  
   - Interactive map displays only 1 document
   - Analytics components show varying counts (1,904 vs 144,138)

2. **Technical Architecture Problems:**
   - Multiple uncoordinated data access layers querying different sources
   - Complex database view attempting to unify 20+ LexML tables causing performance issues
   - SQL type casting errors preventing proper data retrieval
   - Lack of unified data validation framework

3. **User Experience Impact:**
   - Researchers receive inconsistent document counts affecting analysis reliability
   - Policymakers see conflicting metrics reducing confidence in the platform
   - Academic users cannot cite data due to inconsistency concerns
   - Citizens experience confusion with contradictory information displays

### Business Impact Assessment

**Critical Impact Areas:**
- **Research Integrity:** Academic users cannot trust data for scholarly work
- **Policy Decision Support:** Inconsistent metrics undermine evidence-based policymaking  
- **Public Trust:** Citizens lose confidence in government transparency tools
- **Operational Efficiency:** IT teams spend excessive time on emergency fixes
- **Compliance Risk:** Inaccurate data may violate government transparency requirements

**Quantified Impact:**
- 100% of dashboard metrics show inconsistencies
- 3+ emergency fix attempts deployed without resolution
- Potential for incorrect policy analysis affecting millions of citizens
- Research citations at risk due to data reliability concerns

---

## User Stories and Acceptance Criteria

### Epic 1: Unified Data Access Layer

**User Story 1.1 - Data Scientist/Researcher**
```
As a data scientist analyzing legislative trends,
I want all dashboard components to display identical document counts
So that I can confidently cite consistent metrics in research publications.
```

**Acceptance Criteria:**
- All dashboard components (overview, map, analytics) show identical total document count
- Data consistency maintained across user sessions and browser refreshes  
- Audit trail logs all data access requests with timestamps and source verification
- Data validation checks run automatically every hour with alerting on discrepancies

**User Story 1.2 - Policy Analyst**
```
As a policy analyst preparing briefings for government officials,
I need real-time access to accurate, validated legislative data
So that I can provide reliable evidence for policy recommendations.
```

**Acceptance Criteria:**
- Dashboard displays consistent metrics within 5 seconds of page load
- Data freshness indicators show last update timestamp  
- Error handling provides clear feedback when data is unavailable
- Backup data sources activate automatically if primary source fails

### Epic 2: Database Query Optimization

**User Story 2.1 - System Administrator**
```
As a system administrator maintaining the platform,
I want database queries to execute efficiently without type casting errors
So that the system remains stable and performant for all users.
```

**Acceptance Criteria:**
- All SQL queries execute without type mismatch errors
- Database response times under 2 seconds for standard queries
- Query optimization reduces database load by 50%
- Automated monitoring alerts on query performance degradation

### Epic 3: Data Validation Framework

**User Story 3.1 - Quality Assurance Analyst** 
```
As a QA analyst ensuring data quality,
I want automated validation checks to detect and report data inconsistencies
So that issues are identified before affecting user experience.
```

**Acceptance Criteria:**
- Automated validation runs every 15 minutes during business hours
- Data quality dashboard shows validation results and trends
- Alerting system notifies administrators of validation failures within 5 minutes
- Validation reports include source data comparison and reconciliation recommendations

---

## Technical Requirements

### 1. Unified Data Access Layer Architecture

**Primary Components:**

**Data Access Controller (DAC)**
- Single point of entry for all data requests
- Implements circuit breaker pattern for fault tolerance
- Provides caching layer with 30-minute TTL for performance
- Maintains connection pool management (2-10 connections)
- Implements retry logic with exponential backoff

**Query Standardization Service**
- Standardized query templates for common operations
- Parameter validation and sanitization
- SQL injection prevention
- Query performance monitoring and optimization

**Data Consistency Validator**
- Real-time validation of data requests against source of truth
- Cross-component consistency checks
- Anomaly detection for unusual data patterns
- Automated reconciliation for minor discrepancies

### 2. Database Architecture Optimization

**View Consolidation Strategy:**
```sql
-- Optimized unified documents view
CREATE MATERIALIZED VIEW documents_optimized AS
SELECT 
  row_number() OVER (ORDER BY id) as unified_id,
  id as source_id,
  titulo,
  tipo,
  categoria::text as species,
  jurisdicao::text as estado,
  COALESCE(localidade, 'Nacional')::text as municipality,
  data::date as data_publicacao,
  data_coleta::date as created_at,
  transport_category,
  'LexML'::text as fonte,
  table_source
FROM (
  SELECT *, 'legislacao_geral' as table_source FROM lexml_legislacao_geral
  UNION ALL
  SELECT *, 'legislacao_aereo' as table_source FROM lexml_legislacao_aereo
  -- ... additional unions for all 20 tables
) unified_source;

-- Create indexes for performance
CREATE INDEX idx_documents_optimized_species ON documents_optimized(species);
CREATE INDEX idx_documents_optimized_estado ON documents_optimized(estado);
CREATE INDEX idx_documents_optimized_date ON documents_optimized(data_publicacao);
```

**Type Casting Standardization:**
- All date fields standardized to PostgreSQL DATE type
- Text fields explicitly cast to TEXT for COALESCE operations
- Numeric fields cast to consistent precision
- JSON metadata fields standardized with schema validation

### 3. Performance Requirements

**Response Time Targets:**
- Dashboard initial load: < 3 seconds
- Component refresh: < 1 second  
- Database queries: < 500ms average
- Map rendering: < 2 seconds

**Scalability Requirements:**
- Support 1000+ concurrent users
- Handle 500k+ documents without performance degradation
- Horizontal scaling capability for increased load
- 99.9% uptime availability

### 4. Error Handling and Resilience

**Circuit Breaker Implementation:**
- Open circuit after 5 consecutive failures
- Half-open state after 5-minute timeout
- Automatic fallback to cached data or CSV backup
- Health check endpoints for monitoring

**Graceful Degradation:**
- Display cached data when live queries fail
- Show data age indicators when using fallback sources
- Partial functionality when some components are unavailable
- User-friendly error messages with expected resolution times

---

## Data Flow Architecture

### Current State (Problematic)
```
UI Components → Multiple Direct DB Queries → Various LexML Tables
                ↓
            Inconsistent Data Presentation
```

### Target State (Optimized)
```
UI Components → Data Access Layer → Materialized View → LexML Tables
     ↓              ↓                     ↓
Cache Layer ← Validation Service ← Monitoring System
     ↓              ↓                     ↓
Consistent UX ← Quality Assurance ← Performance Metrics
```

### Data Flow Sequence

1. **Request Initiation**: UI component requests data through standardized API
2. **Cache Check**: Data Access Layer checks cache for recent data (TTL: 30 min)
3. **Database Query**: If cache miss, execute optimized query against materialized view
4. **Validation**: Run consistency checks against business rules
5. **Cache Update**: Store validated results in cache layer
6. **Response Delivery**: Return consistent data to UI component
7. **Monitoring**: Log request metrics for performance analysis

### Data Validation Pipeline

```
Raw Data → Schema Validation → Business Rules → Consistency Checks → Cache
    ↓              ↓                 ↓               ↓              ↓
Error Log → Type Checking → Count Validation → Cross-Reference → UI Display
```

**Validation Rules:**
- Document count consistency across all components
- Date range validation (1942-2025)
- Geographic data validation (valid Brazilian states/municipalities)
- Transport category validation (Aéreo, Marítimo, Rodoviário, Geral)
- URL format validation for document links

---

## Success Metrics

### Primary KPIs

**Data Consistency Metrics:**
- **Target:** 100% consistency across all dashboard components
- **Current:** 0% consistency (conflicting data displays)
- **Measurement:** Automated hourly consistency checks

**Query Performance Metrics:**
- **Target:** 95% of queries complete under 500ms
- **Current:** Varies widely due to complex views
- **Measurement:** Database performance monitoring

**System Reliability Metrics:**
- **Target:** 99.9% uptime with graceful degradation
- **Current:** Intermittent failures due to type casting errors
- **Measurement:** Application monitoring and alerting

### Secondary KPIs

**User Experience Metrics:**
- Dashboard load time: < 3 seconds (from current 10+ seconds)
- Error rate: < 0.1% (from current 15%+ SQL errors)
- User satisfaction: Target 8.5/10 (baseline survey needed)

**Operational Metrics:**
- Database CPU utilization: < 70% (optimize complex queries)
- Memory usage: < 80% (efficient caching strategy)
- Failed deployment rate: < 5% (improved CI/CD pipeline)

**Business Impact Metrics:**
- Research citation accuracy: 100% consistent data sources
- Policy analysis reliability: Zero conflicting metrics
- Public trust indicators: Consistent transparency portal data

---

## Implementation Phases and Timeline

### Phase 1: Critical Stabilization (Weeks 1-2)
**Priority:** P0 - Critical production fixes

**Week 1: Database Architecture Fix**
- [ ] Deploy IMMEDIATE_RAILWAY_FIX.sql to resolve type casting errors
- [ ] Create optimized materialized view replacing complex union view
- [ ] Implement proper SQL type casting for all date/text fields
- [ ] Test query performance and validate data consistency

**Week 2: Data Access Layer Foundation**
- [ ] Implement unified Data Access Controller
- [ ] Create standardized query templates
- [ ] Deploy circuit breaker pattern for fault tolerance
- [ ] Implement basic caching layer (Redis/in-memory)

**Deliverables:**
- Working dashboard with consistent data display
- All SQL type errors resolved
- Basic performance optimization implemented
- Emergency hotfix deployment capability

### Phase 2: Validation and Quality Assurance (Weeks 3-4)

**Week 3: Data Validation Framework**
- [ ] Implement automated data consistency checks
- [ ] Create validation rules for business logic
- [ ] Deploy data quality monitoring dashboard
- [ ] Set up alerting for data discrepancies

**Week 4: Performance Optimization**
- [ ] Optimize database queries and indexes
- [ ] Implement advanced caching strategies  
- [ ] Deploy horizontal scaling capabilities
- [ ] Load testing and performance tuning

**Deliverables:**
- Automated data validation system
- Performance monitoring and alerting
- Scalability improvements
- Quality assurance framework

### Phase 3: Advanced Features and Monitoring (Weeks 5-6)

**Week 5: Advanced Error Handling**
- [ ] Implement graceful degradation strategies
- [ ] Deploy backup data sources and failover
- [ ] Create user-friendly error messaging
- [ ] Health check endpoints and monitoring

**Week 6: Documentation and Training**
- [ ] Complete technical documentation
- [ ] User training materials and guides
- [ ] Administrative procedures and runbooks
- [ ] Stakeholder communication and rollout

**Deliverables:**
- Production-ready system with full monitoring
- Complete documentation and training materials
- Stakeholder buy-in and user adoption plan
- Long-term maintenance strategy

---

## Risk Assessment and Mitigation Strategies

### High-Priority Risks

**Risk 1: Data Migration Corruption**
- **Probability:** Medium (30%)
- **Impact:** High - Complete data loss or corruption
- **Mitigation:** 
  - Full database backup before any schema changes
  - Staged deployment with rollback capability
  - Data validation scripts for migration verification
  - Parallel system testing before cutover

**Risk 2: Performance Degradation**
- **Probability:** Medium (40%)  
- **Impact:** High - System unusable during peak usage
- **Mitigation:**
  - Load testing in staging environment
  - Gradual rollout with performance monitoring
  - Automatic scaling and circuit breaker fallback
  - Performance baseline establishment and monitoring

**Risk 3: Integration Failures**
- **Probability:** High (60%)
- **Impact:** Medium - Partial functionality loss
- **Mitigation:**
  - Comprehensive integration testing
  - Backward compatibility maintenance
  - Feature flags for selective rollback
  - Staged component deployment

### Medium-Priority Risks

**Risk 4: Stakeholder Resistance**
- **Probability:** Low (20%)
- **Impact:** Medium - Delayed adoption or requirements changes
- **Mitigation:**
  - Early stakeholder engagement and communication
  - Proof-of-concept demonstrations
  - Phased rollout with feedback incorporation
  - Training and change management support

**Risk 5: Technical Debt Accumulation**
- **Probability:** Medium (50%)
- **Impact:** Low - Long-term maintenance challenges
- **Mitigation:**
  - Code review processes and standards
  - Automated testing and quality gates
  - Technical debt tracking and prioritization
  - Regular architecture reviews

### Contingency Plans

**Plan A: Full Rollback Strategy**
- Automated database restoration from backup
- Previous application version deployment
- User communication and expected restoration time
- Root cause analysis and fix prioritization

**Plan B: Partial Functionality Mode**
- Disable problematic components
- Display cached/static data with age indicators
- Limited functionality with clear user messaging
- Progressive re-enablement as fixes are deployed

**Plan C: Emergency Maintenance Mode**
- Display maintenance page with expected resolution
- Administrative access for emergency fixes
- Stakeholder communication plan
- Service level agreement compliance procedures

---

## Dependencies and Constraints

### Technical Dependencies

**Infrastructure Requirements:**
- PostgreSQL database with materialized view support
- Redis instance for caching (optional but recommended)
- R Shiny server with sufficient memory allocation (8GB+ recommended)
- Load balancer capability for horizontal scaling

**External System Dependencies:**
- LexML Brasil API availability and stability
- Railway platform database service reliability  
- DNS and CDN services for asset delivery
- Monitoring and alerting service integration

### Organizational Constraints

**Budget Limitations:**
- Development team capacity: 2-3 developers maximum
- Infrastructure budget: Existing Railway platform costs
- No additional third-party service procurement allowed
- Must leverage existing open-source tools

**Time Constraints:**
- Critical fixes must be deployed within 2 weeks
- Full implementation within 6 weeks
- Cannot interrupt daily operations during business hours
- Must maintain backward compatibility throughout deployment

**Compliance Requirements:**
- Government data transparency requirements
- Academic research data citation standards
- LGPD (Brazilian data protection law) compliance
- Open source software licensing requirements

### Resource Requirements

**Development Team:**
- Senior R/Shiny Developer (1 FTE) - Data access layer implementation
- Database Administrator (0.5 FTE) - Query optimization and validation
- DevOps Engineer (0.5 FTE) - Deployment and monitoring setup
- Product Owner (0.25 FTE) - Requirements validation and stakeholder communication

**Infrastructure Resources:**
- Development environment matching production specifications
- Staging environment for integration testing
- Database backup and restoration capabilities
- Monitoring and alerting infrastructure

---

## Communication Plan

### Stakeholder Communication Matrix

| Stakeholder Group | Communication Method | Frequency | Key Messages |
|------------------|---------------------|-----------|--------------|
| **Executive Leadership** | Email updates + Dashboard | Weekly | Project status, risk mitigation, business impact |
| **Research Community** | Academic channels + Email | Bi-weekly | Data reliability improvements, citation accuracy |
| **Policy Analysts** | Government portal + Meetings | Weekly | Metric consistency, decision support reliability |
| **Technical Team** | Slack + Stand-ups | Daily | Implementation progress, technical challenges |
| **End Users** | In-app notifications + Help | As needed | Service improvements, feature updates |

### Communication Timeline

**Week 1:** Stakeholder notification of critical fix deployment
**Week 2:** Progress update and initial results communication  
**Week 3:** Validation framework deployment notification
**Week 4:** Performance improvements and user experience updates
**Week 5:** Advanced features rollout communication
**Week 6:** Project completion and success metrics report

### Success Communication Strategy

**Launch Announcement:**
- Highlight data consistency achievement (0% to 100%)
- Demonstrate performance improvements (3x faster loading)
- Showcase reliability enhancements (99.9% uptime)
- Emphasize user experience improvements

**Ongoing Communication:**
- Monthly data quality reports
- Quarterly performance reviews
- Annual stakeholder satisfaction surveys
- Continuous improvement roadmap updates

---

## Appendices

### Appendix A: Technical Specifications

**Database Schema Optimization:**
```sql
-- Optimized table structure
CREATE TABLE IF NOT EXISTS data_consistency_log (
  id SERIAL PRIMARY KEY,
  component_name VARCHAR(100) NOT NULL,
  expected_count INTEGER NOT NULL,
  actual_count INTEGER NOT NULL,
  consistency_check_time TIMESTAMP DEFAULT NOW(),
  status VARCHAR(20) DEFAULT 'PASSED'
);

-- Performance monitoring table
CREATE TABLE IF NOT EXISTS query_performance_log (
  id SERIAL PRIMARY KEY,
  query_type VARCHAR(100) NOT NULL,
  execution_time_ms INTEGER NOT NULL,
  rows_returned INTEGER,
  execution_timestamp TIMESTAMP DEFAULT NOW()
);
```

**API Specification:**
```javascript
// Data Access Layer API
class DataAccessController {
  async getDocumentCount(filters = {}) {
    // Standardized document count with validation
  }
  
  async getDocumentsByState(state, limit = 1000) {
    // State-filtered documents with caching
  }
  
  async validateDataConsistency() {
    // Cross-component consistency validation
  }
}
```

### Appendix B: Data Quality Validation Rules

**Business Logic Validation:**
1. Total document count must be > 100,000 (sanity check)
2. Date ranges must fall between 1942-2025
3. State codes must match valid Brazilian state abbreviations
4. Transport categories limited to: Aéreo, Marítimo, Rodoviário, Geral
5. Document types must match LexML taxonomy

**Cross-Component Consistency Rules:**
1. Overview total must equal sum of all category totals
2. Map document count must equal filtered overview count
3. Analytics charts must reflect same underlying data
4. Search results must match filter criteria exactly
5. Export data must match displayed dashboard data

### Appendix C: Monitoring and Alerting Configuration

**Critical Alerts (Immediate Response Required):**
- Data consistency failure across components
- Database connection failures
- Query execution time > 5 seconds
- Error rate > 1% over 5-minute window

**Warning Alerts (Response Within 1 Hour):**
- Performance degradation > 20% from baseline
- Cache hit ratio < 80%
- Memory usage > 85%
- Disk space < 15% available

**Information Alerts (Daily Review):**
- Data refresh completion status
- Usage pattern changes
- Performance trend analysis
- Capacity planning metrics

---

**Document Approval:**

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Product Owner | [Name] | [Digital Signature] | [Date] |
| Technical Lead | [Name] | [Digital Signature] | [Date] |
| Stakeholder Representative | [Name] | [Digital Signature] | [Date] |

**Version Control:**
- Version 1.0: Initial PRD creation
- Document ID: PRD-MACK-2025-001
- Last Updated: August 1, 2025
- Next Review Date: September 1, 2025