# Product Requirements Document (PRD)
## Monitor Legislativo v4 - AWS/Mackenzie University Deployment

**Document Version:** 1.0  
**Date:** 2025-01-23  
**Project:** AWS Migration & University Integration  
**Domain:** monitor-legislativo.mackenzie.br  

---

## Executive Summary

### Project Overview
Migration of Monitor Legislativo v4 from Railway ($7/month) to AWS infrastructure via Mackenzie University's Typo3 system, enabling deployment under the prestigious mackenzie.br domain with enterprise-grade reliability and academic institutional backing.

### Business Justification
- **Cost Optimization**: Leverage university AWS credits vs. paid Railway hosting
- **Institutional Credibility**: mackenzie.br domain enhances academic legitimacy
- **Scalability**: AWS infrastructure supports research growth and user expansion
- **Integration**: Seamless integration with existing Typo3 university portal
- **Compliance**: University-grade security and data governance standards

### Success Metrics
- **Performance**: <2s page load time, 99.9% uptime
- **Cost**: $0 monthly hosting (AWS credits), 90% cost reduction
- **Reliability**: Zero data loss, automated backups
- **Academic Impact**: Integration with 50,000+ university community
- **Research Enhancement**: Support for 10x current data volume

---

## Current State Analysis

### Technical Debt Assessment
```
Current Architecture (Railway):
├── Frontend: React/Vite → GitHub Pages (FREE) ✅
├── Backend: FastAPI → Railway ($7/month) ❌
├── Database: Supabase PostgreSQL (FREE) ✅
├── Cache: Upstash Redis (FREE) ✅
└── Analytics: R Shiny (Local) ⚠️
```

### Pain Points
1. **Railway Limitations**: Monthly cost, limited scalability
2. **Domain Authority**: GitHub Pages subdomain lacks institutional weight
3. **Integration Gaps**: No university portal integration
4. **Analytics Isolation**: R Shiny runs separately from main platform
5. **Manual Deployment**: No CI/CD integration with university systems

---

## Target Architecture

### AWS Infrastructure Design
```
AWS/Mackenzie Integration:
├── Domain: monitor-legislativo.mackenzie.br
├── CDN: CloudFront + S3 (React app)
├── Compute: ECS Fargate (FastAPI backend)
├── Database: RDS PostgreSQL + ElastiCache Redis
├── Integration: API Gateway + Typo3 Portal
├── Analytics: SageMaker Notebooks (R/Python)
├── Storage: S3 for documents/exports
└── Monitoring: CloudWatch + X-Ray
```

### Component Specifications

#### 1. Frontend (React/Vite)
- **Hosting**: S3 + CloudFront CDN
- **Domain**: monitor-legislativo.mackenzie.br
- **SSL**: AWS Certificate Manager
- **Performance**: Global edge locations, <1s load time

#### 2. Backend (FastAPI)
- **Compute**: ECS Fargate (2 vCPU, 4GB RAM)
- **Auto-scaling**: 1-10 instances based on demand
- **Load Balancer**: Application Load Balancer
- **Health Checks**: Integrated with ECS

#### 3. Database Layer
- **Primary**: RDS PostgreSQL (db.t3.micro → db.t3.small)
- **Cache**: ElastiCache Redis (cache.t3.micro)
- **Backup**: Automated daily snapshots, 7-day retention
- **Monitoring**: CloudWatch metrics and alarms

#### 4. Integration Layer
- **API Gateway**: Rate limiting, authentication, logging
- **Typo3 Integration**: SSO, user management, content syndication
- **University Portal**: Embedded dashboard widgets

#### 5. Analytics Enhancement
- **SageMaker**: Jupyter notebooks for advanced analytics
- **QuickSight**: Executive dashboards for university leadership
- **Data Lake**: S3 for long-term research data storage

---

## Typo3 Integration Strategy

### University Portal Integration
```
Typo3 CMS Integration:
├── Authentication: University SSO (LDAP/SAML)
├── Content: Research summaries auto-published
├── Widgets: Legislative monitoring dashboard embeds
├── Navigation: Integrated university menu system
└── Branding: Mackenzie visual identity compliance
```

### User Experience Flow
1. **Access**: Users visit mackenzie.br → Research → Legislative Monitor
2. **Authentication**: Automatic SSO for university members
3. **Dashboard**: Embedded monitor dashboard with university branding
4. **Export**: Research data exports saved to institutional repository
5. **Collaboration**: Integration with university research management system

---

## Implementation Plan

### Phase 1: Infrastructure Setup (Week 1-2)
```
Sprint 1.1: AWS Foundation
├── AWS Account setup via university
├── VPC, subnets, security groups configuration
├── RDS PostgreSQL instance creation
├── ElastiCache Redis cluster setup
└── S3 buckets for static assets and backups

Sprint 1.2: Compute & Networking
├── ECS cluster and task definitions
├── Application Load Balancer configuration
├── CloudFront distribution setup
├── Route 53 DNS configuration
└── SSL certificate provisioning
```

### Phase 2: Application Migration (Week 3-4)
```
Sprint 2.1: Backend Migration
├── FastAPI containerization (Docker)
├── Database migration from Supabase
├── Environment variables and secrets management
├── Health checks and monitoring setup
└── Load testing and performance optimization

Sprint 2.2: Frontend Deployment
├── S3 static website configuration
├── CloudFront CDN optimization
├── API endpoint updates for AWS backend
├── University branding integration
└── Typo3 widget development
```

### Phase 3: Integration & Testing (Week 5-6)
```
Sprint 3.1: Typo3 Integration
├── SSO authentication implementation
├── University portal widget development
├── Content management system integration
├── User permission and role mapping
└── Navigation and branding alignment

Sprint 3.2: Analytics Enhancement
├── SageMaker notebook setup
├── QuickSight dashboard creation
├── Data pipeline automation
├── Research export workflows
└── Performance monitoring dashboards
```

### Phase 4: Launch & Optimization (Week 7-8)
```
Sprint 4.1: Pre-launch Testing
├── End-to-end testing with university systems
├── Load testing with realistic traffic patterns
├── Security penetration testing
├── Accessibility compliance validation
└── Disaster recovery testing

Sprint 4.2: Go-Live & Monitoring
├── DNS cutover to mackenzie.br
├── Traffic monitoring and alerting
├── User feedback collection
├── Performance optimization
└── Documentation and training
```

---

## Technical Specifications

### AWS Services Utilization
```yaml
Compute:
  - ECS Fargate: Backend API hosting
  - Lambda: Serverless functions for data processing
  - API Gateway: Request routing and rate limiting

Storage:
  - S3: Static assets, backups, data lake
  - RDS PostgreSQL: Primary application database
  - ElastiCache Redis: Session and query caching

Networking:
  - CloudFront: Global CDN
  - Route 53: DNS management
  - Certificate Manager: SSL/TLS certificates
  - VPC: Network isolation and security

Monitoring:
  - CloudWatch: Metrics, logs, and alarms
  - X-Ray: Distributed tracing
  - Config: Compliance monitoring
  - GuardDuty: Threat detection
```

### Security Architecture
```
Security Layers:
├── Network: VPC, security groups, NACLs
├── Application: WAF, API Gateway rate limiting
├── Data: RDS encryption, S3 bucket policies
├── Identity: IAM roles, university SSO integration
├── Monitoring: CloudTrail, GuardDuty, Config
└── Compliance: SOC 2, academic data protection
```

### Performance Targets
- **Page Load Time**: <2 seconds (95th percentile)
- **API Response Time**: <500ms (average)
- **Uptime**: 99.9% availability (8.77 hours/year downtime)
- **Scalability**: Handle 1000 concurrent users
- **Data Processing**: 10,000 documents/hour indexing capacity

---

## Cost Analysis

### AWS Cost Projection (Monthly)
```
Optimized AWS Costs:
├── ECS Fargate (2 vCPU, 4GB): $0 (Free Tier)
├── RDS PostgreSQL (db.t3.micro): $0 (Free Tier)
├── ElastiCache Redis: $0 (Free Tier)
├── S3 Storage (100GB): $2.30
├── CloudFront (1TB transfer): $8.50
├── Route 53 (1 hosted zone): $0.50
├── Certificate Manager: $0
└── Data Transfer: $5.00

Total Monthly Cost: ~$16.30
University Credits Applied: -$16.30
Net Cost: $0.00/month
```

### ROI Analysis
- **Current Railway Cost**: $84/year
- **AWS with University Credits**: $0/year
- **Annual Savings**: $84 + enhanced features
- **Value Addition**: Institutional credibility, unlimited scalability

---

## Risk Assessment & Mitigation

### Technical Risks
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| AWS Credit Exhaustion | High | Low | Monitor usage, implement cost alerts |
| University SSO Integration Issues | Medium | Medium | Fallback authentication, early testing |
| Data Migration Complexity | Medium | Medium | Staged migration, rollback plan |
| Performance Degradation | High | Low | Load testing, auto-scaling policies |
| Typo3 Compatibility Issues | Medium | Medium | Sandbox testing, incremental rollout |

### Operational Risks
| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| University Policy Changes | High | Low | Legal review, backup hosting plan |
| Team Knowledge Gap | Medium | Medium | Training, documentation, AWS support |
| Timeline Delays | Medium | Medium | Agile methodology, buffer time |
| Budget Overruns | Low | Low | Cost monitoring, alerts, university backing |

---

## Success Criteria

### Technical KPIs
- **Zero Downtime Migration**: Complete migration without service interruption
- **Performance Improvement**: 50% faster load times vs. current Railway deployment
- **Scalability Achievement**: Successfully handle 10x traffic spikes
- **Security Compliance**: Pass university security audit

### Business KPIs
- **Cost Reduction**: 100% hosting cost elimination
- **User Adoption**: 25% increase in usage within 3 months
- **Academic Integration**: 5+ research projects utilizing the platform
- **Institutional Recognition**: Featured on main university research portal

### User Experience KPIs
- **Load Time**: <2s average page load
- **Uptime**: >99.9% availability
- **User Satisfaction**: >4.5/5 rating in user surveys
- **Integration Seamlessness**: Single sign-on adoption >90%

---

## Timeline & Milestones

### Critical Path (8 Weeks)
```
Week 1-2: Infrastructure Foundation
├── AWS account and basic services setup
├── VPC, security, and networking configuration
└── Database and cache deployment

Week 3-4: Application Migration
├── Backend containerization and deployment
├── Frontend S3/CloudFront setup
└── API integration and testing

Week 5-6: University Integration
├── Typo3 portal integration
├── SSO authentication implementation
└── University branding and compliance

Week 7-8: Launch Preparation
├── Comprehensive testing and optimization
├── Go-live and DNS cutover
└── Monitoring and post-launch support
```

### Key Milestones
- **Week 2**: AWS infrastructure operational
- **Week 4**: Application successfully migrated and functional
- **Week 6**: University integration complete and tested
- **Week 8**: Live on monitor-legislativo.mackenzie.br

---

## Resource Requirements

### Technical Team
- **Senior Engineer (You)**: Architecture, migration, and deployment leadership
- **DevOps Support**: AWS infrastructure management (university IT team)
- **Frontend Developer**: Typo3 integration and branding (1-2 weeks)
- **QA Analyst**: Testing and validation (university testing team)

### University Resources
- **IT Infrastructure Team**: AWS account management and security compliance
- **Typo3 Administrator**: Portal integration and CMS configuration
- **Legal/Compliance**: Policy review and approval
- **Academic Sponsor**: Project authorization and resource allocation

### External Dependencies
- **AWS University Program**: Credit allocation and technical support
- **Domain Management**: mackenzie.br subdomain allocation
- **Security Review**: University information security approval

---

## Post-Launch Operations

### Monitoring & Maintenance
```
Operational Excellence:
├── 24/7 CloudWatch monitoring with alerts
├── Weekly performance reviews and optimization
├── Monthly cost analysis and university reporting
├── Quarterly security audits and compliance checks
└── Annual architecture review and scaling planning
```

### Continuous Improvement
- **Performance Optimization**: Monthly performance tuning based on metrics
- **Feature Enhancement**: Quarterly feature releases aligned with research needs
- **Integration Expansion**: Annual evaluation of additional university system integrations
- **Research Collaboration**: Ongoing support for academic research initiatives

### Knowledge Transfer
- **Documentation**: Comprehensive AWS architecture and operational runbooks
- **Training**: University IT team cross-training on system management
- **Support**: Escalation procedures and contact information
- **Backup Planning**: Disaster recovery and business continuity procedures

---

## Conclusion

This migration represents a strategic upgrade from a cost-constrained startup environment to an enterprise-grade academic platform. By leveraging Mackenzie University's AWS infrastructure and integrating with the institutional Typo3 system, Monitor Legislativo v4 will achieve:

1. **Zero ongoing hosting costs** through university AWS credits
2. **Enhanced institutional credibility** via mackenzie.br domain
3. **Unlimited scalability** for research growth and user expansion
4. **Seamless university integration** through SSO and portal embedding
5. **Enterprise-grade reliability** with AWS-managed infrastructure

The 8-week implementation timeline is aggressive but achievable with proper resource allocation and university support. The project's success will establish Monitor Legislativo as a flagship example of university-sponsored civic technology, positioning it for future academic partnerships and research collaborations.

**Recommendation**: Proceed with immediate implementation. The technical foundation is solid, the business case is compelling, and the university partnership provides unprecedented opportunities for platform growth and academic impact.