# AWS Mackintegridade Deployment
## Monitor Legislativo v4 Integration

This folder contains all documentation and infrastructure code for deploying Monitor Legislativo v4 as part of the Mackintegridade research platform.

**Target URL:** https://www.mackenzie.br/mackintegridade/energia/transporte

## 📁 Folder Structure

```
aws-mackintegridade-deployment/
├── README.md                           # This file
├── PRD-AWS-MACKENZIE-DEPLOYMENT.md    # Product Requirements Document
├── deployment-plan.md                  # 8-week implementation timeline
├── mackintegridade-integration.md      # Technical integration details
├── aws-infrastructure.yml              # CloudFormation template
├── docker/                             # Containerization files
├── scripts/                            # Deployment automation scripts
└── configs/                            # Environment configurations
```

## 🎯 Quick Links

- **PRD**: [Product Requirements Document](PRD-AWS-MACKENZIE-DEPLOYMENT.md) - Business case and strategic overview
- **Timeline**: [Deployment Plan](deployment-plan.md) - Week-by-week implementation guide
- **Integration**: [Mackintegridade Integration](mackintegridade-integration.md) - Technical integration specifications
- **Infrastructure**: [AWS CloudFormation](aws-infrastructure.yml) - Complete infrastructure as code

## 🚀 Key Features

### Mackintegridade Integration
- Part of the Energy research vertical
- Transport legislation monitoring sub-project
- Unified authentication with Mackintegridade SSO
- Cross-project data sharing capabilities
- Integrated analytics and metrics

### Infrastructure Highlights
- **Zero Cost**: Leverages university AWS credits
- **Enterprise Scale**: Auto-scaling ECS Fargate containers
- **High Performance**: CloudFront CDN with <2s load times
- **Secure**: VPC isolation, WAF protection, university compliance
- **Integrated**: Seamless Mackintegridade portal embedding

## 📋 Pre-Deployment Checklist

- [ ] University AWS account access granted
- [ ] Mackintegridade portal integration approved
- [ ] www.mackenzie.br subdomain permissions
- [ ] Security review completed
- [ ] Legal/compliance clearance
- [ ] Mackintegridade branding assets received

## 🛠️ Quick Start

### 1. Deploy Infrastructure
```bash
aws cloudformation deploy \
  --template-file aws-infrastructure.yml \
  --stack-name mackintegridade-transport-monitor \
  --parameter-overrides \
    Environment=production \
    DomainName=www.mackenzie.br \
    ApplicationPath=/mackintegridade/energia/transporte
```

### 2. Build and Push Container
```bash
cd docker
./build-and-push.sh production
```

### 3. Deploy Application
```bash
cd scripts
./deploy-app.sh production
```

## 📊 Project Status

**Current Phase:** Planning & Documentation  
**Next Milestone:** AWS Account Setup (Week 1)  
**Target Go-Live:** September 15, 2025

## 👥 Contacts

- **Technical Lead:** Sofia Donario (Senior Reseacher)
- **Technical Lead:** Lucas Guimarães (Senior Reseacher)
- **Mackintegridade Lead:** [Cácia Pimentel]
- **University IT:** [TBD]
- **AWS Support:** Enterprise Support Portal

## 🔗 Related Resources

- [Mackintegridade Portal](https://www.mackenzie.br/mackintegridade)
- [Monitor Legislativo v4 Repository](https://github.com/sofiadonario/monitor-legislativo-v4)
- [AWS Best Practices](https://aws.amazon.com/architecture/well-architected/)

---

*This deployment positions Monitor Legislativo as a key component of the Mackintegridade research ecosystem, leveraging university infrastructure for zero-cost, enterprise-grade hosting with seamless portal integration.*