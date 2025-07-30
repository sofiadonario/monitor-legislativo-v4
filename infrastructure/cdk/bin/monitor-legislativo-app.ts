#!/usr/bin/env node
/**
 * Monitor Legislativo v4 - AWS CDK Application
 * Infrastructure for scalable Brazilian legislative document monitoring
 * Supports 500+ concurrent users with cost optimization
 */

import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { MonitorLegislativoStack } from '../lib/monitor-legislativo-stack';
import { MonitoringStack } from '../lib/monitoring-stack';
import { SecurityStack } from '../lib/security-stack';

const app = new cdk.App();

// Environment configurations
const devEnv = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: 'sa-east-1', // São Paulo region for LGPD compliance
};

const prodEnv = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: 'sa-east-1', // São Paulo region for LGPD compliance
};

// Development Stack
const devStack = new MonitorLegislativoStack(app, 'MonitorLegislativoStack-dev', {
  env: devEnv,
  stage: 'dev',
  instanceSize: 'small', // Cost-optimized for development
  minCapacity: 1,
  maxCapacity: 4,
  tags: {
    Environment: 'development',
    Project: 'monitor-legislativo-v4',
    CostCenter: 'university-aws-credits',
    Owner: 'mackenzie-research-team'
  }
});

// Production Stack  
const prodStack = new MonitorLegislativoStack(app, 'MonitorLegislativoStack-prod', {
  env: prodEnv,
  stage: 'prod',
  instanceSize: 'medium', // Optimized for 500+ concurrent users
  minCapacity: 2,
  maxCapacity: 16,
  tags: {
    Environment: 'production',
    Project: 'monitor-legislativo-v4',
    CostCenter: 'university-aws-credits',
    Owner: 'mackenzie-research-team',
    Compliance: 'LGPD'
  }
});

// Security Stack (shared across environments)
const securityStack = new SecurityStack(app, 'MonitorLegislativoSecurityStack', {
  env: prodEnv,
  tags: {
    Environment: 'shared',
    Project: 'monitor-legislativo-v4',
    SecurityLayer: 'waf-certificates',
  }
});

// Monitoring Stack (production)
const monitoringStack = new MonitoringStack(app, 'MonitorLegislativoMonitoringStack', {
  env: prodEnv,
  applicationStack: prodStack,
  tags: {
    Environment: 'production',
    Project: 'monitor-legislativo-v4',
    MonitoringType: 'cloudwatch-xray',
  }
});

// Stack dependencies
monitoringStack.addDependency(prodStack);
prodStack.addDependency(securityStack);
devStack.addDependency(securityStack);