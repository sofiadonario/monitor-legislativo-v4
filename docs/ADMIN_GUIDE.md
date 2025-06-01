# Monitor Legislativo - Guia do Administrador

## Visão Geral

Este guia fornece instruções detalhadas para administradores do sistema Monitor Legislativo, cobrindo instalação, configuração, monitoramento e manutenção da plataforma.

## Índice

1. [Instalação e Deploy](#instalação-e-deploy)
2. [Configuração do Sistema](#configuração-do-sistema)
3. [Gerenciamento de Usuários](#gerenciamento-de-usuários)
4. [Monitoramento e Alertas](#monitoramento-e-alertas)
5. [Backup e Recuperação](#backup-e-recuperação)
6. [Segurança](#segurança)
7. [Performance e Otimização](#performance-e-otimização)
8. [Troubleshooting](#troubleshooting)
9. [Manutenção](#manutenção)

## Instalação e Deploy

### Pré-requisitos

#### Hardware Mínimo (Produção)
- **CPU**: 8 cores
- **RAM**: 32GB
- **Storage**: 500GB SSD
- **Network**: 1Gbps

#### Software Necessário
- Docker 20.10+
- Docker Compose 2.0+
- Kubernetes 1.24+ (para deploy em cluster)
- PostgreSQL 14+
- Redis 6.2+
- Elasticsearch 8.0+

### Deploy com Docker Compose

#### 1. Clone o Repositório
```bash
git clone https://github.com/monitor-legislativo/monitor-legislativo-v4.git
cd monitor-legislativo-v4
```

#### 2. Configure Variáveis de Ambiente
```bash
cp .env.example .env
nano .env
```

Principais variáveis:
```env
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/monitor_legislativo
REDIS_URL=redis://localhost:6379/0
ELASTICSEARCH_URL=http://localhost:9200

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-here

# External APIs
CAMARA_API_KEY=your-camara-api-key
SENADO_API_KEY=your-senado-api-key
```

#### 3. Execute o Deploy
```bash
# Construir e iniciar serviços
docker-compose up -d

# Verificar status
docker-compose ps

# Ver logs
docker-compose logs -f
```

### Deploy em Kubernetes

#### 1. Preparar Infraestrutura
```bash
# Aplicar configurações
kubectl apply -f k8s/production/

# Verificar pods
kubectl get pods -n monitor-legislativo-production

# Verificar serviços
kubectl get svc -n monitor-legislativo-production
```

#### 2. Configurar Ingress
```bash
# Instalar NGINX Ingress Controller
helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx

# Configurar certificados SSL
kubectl apply -f k8s/production/certificates.yaml
```

#### 3. Deploy Automatizado
```bash
# Usar script de deploy
./scripts/deploy.sh production
```

### Verificação Pós-Deploy

#### 1. Health Checks
```bash
# API Health
curl http://localhost:5000/health

# Metrics
curl http://localhost:5000/metrics

# Database
curl http://localhost:5000/api/health/database
```

#### 2. Testes Funcionais
```bash
# Executar suite de testes
python tests/e2e/production_tests.py

# Verificar logs
tail -f data/logs/monitor-legislativo.log
```

## Configuração do Sistema

### Configuração da Aplicação

#### 1. Arquivo de Configuração Principal
Edite `configs/production.json`:

```json
{
  "app_name": "Monitor Legislativo",
  "environment": "production",
  "debug": false,
  "workers": 4,
  "timeout": 60,
  "rate_limit_default": "100/minute",
  "cache_default_timeout": 3600,
  "log_level": "INFO",
  "metrics_enabled": true
}
```

#### 2. Configuração de Database
```json
{
  "database_pool_size": 20,
  "database_max_overflow": 30,
  "database_pool_timeout": 30,
  "database_pool_recycle": 3600
}
```

#### 3. Configuração de Cache
```json
{
  "cache_type": "redis",
  "redis_max_connections": 50,
  "cache_key_prefix": "monitor_legislativo:"
}
```

### Configuração de Monitoramento

#### 1. Prometheus
Edite `monitoring/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'monitor-legislativo-api'
    static_configs:
      - targets: ['api-service:5000']
    scrape_interval: 15s
    metrics_path: '/metrics'
```

#### 2. Grafana
- **URL**: http://localhost:3000
- **Usuário**: admin
- **Senha**: Definida em `GRAFANA_ADMIN_PASSWORD`

Importe dashboards:
```bash
# Dashboard principal
curl -X POST \
  http://admin:password@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @monitoring/grafana/dashboards/legislative-monitor-dashboard.json
```

#### 3. Alertmanager
Configure `monitoring/alertmanager/alertmanager.yml`:

```yaml
global:
  smtp_smarthost: 'smtp.company.com:587'
  smtp_from: 'alerts@monitor-legislativo.gov.br'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  email_configs:
  - to: 'admin@monitor-legislativo.gov.br'
    subject: 'Monitor Legislativo Alert'
```

### Configuração de Segurança

#### 1. SSL/TLS
```bash
# Gerar certificados (desenvolvimento)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365

# Configurar no nginx
server {
    listen 443 ssl;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
}
```

#### 2. Firewall
```bash
# Permitir apenas portas necessárias
ufw allow 22    # SSH
ufw allow 80    # HTTP
ufw allow 443   # HTTPS
ufw enable
```

#### 3. Rate Limiting
```python
# Configuração no Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)
```

## Gerenciamento de Usuários

### Interface de Administração

#### 1. Acesso ao Painel Admin
- **URL**: http://localhost:5000/admin
- **Login**: admin@monitor-legislativo.gov.br
- **Senha**: Definida durante setup inicial

#### 2. Funcionalidades Disponíveis
- Criar/editar/excluir usuários
- Gerenciar permissões e roles
- Visualizar logs de atividade
- Configurar sistema

### Gerenciamento via CLI

#### 1. Criar Usuário
```bash
python -m core.cli user create \
  --email user@example.com \
  --name "João Silva" \
  --role user \
  --active
```

#### 2. Listar Usuários
```bash
python -m core.cli user list --active
```

#### 3. Alterar Role
```bash
python -m core.cli user update \
  --email user@example.com \
  --role admin
```

#### 4. Desativar Usuário
```bash
python -m core.cli user deactivate \
  --email user@example.com
```

### Roles e Permissões

#### Roles Disponíveis

**Admin**
- Acesso total ao sistema
- Gerenciamento de usuários
- Configuração do sistema
- Acesso aos logs e métricas

**Manager**
- Gerenciamento de alertas de equipe
- Exportação de relatórios avançados
- Visualização de métricas básicas

**User**
- Acesso básico ao sistema
- Criação de alertas pessoais
- Exportação de dados limitada

**Viewer**
- Acesso somente leitura
- Visualização de documentos
- Sem criação de alertas

#### Configuração de Permissões
```python
# Em core/auth/permissions.py
PERMISSIONS = {
    'admin': ['*'],
    'manager': [
        'documents:read',
        'documents:export',
        'alerts:manage_team',
        'reports:advanced'
    ],
    'user': [
        'documents:read',
        'documents:export_basic',
        'alerts:manage_own'
    ],
    'viewer': [
        'documents:read'
    ]
}
```

## Monitoramento e Alertas

### Métricas do Sistema

#### 1. Métricas da Aplicação
- **Request Rate**: Requisições por segundo
- **Response Time**: Tempo de resposta (p50, p95, p99)
- **Error Rate**: Taxa de erro por endpoint
- **Active Users**: Usuários ativos
- **Database Connections**: Conexões ativas

#### 2. Métricas de Infraestrutura
- **CPU Usage**: Uso de CPU por container
- **Memory Usage**: Uso de memória
- **Disk I/O**: Operações de disco
- **Network Traffic**: Tráfego de rede

#### 3. Métricas de Negócio
- **Documents Processed**: Documentos processados
- **Search Queries**: Consultas de busca
- **Alert Triggers**: Alertas disparados
- **Export Requests**: Solicitações de exportação

### Alertas Críticos

#### 1. Alertas de Sistema
```yaml
# Service Down
- alert: ServiceDown
  expr: up{job=~"api-service|web-service"} == 0
  for: 1m
  labels:
    severity: critical

# High Error Rate
- alert: HighErrorRate
  expr: rate(flask_http_request_exceptions_total[5m]) > 0.1
  for: 5m
  labels:
    severity: critical
```

#### 2. Alertas de Performance
```yaml
# High Memory Usage
- alert: HighMemoryUsage
  expr: (container_memory_usage_bytes / container_spec_memory_limit_bytes) > 0.9
  for: 10m
  labels:
    severity: warning

# Slow Response Time
- alert: SlowResponseTime
  expr: histogram_quantile(0.95, rate(flask_http_request_duration_seconds_bucket[5m])) > 2
  for: 10m
  labels:
    severity: warning
```

#### 3. Alertas de Negócio
```yaml
# Document Processing Stalled
- alert: DocumentProcessingStalled
  expr: rate(documents_processed_total[10m]) == 0
  for: 30m
  labels:
    severity: warning
```

### Logs e Auditoria

#### 1. Configuração de Logs
```python
# Configuração em core/utils/production_logger.py
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'class': 'core.utils.production_logger.JSONFormatter'
        }
    },
    'handlers': {
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'data/logs/monitor-legislativo.log',
            'maxBytes': 100*1024*1024,  # 100MB
            'backupCount': 10,
            'formatter': 'json'
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['file']
    }
}
```

#### 2. Consulta de Logs
```bash
# Logs em tempo real
tail -f data/logs/monitor-legislativo.log | jq '.'

# Filtrar por nível
grep '"level":"ERROR"' data/logs/monitor-legislativo.log

# Logs por usuário
grep '"user_id":"123"' data/logs/monitor-legislativo.log
```

#### 3. Auditoria de Ações
```bash
# Buscar ações de admin
grep '"event_type":"admin_action"' data/logs/monitor-legislativo.log

# Exportações realizadas
grep '"event_type":"export_request"' data/logs/monitor-legislativo.log
```

## Backup e Recuperação

### Estratégia de Backup

#### 1. Backup Automático
```bash
# Configurar cron job
0 2 * * * /opt/monitor-legislativo/scripts/backup.sh daily
0 2 * * 0 /opt/monitor-legislativo/scripts/backup.sh weekly
0 2 1 * * /opt/monitor-legislativo/scripts/backup.sh monthly
```

#### 2. Script de Backup
```bash
#!/bin/bash
# scripts/backup.sh

BACKUP_TYPE=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/data/backups/${BACKUP_TYPE}/${TIMESTAMP}"

mkdir -p $BACKUP_DIR

# Database backup
pg_dump $DATABASE_URL > $BACKUP_DIR/database.sql

# Files backup
tar -czf $BACKUP_DIR/files.tar.gz data/

# Configuration backup
cp -r configs/ $BACKUP_DIR/

# Upload to S3 (optional)
aws s3 sync $BACKUP_DIR s3://monitor-legislativo-backups/${BACKUP_TYPE}/${TIMESTAMP}
```

#### 3. Retenção de Backups
- **Diários**: 7 dias
- **Semanais**: 4 semanas
- **Mensais**: 12 meses
- **Anuais**: 7 anos

### Recuperação de Dados

#### 1. Restaurar Database
```bash
# Parar aplicação
docker-compose stop api-service

# Restaurar backup
psql $DATABASE_URL < backup/database.sql

# Reiniciar aplicação
docker-compose start api-service
```

#### 2. Recuperação de Arquivos
```bash
# Extrair backup de arquivos
tar -xzf backup/files.tar.gz -C /

# Verificar permissões
chown -R app:app data/
```

#### 3. Recuperação Completa
```bash
# Script de recuperação completa
./scripts/restore.sh /path/to/backup/20240115_020000
```

### Disaster Recovery

#### 1. RTO (Recovery Time Objective)
- **Crítico**: 1 hora
- **Alto**: 4 horas
- **Médio**: 24 horas

#### 2. RPO (Recovery Point Objective)
- **Database**: 15 minutos
- **Files**: 1 hora
- **Configurações**: 24 horas

#### 3. Plano de Contingência
1. Detectar falha
2. Ativar ambiente secundário
3. Restaurar últimos backups
4. Validar integridade
5. Redirecionar tráfego
6. Comunicar stakeholders

## Segurança

### Hardening do Sistema

#### 1. Sistema Operacional
```bash
# Atualizações de segurança
apt update && apt upgrade -y

# Configurar SSH
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart ssh

# Fail2ban
apt install fail2ban
systemctl enable fail2ban
```

#### 2. Docker Security
```dockerfile
# Usar imagens oficiais e atualizadas
FROM python:3.11-slim

# Usuário não-root
RUN addgroup --gid 1001 appuser && \
    adduser --uid 1001 --gid 1001 --disabled-password appuser

USER appuser

# Read-only filesystem
VOLUME ["/tmp", "/var/log"]
```

#### 3. Network Security
```yaml
# Kubernetes Network Policies
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: monitor-legislativo-network-policy
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 5000
```

### Monitoramento de Segurança

#### 1. Logs de Segurança
```python
# Em core/utils/production_logger.py
def log_security_event(event_type, user_id=None, ip_address=None, details=None):
    logger.warning(f"Security event: {event_type}", extra={
        'extra_fields': {
            'event_type': 'security_event',
            'security_event_type': event_type,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details
        }
    })
```

#### 2. Alertas de Segurança
```yaml
# Failed Login Attempts
- alert: FailedLoginAttempts
  expr: increase(authentication_failures_total[5m]) > 10
  for: 5m
  labels:
    severity: warning

# Security Event Spike
- alert: SecurityEventSpike
  expr: rate(security_events_total[5m]) > 0.5
  for: 5m
  labels:
    severity: warning
```

#### 3. Vulnerability Scanning
```bash
# Scan de containers
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image monitor-legislativo/api:latest

# Scan de dependências Python
pip install safety
safety check
```

### Compliance e Auditoria

#### 1. LGPD (Lei Geral de Proteção de Dados)
- Pseudonimização de dados pessoais
- Logs de acesso a dados sensíveis
- Direito ao esquecimento implementado
- Consentimento explícito para coleta

#### 2. Auditoria de Acesso
```sql
-- Query para auditoria de acessos
SELECT 
    user_id,
    action,
    resource,
    timestamp,
    ip_address
FROM audit_log 
WHERE timestamp >= NOW() - INTERVAL '30 days'
ORDER BY timestamp DESC;
```

## Performance e Otimização

### Otimização de Database

#### 1. Índices
```sql
-- Índices para performance
CREATE INDEX CONCURRENTLY idx_documents_created_at ON documents(created_at);
CREATE INDEX CONCURRENTLY idx_documents_type ON documents(type);
CREATE INDEX CONCURRENTLY idx_documents_search_gin ON documents USING gin(to_tsvector('portuguese', title || ' ' || content));
```

#### 2. Query Optimization
```python
# Use query optimization
from sqlalchemy.orm import joinedload

# Eager loading para evitar N+1
documents = session.query(Document)\
    .options(joinedload(Document.alerts))\
    .filter(Document.created_at >= last_week)\
    .all()
```

#### 3. Connection Pooling
```python
# Configuração otimizada
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=30,
    pool_timeout=30,
    pool_recycle=3600,
    pool_pre_ping=True
)
```

### Otimização de Cache

#### 1. Redis Configuration
```redis
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

#### 2. Cache Strategy
```python
# Multi-layer caching
@cache.memoize(timeout=3600)  # Redis cache
def get_documents_by_type(doc_type):
    return Document.query.filter_by(type=doc_type).all()

# Application-level cache
from functools import lru_cache

@lru_cache(maxsize=1000)
def expensive_calculation(params):
    # Expensive operation
    pass
```

### CDN e Static Assets

#### 1. CloudFront Configuration
```json
{
  "Origins": {
    "Items": [
      {
        "Id": "monitor-legislativo-static",
        "DomainName": "static.monitor-legislativo.gov.br",
        "OriginPath": "/static"
      }
    ]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "monitor-legislativo-static",
    "ViewerProtocolPolicy": "redirect-to-https",
    "CachePolicyId": "managed-caching-optimized"
  }
}
```

#### 2. Asset Optimization
```bash
# Compressão de assets
gzip -9 static/js/*.js
gzip -9 static/css/*.css

# Otimização de imagens
optipng static/images/*.png
jpegoptim --max=85 static/images/*.jpg
```

## Troubleshooting

### Problemas Comuns

#### 1. Alto Uso de Memória
```bash
# Identificar processos
docker stats

# Analisar heap (Python)
pip install memory_profiler
python -m memory_profiler app.py

# Ajustar limites
docker-compose up -d --memory=2g api-service
```

#### 2. Lentidão na Database
```sql
-- Queries lentas
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Locks
SELECT * FROM pg_locks 
WHERE NOT granted;

-- Reindex se necessário
REINDEX INDEX CONCURRENTLY idx_documents_search_gin;
```

#### 3. Problemas de Conectividade
```bash
# Teste de conectividade
curl -I http://localhost:5000/health

# DNS
nslookup monitor-legislativo.gov.br

# Portas
netstat -tulpn | grep :5000

# Logs de rede
tcpdump -i any port 5000
```

### Debugging

#### 1. Debug Mode
```python
# Habilitar apenas em desenvolvimento
if app.config['DEBUG']:
    app.logger.setLevel(logging.DEBUG)
    
# Debug específico
import pdb; pdb.set_trace()
```

#### 2. Profiling
```python
# Performance profiling
from werkzeug.middleware.profiler import ProfilerMiddleware
app.wsgi_app = ProfilerMiddleware(app.wsgi_app)

# Memory profiling
from memory_profiler import profile

@profile
def function_to_profile():
    pass
```

#### 3. Health Checks Detalhados
```python
@app.route('/health/detailed')
def detailed_health():
    checks = {
        'database': test_database_connection(),
        'redis': test_redis_connection(),
        'elasticsearch': test_elasticsearch_connection(),
        'external_apis': test_external_apis()
    }
    
    overall_health = all(checks.values())
    status_code = 200 if overall_health else 503
    
    return jsonify(checks), status_code
```

## Manutenção

### Atualizações do Sistema

#### 1. Processo de Atualização
```bash
# 1. Backup completo
./scripts/backup.sh pre-update

# 2. Atualizar código
git pull origin main

# 3. Atualizar dependências
pip install -r requirements.txt

# 4. Executar migrações
python -m core.database.migrations

# 5. Restart gradual
docker-compose restart api-service
```

#### 2. Rolling Updates (Kubernetes)
```bash
# Update image
kubectl set image deployment/api-service api=monitor-legislativo/api:v1.1.0

# Monitor rollout
kubectl rollout status deployment/api-service

# Rollback se necessário
kubectl rollout undo deployment/api-service
```

### Manutenção Preventiva

#### 1. Limpeza de Logs
```bash
# Rotacionar logs
logrotate /etc/logrotate.d/monitor-legislativo

# Limpar logs antigos
find data/logs/ -name "*.log" -mtime +30 -delete
```

#### 2. Limpeza de Cache
```bash
# Redis
redis-cli FLUSHALL

# Application cache
rm -rf data/cache/*
```

#### 3. Otimização de Database
```sql
-- Vacuum e analyze
VACUUM ANALYZE;

-- Reindex
REINDEX DATABASE monitor_legislativo;

-- Update statistics
ANALYZE;
```

### Planejamento de Capacidade

#### 1. Métricas de Crescimento
- Usuários ativos mensais
- Volume de documentos processados
- Requisições por minuto
- Tamanho do database

#### 2. Scaling Horizontal
```yaml
# HPA Configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

#### 3. Scaling Vertical
```bash
# Aumentar recursos
kubectl patch deployment api-service -p '{"spec":{"template":{"spec":{"containers":[{"name":"api","resources":{"requests":{"memory":"2Gi","cpu":"1000m"}}}]}}}}'
```

---

**Versão do Documento**: 1.0  
**Última Atualização**: Janeiro 2025  
**Próxima Revisão**: Abril 2025

Para dúvidas técnicas: tech@monitor-legislativo.gov.br