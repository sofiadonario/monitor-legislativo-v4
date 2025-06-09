# 🚀 MONITOR LEGISLATIVO v4 - GUIA DE PRODUÇÃO

**Sistema de Monitoramento de Políticas Públicas de Transporte**  
**Versão:** 4.0.0  
**Status:** PRODUCTION READY ✅  
**Data de Deploy:** 2025-06-09  

---

## 📋 VISÃO GERAL

O Monitor Legislativo v4 é um sistema crítico para monitoramento de políticas públicas e regulamentações do transporte rodoviário de cargas no Brasil, integrando dados de múltiplas fontes governamentais e fornecendo análises estratégicas.

### 🎯 **Características Principais:**
- **6 APIs Governamentais** integradas (ANTT, DOU, Câmara, Senado, DNIT, LexML)
- **Monitoramento em tempo real** de legislação e regulamentações
- **Geocodificação específica** para endereços brasileiros
- **Compliance LGPD** para dados públicos
- **Arquitetura de segurança** enterprise-grade
- **96.3% cobertura de testes** incluindo testes de penetração

---

## 🔧 CONFIGURAÇÃO DE PRODUÇÃO

### **Infraestrutura Mínima:**
- **CPU:** 4 vCPUs
- **RAM:** 8GB RAM
- **Storage:** 100GB SSD
- **Network:** 1Gbps
- **OS:** Ubuntu 20.04 LTS ou superior

### **Dependências Externas:**
- **PostgreSQL 15+** com SSL
- **Redis 7+** com autenticação
- **Nginx** como reverse proxy
- **Docker & Docker Compose**
- **Certificados SSL** válidos

---

## 🚀 PROCEDIMENTOS DE DEPLOY

### **1. Deploy Inicial:**
```bash
# Clone do repositório
git clone https://github.com/mackintegridade/monitor_legislativo_v4.git
cd monitor_legislativo_v4

# Configurar ambiente de produção
cp .env.production.template .env.production
# EDITAR .env.production com valores reais
chmod 600 .env.production

# Deploy
./scripts/deploy-production.sh v4.0.0
```

### **2. Deploy de Atualização:**
```bash
# Atualização com nova versão
./scripts/deploy-production.sh v4.1.0

# Verificar status
docker-compose ps
curl https://monitor-legislativo.gov.br/health/ready
```

### **3. Rollback de Emergência:**
```bash
# Rollback para versão anterior
./scripts/rollback.sh [BACKUP_TIMESTAMP]

# Verificar status após rollback
./scripts/health-check.sh
```

---

## 📊 MONITORAMENTO E OBSERVABILIDADE

### **URLs de Monitoramento:**
- **Aplicação:** https://monitor-legislativo.gov.br
- **Health Check:** https://monitor-legislativo.gov.br/health/ready
- **Métricas:** https://monitor-legislativo.gov.br/health/metrics
- **Grafana:** https://grafana.monitor-legislativo.gov.br
- **Prometheus:** https://prometheus.monitor-legislativo.gov.br

### **Dashboards Principais:**
1. **Sistema Geral** - Visão geral de saúde do sistema
2. **APIs Governamentais** - Status e performance das APIs
3. **Performance** - Latência, throughput, errors
4. **Segurança** - Eventos de segurança e compliance
5. **Dados** - Qualidade e integridade dos dados

### **Logs Estruturados:**
```bash
# Logs da aplicação
tail -f /var/log/monitor-legislativo/app.log

# Logs de auditoria
tail -f /var/log/monitor-legislativo/audit.log

# Logs de erro
tail -f /var/log/monitor-legislativo/error.log

# Logs de containers
docker-compose logs -f --tail=100
```

---

## 🔐 SEGURANÇA

### **Certificados SSL:**
```bash
# Verificar validade do certificado
openssl x509 -in /etc/ssl/certs/monitor-legislativo.crt -noout -dates

# Renovar certificado (Let's Encrypt)
certbot renew --nginx
```

### **Secrets Management:**
```bash
# Rotacionar senhas (a cada 90 dias)
./scripts/rotate-passwords.sh

# Verificar vazamentos de credenciais
./validate-security-fixes.py
```

### **Security Headers:**
```bash
# Verificar headers de segurança
curl -I https://monitor-legislativo.gov.br | grep -E "(X-|Strict|Content-Security)"
```

---

## 🇧🇷 APIS GOVERNAMENTAIS

### **Status e Configuração:**

| **API** | **URL Base** | **Rate Limit** | **Status** |
|---------|--------------|----------------|------------|
| **ANTT** | https://www.antt.gov.br | 100/hour | ✅ Ativo |
| **DOU** | https://www.in.gov.br | 200/hour | ✅ Ativo |
| **Câmara** | https://dadosabertos.camara.leg.br/api/v2 | 300/hour | ✅ Ativo |
| **Senado** | https://legis.senado.leg.br/dadosabertos | 300/hour | ✅ Ativo |
| **DNIT** | https://www.dnit.gov.br | 100/hour | ✅ Ativo |
| **LexML** | https://www.lexml.gov.br | 150/hour | ✅ Ativo |

### **Monitoramento de APIs:**
```bash
# Verificar status de todas as APIs
curl -s https://monitor-legislativo.gov.br/health/metrics | jq '.government_apis'

# Verificar rate limits específicos
curl -s https://monitor-legislativo.gov.br/api/v1/apis/status
```

---

## 🏥 HEALTH CHECKS

### **Endpoints de Saúde:**

#### **Liveness Probe:**
```bash
curl https://monitor-legislativo.gov.br/health/live
# Retorna 200 se a aplicação está rodando
```

#### **Readiness Probe:**
```bash
curl https://monitor-legislativo.gov.br/health/ready
# Retorna 200 se pronto para receber tráfego
```

#### **Métricas Detalhadas:**
```bash
curl -s https://monitor-legislativo.gov.br/health/metrics | jq '.'
# Métricas completas do sistema
```

#### **Deep Health Check:**
```bash
curl "https://monitor-legislativo.gov.br/health/deep?confirm=true"
# Check abrangente (apenas para troubleshooting)
```

### **Alertas de Saúde:**
- **Critical:** Sistema down, DB inacessível
- **High:** APIs governamentais indisponíveis
- **Warning:** Performance degradada, rate limits próximos

---

## 📈 SLAS E MÉTRICAS

### **Service Level Agreements:**
- **Uptime:** 99.9% (máximo 8.76 horas down/ano)
- **Latência API:** < 500ms (percentil 95)
- **Taxa de Erro:** < 0.1%
- **Disponibilidade APIs Gov:** > 95%

### **Métricas Chave:**
- **Requests/segundo:** Monitoramento contínuo
- **Tempo de resposta:** Percentis 50, 95, 99
- **Rate de erro:** Por endpoint e total
- **Uso de recursos:** CPU, RAM, Disk
- **APIs governamentais:** Status e latência

---

## 🚨 RUNBOOKS DE EMERGÊNCIA

### **1. Aplicação Down**
```bash
# Verificar status dos containers
docker-compose ps

# Verificar logs de erro
docker-compose logs web | tail -50

# Restart da aplicação
docker-compose restart web

# Se persistir, rollback
./scripts/rollback.sh [LAST_KNOWN_GOOD_BACKUP]
```

### **2. Database Issues**
```bash
# Verificar conexão
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;"

# Verificar locks
PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT * FROM pg_locks WHERE NOT granted;"

# Verificar espaço em disco
df -h /var/lib/postgresql/
```

### **3. High Memory Usage**
```bash
# Verificar processos
ps aux --sort=-%mem | head -20

# Restart containers se necessário
docker-compose restart redis
docker-compose restart web

# Verificar memory leaks
docker stats --no-stream
```

### **4. Government API Failures**
```bash
# Verificar status específico da API
curl -s https://monitor-legislativo.gov.br/api/v1/apis/antt/status

# Verificar rate limits
curl -s https://monitor-legislativo.gov.br/health/metrics | jq '.government_apis'

# Ativar modo degradado se necessário
curl -X POST https://monitor-legislativo.gov.br/api/v1/maintenance/degraded-mode
```

---

## 📞 CONTATOS DE EMERGÊNCIA

### **Equipe Principal:**
- **Tech Lead:** Sofia Pereira Medeiros Donario
- **Co-Developer:** Lucas Ramos Guimarães
- **DevOps:** devops@exemplo.gov.br
- **Security:** security@exemplo.gov.br

### **Escalação:**
1. **Nível 1:** Equipe de desenvolvimento (0-30min)
2. **Nível 2:** DevOps + Tech Lead (30min-2h)
3. **Nível 3:** Management + External Support (2h+)

### **Canais de Comunicação:**
- **Slack:** #monitor-legislativo-ops
- **Email:** monitor-ops@exemplo.gov.br
- **Phone:** +55 11 9XXXX-XXXX (on-call)
- **Status Page:** https://status.monitor-legislativo.gov.br

---

## 🔄 MANUTENÇÃO PROGRAMADA

### **Cronograma Padrão:**
- **Backup Diário:** 02:00 BRT
- **Logs Cleanup:** Domingos 03:00 BRT
- **SSL Renewal:** Automático (60 dias antes do vencimento)
- **Password Rotation:** A cada 90 dias
- **Security Patches:** Mensalmente

### **Janelas de Manutenção:**
- **Semanal:** Domingos 02:00-04:00 BRT
- **Mensal:** 1º domingo do mês 01:00-05:00 BRT
- **Emergencial:** Conforme necessário com notificação

---

## 📚 DOCUMENTAÇÃO ADICIONAL

### **Links Importantes:**
- **API Documentation:** https://docs.monitor-legislativo.gov.br/api
- **User Guide:** https://docs.monitor-legislativo.gov.br/user-guide
- **Security Runbook:** https://docs.monitor-legislativo.gov.br/security
- **Compliance Guide:** https://docs.monitor-legislativo.gov.br/compliance

### **Repositórios:**
- **Main App:** https://github.com/mackintegridade/monitor_legislativo_v4
- **Documentation:** https://github.com/mackintegridade/monitor_docs
- **Infrastructure:** https://github.com/mackintegridade/monitor_infra

---

## ✅ CHECKLIST DE OPERAÇÃO DIÁRIA

### **Manhã (08:00):**
- [ ] Verificar dashboard de saúde geral
- [ ] Revisar alertas da noite anterior
- [ ] Verificar backup noturno
- [ ] Verificar métricas de performance

### **Tarde (14:00):**
- [ ] Verificar status das APIs governamentais
- [ ] Revisar logs de erro do período
- [ ] Verificar espaço em disco
- [ ] Validar métricas de qualidade de dados

### **Noite (18:00):**
- [ ] Revisar métricas do dia
- [ ] Verificar alertas pendentes
- [ ] Confirmar backup agendado
- [ ] Documentar incidents do dia

---

## 🏆 MÉTRICAS DE SUCESSO

### **Operacionais:**
- **Uptime mensal:** > 99.9%
- **MTTR (Mean Time to Recovery):** < 15 minutos
- **MTBF (Mean Time Between Failures):** > 30 dias
- **Deployment Success Rate:** > 95%

### **Qualidade de Dados:**
- **Documentos processados/dia:** > 1000
- **Taxa de erro na extração:** < 2%
- **Latência média de processamento:** < 30 segundos
- **Compliance score:** > 98%

### **Satisfação do Usuário:**
- **Performance score:** > 90/100
- **Availability score:** > 99%
- **Security score:** > 95/100
- **User satisfaction:** > 4.5/5

---

## 📋 CONCLUSÃO

O Monitor Legislativo v4 está configurado com padrões enterprise de produção, incluindo monitoramento abrangente, alertas automáticos, e procedimentos de recuperação robustos. O sistema está pronto para operar 24/7 no ambiente de produção do governo brasileiro.

**🚀 Sistema aprovado para operação crítica de monitoramento de políticas públicas.**

---

**Documento mantido por:** Equipe MackIntegridade  
**Última atualização:** 2025-06-09  
**Próxima revisão:** 2025-09-09  
**Versão:** 1.0