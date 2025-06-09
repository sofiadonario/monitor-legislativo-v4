# 🟡 HIGH-001: Default Docker Passwords in Compose Files

## 📊 Issue Details
- **Severity**: HIGH
- **CVSS Score**: 7.5
- **Category**: Configuration Security
- **Discovery Date**: 2025-06-09
- **Status**: OPEN

## 🎯 Summary
Default and weak passwords are hardcoded in Docker Compose configuration files, exposing database and service authentication.

## 📍 Location
**File**: `/docker-compose.yml`  
**Lines**: 15, 32, 45

## 🔍 Detailed Description
The Docker Compose configuration contains several default passwords that present security risks:

```yaml
# Line 15 - Redis Configuration
redis:
  environment:
    REDIS_PASSWORD: redis123  # ❌ Weak default password

# Line 32 - PostgreSQL Configuration  
postgres:
  environment:
    POSTGRES_PASSWORD: postgres  # ❌ Default PostgreSQL password
    POSTGRES_USER: postgres      # ❌ Default username

# Line 45 - Admin Interface
admin:
  environment:
    ADMIN_USER: admin     # ❌ Default admin username
    ADMIN_PASS: admin     # ❌ Default admin password
```

## 💥 Impact Assessment

### Security Risks:
1. **Unauthorized Database Access**: Default PostgreSQL credentials allow full database access
2. **Redis Compromise**: Weak Redis password enables data manipulation and DoS attacks  
3. **Admin Interface Breach**: Default admin credentials provide system-wide access
4. **Lateral Movement**: Compromised services can be used to access other components
5. **Data Exfiltration**: Access to legislative and transport regulation data

### Attack Scenarios:
- Network scanning discovering exposed services with default credentials
- Brute force attacks against weak passwords
- Container escape leading to host compromise
- Data tampering in government policy databases

## 🚨 Remediation Steps

### ⚡ Immediate Actions (0-4 hours):

1. **Generate Strong Passwords**:
   ```bash
   # Generate secure passwords
   REDIS_PASSWORD=$(openssl rand -base64 32)
   POSTGRES_PASSWORD=$(openssl rand -base64 32)  
   ADMIN_PASSWORD=$(openssl rand -base64 32)
   
   echo "Generated passwords (store securely):"
   echo "REDIS_PASSWORD=$REDIS_PASSWORD"
   echo "POSTGRES_PASSWORD=$POSTGRES_PASSWORD"
   echo "ADMIN_PASSWORD=$ADMIN_PASSWORD"
   ```

2. **Update Environment Configuration**:
   ```bash
   # Create .env file with secure passwords
   cat > .env << EOF
   # Database Configuration
   POSTGRES_USER=legislativo_user
   POSTGRES_PASSWORD=$POSTGRES_PASSWORD
   POSTGRES_DB=monitor_legislativo
   
   # Redis Configuration
   REDIS_PASSWORD=$REDIS_PASSWORD
   
   # Admin Configuration
   ADMIN_USER=admin_$(openssl rand -hex 4)
   ADMIN_PASSWORD=$ADMIN_PASSWORD
   EOF
   
   # Secure the .env file
   chmod 600 .env
   ```

3. **Update Docker Compose**:
   ```yaml
   # docker-compose.yml
   services:
     redis:
       environment:
         REDIS_PASSWORD: ${REDIS_PASSWORD}
     
     postgres:
       environment:
         POSTGRES_USER: ${POSTGRES_USER}
         POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
         POSTGRES_DB: ${POSTGRES_DB}
     
     admin:
       environment:
         ADMIN_USER: ${ADMIN_USER}
         ADMIN_PASSWORD: ${ADMIN_PASSWORD}
   ```

### 🛡️ Security Hardening (4-24 hours):

4. **Implement Secrets Management**:
   ```yaml
   # docker-compose.prod.yml
   version: '3.8'
   services:
     postgres:
       secrets:
         - postgres_password
       environment:
         POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
   
   secrets:
     postgres_password:
       external: true
       name: postgres_password_v1
   ```

5. **Add Network Security**:
   ```yaml
   # Restrict network access
   networks:
     internal:
       driver: bridge
       internal: true
     external:
       driver: bridge
   
   services:
     postgres:
       networks:
         - internal  # Database only on internal network
     
     api:
       networks:
         - internal
         - external  # API can access both networks
   ```

6. **Configure Connection Limits**:
   ```yaml
   postgres:
     command: |
       -c max_connections=20
       -c shared_buffers=256MB
       -c log_connections=on
       -c log_disconnections=on
   ```

### 🔐 Production Security (1-7 days):

7. **Implement Vault Integration**:
   ```bash
   # Install HashiCorp Vault sidecar
   docker run -d --name vault \
     --cap-add=IPC_LOCK \
     -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' \
     -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
     vault:latest
   ```

8. **Add Health Checks with Authentication**:
   ```yaml
   services:
     postgres:
       healthcheck:
         test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
         interval: 30s
         timeout: 10s
         retries: 3
   ```

## ✅ Verification Steps
- [ ] All default passwords replaced with strong generated passwords
- [ ] Environment variables properly configured in .env file
- [ ] Docker Compose files updated to use environment variables
- [ ] Network segmentation implemented
- [ ] Connection limits configured
- [ ] Health checks with authentication working
- [ ] Secrets management solution implemented

## 📋 Testing
```bash
# Test database connection with new credentials
docker-compose exec postgres psql -U ${POSTGRES_USER} -d ${POSTGRES_DB} -c "SELECT version();"

# Test Redis authentication
docker-compose exec redis redis-cli -a ${REDIS_PASSWORD} ping

# Verify admin interface access
curl -u ${ADMIN_USER}:${ADMIN_PASSWORD} http://localhost:8080/admin/health

# Test with old credentials (should fail)
docker-compose exec postgres psql -U postgres -d postgres -c "SELECT version();"
# Should return authentication error
```

## 🎯 Security Standards Compliance

### Minimum Password Requirements:
- ✅ **Length**: Minimum 16 characters
- ✅ **Complexity**: Mixed case, numbers, special characters  
- ✅ **Entropy**: Minimum 80 bits of entropy
- ✅ **Uniqueness**: Different passwords for each service
- ✅ **Rotation**: Automated password rotation every 90 days

### Docker Security Best Practices:
- ✅ **Non-root containers**: Run services as non-privileged users
- ✅ **Read-only filesystems**: Mount containers with read-only root
- ✅ **Resource limits**: Configure CPU and memory limits
- ✅ **Security scanning**: Regular vulnerability scans of images

## 📞 Related Issues
- Consider implementing: Secret rotation automation
- Consider implementing: Container runtime security monitoring
- Consider implementing: Network traffic monitoring between containers

## 🕐 Timeline
- **Discovery**: 2025-06-09 11:35:06
- **Patch Deployment**: Within 24 hours
- **Full Security Hardening**: Within 7 days
- **Security Review**: 2025-06-16

---

**⚠️ Priority: HIGH - Address before production deployment**