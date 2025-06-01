# Database Migration Strategy - Railway PostgreSQL to AWS RDS
## Monitor Legislativo v4 - Zero Downtime Migration

### Overview

This document outlines the comprehensive database migration strategy for moving Monitor Legislativo v4 from Railway PostgreSQL to AWS RDS PostgreSQL, ensuring zero data loss and minimal downtime for 278,152 legislative documents.

### Current Database Analysis

**Railway PostgreSQL Database:**
- **Version**: PostgreSQL 13.x
- **Size**: ~2.5GB (278,152 documents)
- **Schema**: Legislative documents with full-text search
- **Connections**: Connection pooling via R pool package
- **Performance**: Adequate for current load (<50 users)

**Key Tables:**
```sql
-- Primary documents table
documents (
  id SERIAL PRIMARY KEY,
  titulo TEXT NOT NULL,
  tipo VARCHAR(100),
  estado VARCHAR(2),
  data_publicacao DATE,
  conteudo TEXT,
  url TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Full-text search indexes
CREATE INDEX idx_documents_search_vector ON documents 
  USING gin(to_tsvector('portuguese', titulo || ' ' || conteudo));
```

### Target AWS RDS Configuration

**AWS RDS PostgreSQL:**
- **Version**: PostgreSQL 15.4 (latest stable)
- **Instance Class**: db.t3.small (2 vCPU, 2GB RAM)
- **Storage**: 100GB GP3 SSD (3000 IOPS baseline)
- **Multi-AZ**: Yes (High Availability)
- **Backup**: 7-day automated backups
- **Region**: sa-east-1 (São Paulo - LGPD compliance)

### Migration Strategy - Zero Downtime Approach

#### Phase 1: Preparation and Setup (Duration: 2-3 days)

**1.1 AWS RDS Instance Creation**
```bash
# Create RDS subnet group
aws rds create-db-subnet-group \
  --db-subnet-group-name monitor-legislativo-subnet-group \
  --db-subnet-group-description "Subnet group for Monitor Legislativo RDS" \
  --subnet-ids subnet-12345678 subnet-87654321 \
  --region sa-east-1

# Create RDS instance
aws rds create-db-instance \
  --db-instance-identifier monitor-legislativo-prod \
  --db-instance-class db.t3.small \
  --engine postgres \
  --engine-version 15.4 \
  --master-username postgres \
  --master-user-password $(aws secretsmanager get-secret-value --secret-id monitor-legislativo-db-prod --query SecretString --output text | jq -r .password) \
  --allocated-storage 100 \
  --storage-type gp3 \
  --storage-encrypted \
  --multi-az \
  --db-name monitor_legislativo \
  --vpc-security-group-ids sg-12345678 \
  --db-subnet-group-name monitor-legislativo-subnet-group \
  --backup-retention-period 7 \
  --monitoring-interval 60 \
  --monitoring-role-arn arn:aws:iam::ACCOUNT:role/rds-monitoring-role \
  --enable-performance-insights \
  --performance-insights-retention-period 7 \
  --region sa-east-1
```

**1.2 Database Schema Preparation**
```sql
-- Create optimized schema for AWS RDS
-- Enhanced with additional indexes for scalability

-- Main documents table with optimizations
CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  titulo TEXT NOT NULL,
  tipo VARCHAR(100) NOT NULL,
  estado VARCHAR(2),
  municipio VARCHAR(100),
  data_publicacao DATE NOT NULL,
  conteudo TEXT,
  url TEXT UNIQUE,
  hash_conteudo VARCHAR(64), -- SHA256 hash for duplicate detection
  metadata JSONB, -- Flexible metadata storage
  status VARCHAR(20) DEFAULT 'active',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Optimized indexes for 500+ concurrent users
CREATE INDEX CONCURRENTLY idx_documents_tipo_estado ON documents(tipo, estado);
CREATE INDEX CONCURRENTLY idx_documents_data_publicacao ON documents(data_publicacao DESC);
CREATE INDEX CONCURRENTLY idx_documents_estado ON documents(estado) WHERE estado IS NOT NULL;
CREATE INDEX CONCURRENTLY idx_documents_tipo ON documents(tipo);
CREATE INDEX CONCURRENTLY idx_documents_status ON documents(status);
CREATE INDEX CONCURRENTLY idx_documents_created_at ON documents(created_at DESC);

-- Full-text search with Portuguese configuration
CREATE INDEX CONCURRENTLY idx_documents_search_vector 
  ON documents USING gin(to_tsvector('portuguese', titulo || ' ' || COALESCE(conteudo, '')));

-- Metadata search index
CREATE INDEX CONCURRENTLY idx_documents_metadata ON documents USING gin(metadata);

-- Hash index for duplicate detection
CREATE UNIQUE INDEX CONCURRENTLY idx_documents_hash ON documents(hash_conteudo) 
  WHERE hash_conteudo IS NOT NULL;

-- User sessions table for analytics
CREATE TABLE user_sessions (
  id SERIAL PRIMARY KEY,
  session_id VARCHAR(100) NOT NULL,
  user_email VARCHAR(255),
  ip_address INET,
  user_agent TEXT,
  started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  ended_at TIMESTAMP WITH TIME ZONE,
  page_views INTEGER DEFAULT 0,
  searches INTEGER DEFAULT 0
);

CREATE INDEX idx_user_sessions_session_id ON user_sessions(session_id);
CREATE INDEX idx_user_sessions_started_at ON user_sessions(started_at DESC);

-- Audit log table for LGPD compliance
CREATE TABLE audit_log (
  id SERIAL PRIMARY KEY,
  table_name VARCHAR(100) NOT NULL,
  record_id INTEGER,
  action VARCHAR(20) NOT NULL, -- INSERT, UPDATE, DELETE, SELECT
  user_email VARCHAR(255),
  ip_address INET,
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  old_values JSONB,
  new_values JSONB
);

CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_table_record ON audit_log(table_name, record_id);
CREATE INDEX idx_audit_log_user ON audit_log(user_email);
```

**1.3 Performance Configuration**
```sql
-- PostgreSQL configuration for 500+ concurrent users
-- These settings will be applied via RDS parameter group

-- Connection settings
max_connections = 200
shared_preload_libraries = 'pg_stat_statements'

-- Memory settings
shared_buffers = 512MB -- 25% of 2GB RAM
effective_cache_size = 1536MB -- 75% of 2GB RAM
work_mem = 4MB
maintenance_work_mem = 64MB

-- Checkpoint settings
checkpoint_completion_target = 0.7
wal_buffers = 16MB
default_statistics_target = 100

-- Query performance
random_page_cost = 1.1 -- For SSD storage
effective_io_concurrency = 200

-- Brazilian Portuguese full-text search
default_text_search_config = 'portuguese'
```

#### Phase 2: Data Replication Setup (Duration: 1 day)

**2.1 Create Read Replica from Railway**
```bash
# Export Railway database
pg_dump --host=$RAILWAY_HOST \
        --port=$RAILWAY_PORT \
        --username=$RAILWAY_USER \
        --dbname=$RAILWAY_DB \
        --format=custom \
        --no-privileges \
        --no-owner \
        --verbose \
        --file=monitor_legislativo_backup_$(date +%Y%m%d_%H%M%S).dump

# Verify backup integrity
pg_restore --list monitor_legislativo_backup_*.dump | head -20

# Upload backup to S3 for secure transfer
aws s3 cp monitor_legislativo_backup_*.dump s3://monitor-legislativo-migration-bucket/
```

**2.2 Initial Data Load to AWS RDS**
```bash
# Restore to AWS RDS
pg_restore --host=$AWS_RDS_HOST \
           --port=5432 \
           --username=postgres \
           --dbname=monitor_legislativo \
           --no-privileges \
           --no-owner \
           --verbose \
           --jobs=4 \
           monitor_legislativo_backup_*.dump

# Verify data integrity
psql --host=$AWS_RDS_HOST \
     --port=5432 \
     --username=postgres \
     --dbname=monitor_legislativo \
     -c "SELECT COUNT(*) FROM documents; SELECT COUNT(DISTINCT tipo) FROM documents; SELECT MAX(created_at) FROM documents;"
```

**2.3 Set Up Real-time Synchronization**
```python
# Python script for real-time synchronization
import psycopg2
import time
import json
from datetime import datetime, timedelta

def sync_incremental_changes():
    """
    Synchronize incremental changes from Railway to AWS RDS
    """
    railway_conn = psycopg2.connect(
        host=os.environ['RAILWAY_HOST'],
        port=os.environ['RAILWAY_PORT'],
        database=os.environ['RAILWAY_DB'],
        user=os.environ['RAILWAY_USER'],
        password=os.environ['RAILWAY_PASSWORD']
    )
    
    aws_conn = psycopg2.connect(
        host=os.environ['AWS_RDS_HOST'],
        port=5432,
        database='monitor_legislativo',
        user='postgres',
        password=os.environ['AWS_RDS_PASSWORD']
    )
    
    # Get latest timestamp from AWS RDS
    aws_cursor = aws_conn.cursor()
    aws_cursor.execute("SELECT COALESCE(MAX(updated_at), '1970-01-01') FROM documents")
    last_sync = aws_cursor.fetchone()[0]
    
    # Get new/updated records from Railway
    railway_cursor = railway_conn.cursor()
    railway_cursor.execute("""
        SELECT id, titulo, tipo, estado, municipio, data_publicacao, 
               conteudo, url, created_at, updated_at
        FROM documents 
        WHERE updated_at > %s 
        ORDER BY updated_at ASC
    """, (last_sync,))
    
    records = railway_cursor.fetchall()
    
    # Sync to AWS RDS
    for record in records:
        aws_cursor.execute("""
            INSERT INTO documents (id, titulo, tipo, estado, municipio, 
                                 data_publicacao, conteudo, url, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                titulo = EXCLUDED.titulo,
                tipo = EXCLUDED.tipo,
                estado = EXCLUDED.estado,
                municipio = EXCLUDED.municipio,
                data_publicacao = EXCLUDED.data_publicacao,
                conteudo = EXCLUDED.conteudo,
                url = EXCLUDED.url,
                updated_at = EXCLUDED.updated_at
        """, record)
    
    aws_conn.commit()
    
    print(f"Synced {len(records)} records at {datetime.now()}")
    
    railway_conn.close()
    aws_conn.close()

# Run every 5 minutes during migration window
if __name__ == "__main__":
    while True:
        try:
            sync_incremental_changes()
            time.sleep(300)  # 5 minutes
        except Exception as e:
            print(f"Sync error: {e}")
            time.sleep(60)  # Retry in 1 minute
```

#### Phase 3: Application Configuration (Duration: 1 day)

**3.1 Update Application Configuration**
```yaml
# config.yml - Add AWS RDS configuration
production:
  database:
    primary:
      host: !expr Sys.getenv("AWS_RDS_HOST")
      port: 5432
      name: "monitor_legislativo"
      user: "postgres"
      password: !expr Sys.getenv("AWS_RDS_PASSWORD")
      ssl_mode: "require"
      pool_size: 20
      max_overflow: 30
      
    # Keep Railway as fallback during migration
    fallback:
      host: !expr Sys.getenv("RAILWAY_HOST")
      port: !expr Sys.getenv("RAILWAY_PORT")
      name: !expr Sys.getenv("RAILWAY_DB")
      user: !expr Sys.getenv("RAILWAY_USER")
      password: !expr Sys.getenv("RAILWAY_PASSWORD")
      ssl_mode: "require"
      pool_size: 5
```

**3.2 Enhanced Database Connection Code**
```r
# database.R - Enhanced connection with fallback
init_database_with_fallback <- function() {
  # Try AWS RDS first
  tryCatch({
    .db_pool <<- dbPool(
      drv = RPostgres::Postgres(),
      host = config::get("database")$primary$host,
      port = config::get("database")$primary$port,
      dbname = config::get("database")$primary$name,
      user = config::get("database")$primary$user,
      password = config::get("database")$primary$password,
      sslmode = config::get("database")$primary$ssl_mode,
      minSize = 2,
      maxSize = config::get("database")$primary$pool_size
    )
    
    # Test connection
    test_query <- dbGetQuery(.db_pool, "SELECT 1 as test")
    if (test_query$test == 1) {
      log_event("Successfully connected to AWS RDS PostgreSQL")
      return(TRUE)
    }
    
  }, error = function(e) {
    log_event(paste("AWS RDS connection failed:", e$message))
    
    # Fallback to Railway
    tryCatch({
      .db_pool <<- dbPool(
        drv = RPostgres::Postgres(),
        host = config::get("database")$fallback$host,
        port = config::get("database")$fallback$port,
        dbname = config::get("database")$fallback$name,
        user = config::get("database")$fallback$user,
        password = config::get("database")$fallback$password,
        sslmode = config::get("database")$fallback$ssl_mode,
        minSize = 1,
        maxSize = config::get("database")$fallback$pool_size
      )
      
      test_query <- dbGetQuery(.db_pool, "SELECT 1 as test")
      if (test_query$test == 1) {
        log_event("Fallback to Railway PostgreSQL successful")
        return(TRUE)
      }
      
    }, error = function(e2) {
      log_event(paste("Railway fallback also failed:", e2$message))
      return(FALSE)
    })
  })
}
```

#### Phase 4: Migration Execution (Duration: 4-6 hours)

**4.1 Pre-Migration Checklist**
```bash
#!/bin/bash
# pre-migration-checklist.sh

echo "=== Monitor Legislativo v4 - Pre-Migration Checklist ==="

# 1. Verify AWS RDS is ready
echo "1. Checking AWS RDS availability..."
aws rds describe-db-instances \
  --db-instance-identifier monitor-legislativo-prod \
  --query 'DBInstances[0].DBInstanceStatus' \
  --output text

# 2. Verify data synchronization
echo "2. Checking data synchronization..."
RAILWAY_COUNT=$(psql $RAILWAY_DATABASE_URL -t -c "SELECT COUNT(*) FROM documents")
AWS_COUNT=$(psql $AWS_RDS_URL -t -c "SELECT COUNT(*) FROM documents")

echo "Railway records: $RAILWAY_COUNT"
echo "AWS RDS records: $AWS_COUNT"

if [ "$RAILWAY_COUNT" -eq "$AWS_COUNT" ]; then
    echo "✓ Data synchronization verified"
else
    echo "✗ Data mismatch detected - aborting migration"
    exit 1
fi

# 3. Verify application health
echo "3. Checking application health..."
curl -f http://localhost:3838/health || {
    echo "✗ Application health check failed"
    exit 1
}

# 4. Create final backup
echo "4. Creating final backup..."
pg_dump $RAILWAY_DATABASE_URL --format=custom --file=final_backup_$(date +%Y%m%d_%H%M%S).dump

# 5. Notify stakeholders
echo "5. Sending migration start notification..."
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --subject "Migration Starting - Monitor Legislativo v4" \
  --message "Database migration from Railway to AWS RDS is starting. Expected duration: 4-6 hours."

echo "=== Pre-migration checklist completed successfully ==="
```

**4.2 Migration Execution Script**
```bash
#!/bin/bash
# execute-migration.sh

set -e  # Exit on any error

echo "=== Starting Monitor Legislativo v4 Database Migration ==="
echo "Start time: $(date)"

# Step 1: Stop incremental sync
echo "Step 1: Stopping incremental synchronization..."
pkill -f sync_incremental_changes.py || true

# Step 2: Final data sync
echo "Step 2: Performing final data synchronization..."
python3 final_sync.py

# Step 3: Verify final data consistency
echo "Step 3: Verifying final data consistency..."
python3 verify_data_consistency.py

# Step 4: Update application configuration
echo "Step 4: Updating application to use AWS RDS..."
export DATABASE_URL=$AWS_RDS_URL
export REDIS_URL=$AWS_REDIS_URL

# Step 5: Restart application with new configuration
echo "Step 5: Restarting application..."
# In production, this would be handled by ECS deployment
docker-compose down
docker-compose up -d

# Step 6: Verify application functionality
echo "Step 6: Verifying application functionality..."
sleep 60  # Wait for application to start

# Health check
curl -f http://localhost:3838/health || {
    echo "✗ Application health check failed - initiating rollback"
    rollback_migration.sh
    exit 1
}

# Functional test
python3 functional_tests.py || {
    echo "✗ Functional tests failed - initiating rollback"
    rollback_migration.sh
    exit 1
}

echo "Step 7: Migration completed successfully!"
echo "End time: $(date)"

# Notification
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --subject "Migration Completed - Monitor Legislativo v4" \
  --message "Database migration from Railway to AWS RDS completed successfully. Application is now running on AWS infrastructure."
```

#### Phase 5: Post-Migration Validation (Duration: 2 days)

**5.1 Data Validation Scripts**
```python
# validate_migration.py
import psycopg2
import os
import json
from datetime import datetime

def validate_data_integrity():
    """Comprehensive data validation after migration"""
    
    aws_conn = psycopg2.connect(os.environ['AWS_RDS_URL'])
    aws_cursor = aws_conn.cursor()
    
    validation_results = {}
    
    # Test 1: Record count validation
    aws_cursor.execute("SELECT COUNT(*) FROM documents")
    total_records = aws_cursor.fetchone()[0]
    validation_results['total_records'] = total_records
    print(f"✓ Total records in AWS RDS: {total_records}")
    
    # Test 2: Data type validation
    aws_cursor.execute("""
        SELECT COUNT(*) FROM documents 
        WHERE titulo IS NOT NULL 
        AND tipo IS NOT NULL 
        AND data_publicacao IS NOT NULL
    """)
    valid_records = aws_cursor.fetchone()[0]
    validation_results['valid_records'] = valid_records
    validation_results['data_quality_pct'] = (valid_records / total_records) * 100
    print(f"✓ Valid records: {valid_records} ({validation_results['data_quality_pct']:.1f}%)")
    
    # Test 3: Full-text search validation
    aws_cursor.execute("""
        SELECT COUNT(*) FROM documents 
        WHERE to_tsvector('portuguese', titulo || ' ' || COALESCE(conteudo, '')) IS NOT NULL
    """)
    searchable_records = aws_cursor.fetchone()[0]
    validation_results['searchable_records'] = searchable_records
    print(f"✓ Searchable records: {searchable_records}")
    
    # Test 4: Index validation
    aws_cursor.execute("""
        SELECT schemaname, tablename, indexname, indexdef 
        FROM pg_indexes 
        WHERE tablename = 'documents'
    """)
    indexes = aws_cursor.fetchall()
    validation_results['indexes_count'] = len(indexes)
    print(f"✓ Database indexes: {len(indexes)}")
    
    # Test 5: Performance test
    start_time = datetime.now()
    aws_cursor.execute("""
        SELECT COUNT(*) FROM documents 
        WHERE to_tsvector('portuguese', titulo || ' ' || COALESCE(conteudo, '')) 
        @@ plainto_tsquery('portuguese', 'legislação')
    """)
    search_results = aws_cursor.fetchone()[0]
    end_time = datetime.now()
    query_time = (end_time - start_time).total_seconds()
    validation_results['search_performance'] = {
        'results': search_results,
        'query_time_seconds': query_time
    }
    print(f"✓ Search performance: {search_results} results in {query_time:.3f} seconds")
    
    aws_conn.close()
    
    # Save validation report
    with open(f"migration_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
        json.dump(validation_results, f, indent=2, default=str)
    
    return validation_results

if __name__ == "__main__":
    results = validate_data_integrity()
    print("\n=== Migration Validation Completed ===")
    print(f"Total Records: {results['total_records']}")
    print(f"Data Quality: {results['data_quality_pct']:.1f}%")
    print(f"Search Performance: {results['search_performance']['query_time_seconds']:.3f}s")
```

**5.2 Performance Monitoring**
```sql
-- Performance monitoring queries for first 48 hours

-- Query performance analysis
SELECT 
  query,
  calls,
  total_time,
  mean_time,
  rows
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 20;

-- Connection monitoring
SELECT 
  count(*) as active_connections,
  state
FROM pg_stat_activity 
GROUP BY state;

-- Database size and growth
SELECT 
  pg_size_pretty(pg_database_size('monitor_legislativo')) as database_size,
  pg_size_pretty(pg_total_relation_size('documents')) as documents_table_size;

-- Index usage analysis
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_tup_read,
  idx_tup_fetch
FROM pg_stat_user_indexes 
WHERE tablename = 'documents'
ORDER BY idx_tup_read DESC;
```

### Rollback Strategy

**Emergency Rollback Procedure (if needed):**

```bash
#!/bin/bash
# rollback_migration.sh

echo "=== EMERGENCY ROLLBACK - Monitor Legislativo v4 ==="
echo "Rolling back to Railway PostgreSQL..."

# Step 1: Update environment variables to point back to Railway
export DATABASE_URL=$RAILWAY_DATABASE_URL
export REDIS_URL=$RAILWAY_REDIS_URL

# Step 2: Restart application with Railway configuration
docker-compose down
docker-compose up -d

# Step 3: Verify rollback
sleep 60
curl -f http://localhost:3838/health || {
    echo "✗ Rollback failed - manual intervention required"
    exit 1
}

echo "✓ Successfully rolled back to Railway infrastructure"

# Step 4: Notify stakeholders
aws sns publish \
  --topic-arn arn:aws:sns:sa-east-1:ACCOUNT:monitor-legislativo-alerts \
  --subject "ROLLBACK COMPLETED - Monitor Legislativo v4" \
  --message "Emergency rollback to Railway completed. Application is functional. AWS RDS migration will be reattempted after issue resolution."
```

### Success Criteria

**Migration is considered successful when:**

1. **Data Integrity**: 100% of records migrated with no data loss
2. **Performance**: Query response times <500ms for typical searches
3. **Functionality**: All application features working correctly
4. **Availability**: <5 minutes total downtime during migration
5. **Monitoring**: CloudWatch metrics showing healthy database performance
6. **Security**: All LGPD compliance requirements maintained

### Post-Migration Optimization

**Week 1 After Migration:**
- Monitor query performance and optimize slow queries
- Adjust connection pool settings based on usage patterns
- Fine-tune auto-scaling parameters
- Review and optimize database configuration parameters

**Week 2-4 After Migration:**
- Implement automated backup verification
- Set up read replicas if needed for reporting
- Optimize expensive queries identified through monitoring
- Document lessons learned and update procedures

This comprehensive migration strategy ensures a successful transition from Railway to AWS RDS while maintaining data integrity, minimizing downtime, and providing robust rollback capabilities.