# Database Optimization Guide
# Monitor Legislativo v4 - Phase 4 Week 14

## 🗄️ Overview

This guide covers comprehensive database optimization for Monitor Legislativo v4, including query tuning, advanced connection pooling, intelligent materialized view management, and disaster recovery procedures. The implementation provides production-grade database performance and reliability.

## 📋 Architecture Components

### Core Optimization Features
- **Advanced Query Optimization**: Comprehensive indexing strategy for Brazilian legislative data
- **Intelligent Connection Pooling**: Adaptive connection management with health monitoring
- **Materialized View Management**: Smart refresh strategies with dependency tracking
- **Disaster Recovery**: Automated backup system with point-in-time recovery
- **Performance Monitoring**: Real-time metrics and optimization recommendations

### Database Technologies
- **PostgreSQL 15+**: Production database with Portuguese language support
- **asyncpg**: High-performance async Python driver
- **pg_stat_statements**: Query performance monitoring
- **pg_trgm**: Fuzzy text search capabilities
- **WAL Archiving**: Point-in-time recovery support

## 🔧 Implementation Components

### 1. Schema Optimization
**File**: `database/schema-optimization.sql`

Key features:
- **Performance Indexes**: 25+ optimized indexes for Brazilian government data
- **Full-Text Search**: Portuguese language search with GIN indexes
- **JSONB Optimization**: Specialized indexes for metadata fields
- **Materialized Views**: Pre-computed aggregations for common queries
- **Performance Functions**: Smart search and aggregation functions

### 2. Connection Pool Management
**File**: `database/connection-pool-config.py`

Features:
- **Adaptive Pooling**: Dynamic connection scaling based on load
- **Health Monitoring**: Real-time pool metrics and health status
- **Query Tracking**: Performance monitoring with slow query detection
- **Failover Support**: Automatic connection recovery
- **Brazilian Optimizations**: Portuguese locale and timezone settings

### 3. Materialized View System
**File**: `database/materialized-view-manager.py`

Capabilities:
- **Smart Refresh**: Intelligent refresh scheduling based on data changes
- **Dependency Tracking**: Automatic view refresh based on table modifications
- **Performance Metrics**: View usage and refresh performance monitoring
- **Concurrent Refresh**: Non-blocking view updates
- **Priority Management**: Critical views refresh first

### 4. Backup & Recovery System
**File**: `database/backup-recovery.sh`

Features:
- **Automated Backups**: Full and incremental backup scheduling
- **Point-in-Time Recovery**: WAL-based recovery capabilities
- **Cloud Storage**: S3 integration for remote backup storage
- **Health Monitoring**: Backup validation and alerting
- **Disaster Recovery**: Complete restoration procedures

## 🚀 Performance Optimizations

### Index Strategy

#### Core Performance Indexes
```sql
-- Primary document indexes
CREATE INDEX CONCURRENTLY idx_documents_urn ON legislative_documents(urn);
CREATE INDEX CONCURRENTLY idx_documents_type_date ON legislative_documents(document_type, collected_at DESC);
CREATE INDEX CONCURRENTLY idx_documents_state ON legislative_documents((metadata->>'state'));

-- Full-text search indexes
CREATE INDEX CONCURRENTLY gin_content_search ON legislative_documents 
    USING GIN (to_tsvector('portuguese', content));
CREATE INDEX CONCURRENTLY trgm_title_idx ON legislative_documents 
    USING GIN (title gin_trgm_ops);

-- Transport-specific indexes
CREATE INDEX CONCURRENTLY idx_metadata_modal_transporte ON legislative_documents((metadata->>'modal_transporte'));
```

#### JSONB Metadata Optimization
```sql
-- Brazilian government data specific indexes
CREATE INDEX CONCURRENTLY idx_metadata_orgao ON legislative_documents((metadata->>'orgao'));
CREATE INDEX CONCURRENTLY idx_metadata_ano ON legislative_documents((metadata->>'ano'));
CREATE INDEX CONCURRENTLY idx_metadata_categoria ON legislative_documents((metadata->>'categoria'));
```

### Query Performance Functions

#### Intelligent Document Search
```sql
-- Smart search with ranking for Brazilian legislation
CREATE OR REPLACE FUNCTION search_documents_ranked(
    search_query TEXT,
    doc_types TEXT[] DEFAULT NULL,
    states TEXT[] DEFAULT NULL,
    limit_count INTEGER DEFAULT 50
) RETURNS TABLE (
    id BIGINT,
    title TEXT,
    rank REAL,
    headline TEXT
) LANGUAGE plpgsql;
```

#### Geographic Distribution Analysis
```sql
-- Document distribution by Brazilian states
CREATE OR REPLACE FUNCTION get_document_distribution_by_state()
RETURNS TABLE (
    state TEXT,
    document_count BIGINT,
    latest_document TIMESTAMP,
    transport_related BIGINT
) LANGUAGE sql STABLE;
```

### Materialized Views

#### Document Statistics View
```sql
CREATE MATERIALIZED VIEW mv_document_statistics AS
SELECT 
    document_type,
    DATE_TRUNC('month', collected_at) as month,
    metadata->>'state' as state,
    COUNT(*) as document_count,
    AVG(LENGTH(content)) as avg_content_length
FROM legislative_documents 
GROUP BY document_type, DATE_TRUNC('month', collected_at), metadata->>'state';
```

#### Transport Legislation Summary
```sql
CREATE MATERIALIZED VIEW mv_transport_summary AS
SELECT 
    metadata->>'modal_transporte' as transport_modal,
    metadata->>'state' as state,
    document_type,
    COUNT(*) as document_count,
    STRING_AGG(DISTINCT metadata->>'orgao', ', ') as source_organs
FROM legislative_documents 
WHERE metadata->>'modal_transporte' IS NOT NULL
GROUP BY metadata->>'modal_transporte', metadata->>'state', document_type;
```

## 🔗 Connection Pool Configuration

### Adaptive Pool Settings
```python
config = ConnectionConfig(
    min_size=5,                    # Minimum connections
    max_size=20,                   # Maximum connections  
    max_queries=50000,             # Queries per connection
    max_inactive_connection_lifetime=300.0,  # 5 minutes
    command_timeout=60.0,          # Query timeout
    slow_query_threshold=1.0       # Slow query detection
)
```

### Brazilian Database Optimizations
```python
# Connection initialization for Brazilian data
await conn.execute("SET TIME ZONE 'America/Sao_Paulo'")
await conn.execute("SET default_text_search_config = 'portuguese'")
await conn.execute("SET lc_messages = 'pt_BR.UTF-8'")
await conn.execute("SET DateStyle = 'ISO, DMY'")

# Performance optimizations
await conn.execute("SET random_page_cost = 1.1")  # SSD optimization
await conn.execute("SET effective_cache_size = '1GB'")
await conn.execute("SET work_mem = '4MB'")
```

### Health Monitoring
```python
# Real-time pool metrics
@dataclass
class PoolMetrics:
    total_connections: int
    active_connections: int
    idle_connections: int
    total_queries: int
    slow_queries: int
    failed_queries: int
    avg_query_time: float
    pool_health: PoolHealth
```

## 📊 Materialized View Management

### Smart Refresh Strategies
```python
class RefreshStrategy(Enum):
    IMMEDIATE = "immediate"    # Refresh on data changes
    SCHEDULED = "scheduled"    # Fixed schedule refresh
    THRESHOLD = "threshold"    # Change count trigger
    SMART = "smart"           # Usage-based refresh
    MANUAL = "manual"         # Manual only
```

### View Definitions for Monitor Legislativo v4
```python
# Document statistics - high priority, frequent updates
ViewDefinition(
    name="mv_document_statistics",
    dependencies=["legislative_documents"],
    refresh_strategy=RefreshStrategy.THRESHOLD,
    refresh_interval=timedelta(minutes=30),
    threshold_changes=50,
    priority=1
)

# Transport summary - medium priority
ViewDefinition(
    name="mv_transport_summary", 
    dependencies=["legislative_documents"],
    refresh_strategy=RefreshStrategy.SCHEDULED,
    refresh_interval=timedelta(hours=2),
    priority=2
)
```

### Dependency Tracking
```python
# Automatic refresh based on table changes
async def record_table_change(self, table_name: str, change_count: int = 1):
    if table_name in self.change_counters:
        self.change_counters[table_name] += change_count
        
        # Trigger immediate refresh for IMMEDIATE strategy views
        for view_name, view_def in self.views.items():
            if (view_def.refresh_strategy == RefreshStrategy.IMMEDIATE and
                table_name in view_def.dependencies):
                await self.refresh_view(view_name, background=True)
```

## 💾 Backup and Recovery System

### Automated Backup Strategy
```bash
# Full backup (daily)
./database/backup-recovery.sh backup-full

# Incremental backup (every 6 hours)  
./database/backup-recovery.sh backup-incremental

# Schema backup (weekly)
./database/backup-recovery.sh backup-schema
```

### Point-in-Time Recovery Setup
```sql
-- PostgreSQL configuration for PITR
wal_level = replica
archive_mode = on
archive_command = 'cp %p /var/backups/monitor-legislativo/wal/%f'
archive_timeout = 300  # 5 minutes

# Recovery configuration
restore_command = 'cp /var/backups/monitor-legislativo/wal/%f %p'
recovery_target_timeline = 'latest'
```

### Backup Validation
```bash
# Automated backup integrity testing
validate_backup() {
    local backup_file="$1"
    
    # Checksum verification
    local stored_checksum=$(jq -r '.checksum' "$metadata_file")
    local actual_checksum=$(openssl dgst -sha256 "$backup_file" | awk '{print $2}')
    
    # Test restore to temporary database
    local test_db="test_restore_$(date +%s)"
    createdb "$test_db"
    pg_restore -d "$test_db" "$backup_file"
    
    # Verify table count and data integrity
    local table_count=$(psql -d "$test_db" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")
}
```

### Cloud Storage Integration
```bash
# S3 backup upload
upload_to_s3() {
    local local_file="$1"
    local s3_key="$2"
    
    aws s3 cp "$local_file" "s3://$S3_BUCKET/$s3_key" \
        --region "$S3_REGION" \
        --storage-class STANDARD_IA
}
```

## 🎯 Performance Targets

### Database Performance Metrics
- **Query Response Time**: <100ms for cached queries, <1s for complex searches
- **Connection Pool Utilization**: 60-80% optimal range
- **Index Hit Ratio**: >95% for primary indexes
- **Full-Text Search**: <500ms for Portuguese text search
- **Materialized View Refresh**: <30s for statistics views

### Backup Performance Targets
- **Full Backup Time**: <10 minutes for databases up to 10GB
- **Incremental Backup**: <2 minutes with WAL archiving
- **Recovery Time**: <15 minutes for full database restore
- **Backup Validation**: 100% integrity verification
- **Remote Storage**: <5 minutes upload to S3

## 📈 Monitoring and Metrics

### Database Performance Views
```sql
-- Slow query monitoring
CREATE VIEW v_slow_queries AS
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements 
WHERE total_time > 1000
ORDER BY total_time DESC;

-- Index usage statistics  
CREATE VIEW v_index_usage AS
SELECT schemaname, tablename, indexname, idx_scan,
    CASE 
        WHEN idx_scan = 0 THEN 'unused'
        WHEN idx_scan < 10 THEN 'rarely_used'
        ELSE 'active'
    END as usage_status
FROM pg_stat_user_indexes;
```

### Connection Pool Monitoring
```python
async def get_pool_stats(self) -> Dict[str, Any]:
    return {
        "pool_metrics": self.metrics.to_dict(),
        "performance": {
            "avg_query_time_ms": round(self.metrics.avg_query_time * 1000, 2),
            "utilization_percent": round(
                (self.metrics.active_connections / max(self.metrics.total_connections, 1)) * 100, 1
            )
        },
        "database_stats": {
            "active_db_connections": active_conns,
            "database_size": db_size
        }
    }
```

### Backup Health Monitoring
```bash
# Backup health report generation
monitor_backup_health() {
    local health_status="healthy"
    local issues=()
    
    # Check backup age
    if [[ $full_age_hours -gt 168 ]]; then  # 1 week
        health_status="critical"
        issues+=("Full backup is over 1 week old")
    fi
    
    # Generate JSON report
    cat > "$report_file" << EOF
{
    "health_status": "$health_status",
    "issues": $(printf '%s\n' "${issues[@]}" | jq -R . | jq -s .),
    "statistics": {
        "full_backups_count": $full_backups,
        "full_backup_age_hours": $full_age_hours
    }
}
EOF
}
```

## 🔧 Deployment and Usage

### Database Schema Setup
```bash
# Apply schema optimizations
psql -d monitor_legislativo -f database/schema-optimization.sql

# Verify indexes created
psql -d monitor_legislativo -c "\di"

# Check materialized views
psql -d monitor_legislativo -c "\dm"
```

### Connection Pool Integration
```python
# Initialize optimized connection pool
from database.connection_pool_config import create_optimized_pool

# Create pool with Brazilian settings
pool = await create_optimized_pool(
    database_url="postgresql://user:pass@localhost/monitor_legislativo"
)

# Use pool in application
async with pool.acquire_connection() as conn:
    results = await conn.fetch("SELECT * FROM legislative_documents WHERE metadata->>'state' = $1", "SP")
```

### Materialized View Management
```python
# Initialize view manager
from database.materialized_view_manager import create_view_manager

manager = await create_view_manager(connection_pool)

# Manual refresh of specific view
result = await manager.refresh_view("mv_document_statistics")

# Get view status
status = await manager.get_view_status("mv_transport_summary")

# Automatic optimization recommendations
recommendations = await manager.optimize_refresh_schedule()
```

### Backup Automation
```bash
# Setup automated backups via cron
# Daily full backup at 2 AM
0 2 * * * /path/to/backup-recovery.sh backup-full

# Incremental backup every 6 hours
0 */6 * * * /path/to/backup-recovery.sh backup-incremental

# Weekly cleanup
0 3 * * 0 /path/to/backup-recovery.sh cleanup

# Health monitoring
0 6 * * * /path/to/backup-recovery.sh health
```

## 🚨 Troubleshooting

### Common Performance Issues

1. **Slow Full-Text Search**
```sql
-- Check if Portuguese text search is properly configured
SHOW default_text_search_config;

-- Verify GIN indexes exist
SELECT indexname FROM pg_indexes WHERE indexname LIKE '%gin%';

-- Rebuild text search indexes if needed
REINDEX INDEX gin_content_search;
```

2. **Connection Pool Exhaustion**
```python
# Check pool status
stats = await pool.get_pool_stats()
print(f"Utilization: {stats['performance']['utilization_percent']}%")

# Optimize pool settings
if stats['performance']['utilization_percent'] > 80:
    config.max_size = min(config.max_size + 5, 50)
```

3. **Materialized View Staleness**
```python
# Check view staleness
status = await manager.get_view_status()
for view_name, view_info in status.items():
    staleness = view_info['metrics']['staleness_score']
    if staleness > 0.7:
        await manager.refresh_view(view_name)
```

### Backup Recovery Issues
```bash
# Test backup integrity
./database/backup-recovery.sh validate /path/to/backup.sql

# Restore to test database
./database/backup-recovery.sh restore /path/to/backup.sql test_restore

# Check backup health
./database/backup-recovery.sh health
```

## 📋 Maintenance Tasks

### Daily Operations
```bash
# Monitor database performance
psql -c "SELECT * FROM v_slow_queries LIMIT 10;"

# Check connection pool health
curl http://localhost:8000/api/v1/health/database

# Verify backup completion
./database/backup-recovery.sh health
```

### Weekly Maintenance
```bash
# Database maintenance
psql -c "SELECT maintain_database_health();"

# Refresh all materialized views
psql -c "SELECT refresh_all_materialized_views();"

# Cleanup old backups
./database/backup-recovery.sh cleanup

# Performance optimization review
psql -c "SELECT * FROM v_index_usage WHERE usage_status = 'unused';"
```

### Monthly Optimization
```bash
# Analyze database statistics
psql -c "ANALYZE;"

# Review and optimize materialized view schedules
python -c "
import asyncio
from database.materialized_view_manager import create_view_manager
from database.connection_pool_config import get_connection_pool

async def optimize():
    pool = await get_connection_pool()
    manager = await create_view_manager(pool)
    report = await manager.optimize_refresh_schedule()
    print(json.dumps(report, indent=2))

asyncio.run(optimize())
"

# Database size and growth analysis
psql -c "SELECT * FROM v_table_sizes;"
```

---

**Next Phase**: Week 15 - Monitoring & Alerting with comprehensive application monitoring, log aggregation, and performance dashboards.

**Last Updated**: Phase 4 Week 14  
**Production Ready**: ✅ Query optimization, connection pooling, materialized views, backup/recovery  
**Performance Targets**: <100ms queries, >95% index hit ratio, <30s view refresh