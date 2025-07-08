#!/bin/bash
# Automated backup script for Monitor Legislativo v4

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-monitor_legislativo_postgres}"
REDIS_CONTAINER="${REDIS_CONTAINER:-monitor_legislativo_redis}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "Starting backup process at $(date)"

# Database backup
echo "Backing up PostgreSQL database..."
docker exec "$POSTGRES_CONTAINER" pg_dumpall -U postgres | gzip > "$BACKUP_DIR/postgres_$TIMESTAMP.sql.gz"

# Redis backup
echo "Backing up Redis data..."
docker exec "$REDIS_CONTAINER" redis-cli BGSAVE
sleep 5  # Wait for background save to complete
docker cp "$REDIS_CONTAINER:/data/dump.rdb" "$BACKUP_DIR/redis_$TIMESTAMP.rdb"

# Application data backup
echo "Backing up application data..."
tar -czf "$BACKUP_DIR/app_data_$TIMESTAMP.tar.gz" \
    --exclude='*.log' \
    --exclude='temp/*' \
    logs/ exports/ data/

# Configuration backup
echo "Backing up configuration files..."
tar -czf "$BACKUP_DIR/config_$TIMESTAMP.tar.gz" \
    .env.production \
    docker-compose.production.yml \
    nginx/ \
    monitoring/

# Cleanup old backups
echo "Cleaning up backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "*.rdb" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete

# Create backup manifest
echo "Creating backup manifest..."
cat > "$BACKUP_DIR/manifest_$TIMESTAMP.txt" << EOF
Backup created: $(date)
PostgreSQL: postgres_$TIMESTAMP.sql.gz
Redis: redis_$TIMESTAMP.rdb
App Data: app_data_$TIMESTAMP.tar.gz
Config: config_$TIMESTAMP.tar.gz
EOF

# Calculate backup sizes
echo "Backup summary:"
du -sh "$BACKUP_DIR"/*_$TIMESTAMP.*

echo "Backup process completed at $(date)"

# Optional: Upload to cloud storage
if [ -n "$BACKUP_UPLOAD_ENABLED" ] && [ "$BACKUP_UPLOAD_ENABLED" = "true" ]; then
    echo "Uploading backups to cloud storage..."
    # Add your cloud storage upload commands here
    # aws s3 sync "$BACKUP_DIR" s3://your-backup-bucket/
fi