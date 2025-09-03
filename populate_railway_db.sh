#!/bin/bash

# Railway PostgreSQL Population Script
echo "=== RAILWAY DATABASE POPULATION ==="

# Database connection details - external URL for access from outside Railway
DB_HOST="nozomi.proxy.rlwy.net"
DB_PORT="44844"
DB_NAME="railway"
DB_USER="postgres"
export PGPASSWORD="smNCedRjMKeNsoqpurLWXjGEUZxORwVY"

CSV_FILE="data_current/processed/production/lexml_unified_dataset.csv"

echo "🔌 Testing connection to Railway PostgreSQL..."
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "SELECT version();" || exit 1

echo "✅ Connected successfully!"
