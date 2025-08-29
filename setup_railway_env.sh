#!/bin/bash

# Railway PostgreSQL Environment Setup Script
# ==========================================
# This script sets up the environment variables needed for the Railway PostgreSQL connection

echo "🔄 Setting up Railway PostgreSQL environment variables..."

# Set Railway PostgreSQL connection variables
export DATABASE_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
export PGHOST="nozomi.proxy.rlwy.net"
export PGPORT="44844"
export PGDATABASE="railway"
export PGUSER="postgres"
export PGPASSWORD="smNCedRjMKeNsoqpurLWXjGEUZxORwVY"

# For R connection
export R_DATABASE_URL="postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

echo "✅ Environment variables set:"
echo "   DATABASE_URL: $DATABASE_URL"
echo "   PGHOST: $PGHOST"
echo "   PGPORT: $PGPORT"
echo "   PGDATABASE: $PGDATABASE"
echo "   PGUSER: $PGUSER"
echo "   PGPASSWORD: [HIDDEN]"

echo ""
echo "🔧 To use these variables in your current session:"
echo "   source setup_railway_env.sh"
echo ""
echo "🔧 To run the import script:"
echo "   python3 railway_bulk_import.py --all"
echo ""
echo "🔧 To test connection:"
echo "   python3 test_railway_connection.py"