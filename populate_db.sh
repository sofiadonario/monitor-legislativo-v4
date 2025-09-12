#!/bin/bash

echo "=== RAILWAY DATABASE POPULATION ==="
echo ""

# Set database credentials
export PGPASSWORD="smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
DB_HOST="postgres.railway.internal"
DB_PORT="5432"
DB_NAME="railway"
DB_USER="postgres"

echo "Testing connection to Railway PostgreSQL..."
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "SELECT version();" || {
    echo "Failed to connect using internal URL, trying external..."
    DB_HOST="nozomi.proxy.rlwy.net"
    DB_PORT="44844"
    psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "SELECT version();" || {
        echo "❌ Cannot connect to database"
        exit 1
    }
}

echo "✅ Connected to PostgreSQL"
echo ""

# Check if table exists and has data
COUNT=$(psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(*) FROM documents;" 2>/dev/null)

if [ $? -eq 0 ] && [ "$COUNT" -gt 100000 ]; then
    echo "✅ Database already has $COUNT documents"
    exit 0
fi

echo "Creating documents table..."
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME << 'EOF'
DROP TABLE IF EXISTS documents CASCADE;

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    estado VARCHAR(10),
    data DATE,
    categoria VARCHAR(100),
    tipo VARCHAR(100),
    ementa TEXT,
    autor TEXT,
    urn TEXT,
    assunto TEXT,
    texto TEXT,
    municipio VARCHAR(100),
    ano INTEGER,
    mes INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF

echo "Loading CSV data..."
CSV_FILE="data_current/processed/production/lexml_unified_dataset.csv"

if [ ! -f "$CSV_FILE" ]; then
    echo "❌ CSV file not found: $CSV_FILE"
    exit 1
fi

echo "Importing data (this will take a few minutes)..."
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "\COPY documents(titulo,estado,data,categoria,tipo,ementa,autor,urn) FROM '$CSV_FILE' WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '\"');"

echo "Creating indexes..."
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME << 'EOF'
CREATE INDEX idx_documents_titulo ON documents(titulo);
CREATE INDEX idx_documents_estado ON documents(estado);
CREATE INDEX idx_documents_data ON documents(data);
CREATE INDEX idx_documents_categoria ON documents(categoria);
EOF

# Verify
COUNT=$(psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -t -c "SELECT COUNT(*) FROM documents;")
echo ""
echo "🎉 DATABASE POPULATION COMPLETE!"
echo "✅ Total documents: $COUNT"