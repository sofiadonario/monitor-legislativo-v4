#!/bin/bash
# SSL Certificate Generation Script for Monitor Legislativo v4

set -e

DOMAIN=${1:-monitor-legislativo.local}
SSL_DIR="./nginx/ssl"
DAYS=${2:-365}

echo "Generating SSL certificates for domain: $DOMAIN"

# Create SSL directory if it doesn't exist
mkdir -p "$SSL_DIR"

# Generate private key
openssl genrsa -out "$SSL_DIR/key.pem" 2048

# Generate certificate signing request
openssl req -new -key "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.csr" -subj "/C=BR/ST=SP/L=Sao Paulo/O=Monitor Legislativo/OU=IT Department/CN=$DOMAIN"

# Generate self-signed certificate
openssl x509 -req -in "$SSL_DIR/cert.csr" -signkey "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" -days "$DAYS" -extensions v3_req -extfile <(cat <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = www.$DOMAIN
DNS.3 = localhost
IP.1 = 127.0.0.1
EOF
)

# Set proper permissions
chmod 600 "$SSL_DIR/key.pem"
chmod 644 "$SSL_DIR/cert.pem"

# Clean up CSR
rm "$SSL_DIR/cert.csr"

echo "SSL certificates generated successfully!"
echo "Certificate: $SSL_DIR/cert.pem"
echo "Private key: $SSL_DIR/key.pem"
echo "Valid for $DAYS days"

# Display certificate information
echo -e "\nCertificate information:"
openssl x509 -in "$SSL_DIR/cert.pem" -text -noout | grep -E "(Subject:|DNS:|IP Address:|Not Before:|Not After:)"