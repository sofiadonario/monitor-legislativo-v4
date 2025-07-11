#!/bin/bash
# SSL Certificate Generation Script
# Monitor Legislativo v4 - Production SSL Setup
# Phase 4 Week 13: SSL termination and security

set -euo pipefail

# Configuration
DOMAIN="monitor-legislativo.com"
COUNTRY="BR"
STATE="SP"
CITY="São Paulo"
ORG="MackIntegridade"
OU="Academic Research"
EMAIL="admin@monitor-legislativo.com"
SSL_DIR="/etc/nginx/ssl"
CERT_VALIDITY=365

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for production SSL setup"
        exit 1
    fi
}

# Create SSL directory
create_ssl_directory() {
    log_info "Creating SSL directory: $SSL_DIR"
    mkdir -p "$SSL_DIR"
    chmod 755 "$SSL_DIR"
}

# Generate strong Diffie-Hellman parameters
generate_dhparam() {
    local dhparam_file="$SSL_DIR/dhparam.pem"
    
    if [[ -f "$dhparam_file" ]]; then
        log_warn "DH parameters already exist at $dhparam_file"
        return 0
    fi
    
    log_info "Generating Diffie-Hellman parameters (this may take several minutes)..."
    openssl dhparam -out "$dhparam_file" 2048
    chmod 644 "$dhparam_file"
    log_info "DH parameters generated successfully"
}

# Generate self-signed certificate for development/staging
generate_self_signed() {
    local cert_file="$SSL_DIR/monitor-legislativo.crt"
    local key_file="$SSL_DIR/monitor-legislativo.key"
    local csr_file="$SSL_DIR/monitor-legislativo.csr"
    
    log_info "Generating self-signed SSL certificate for development..."
    
    # Generate private key
    openssl genrsa -out "$key_file" 2048
    chmod 600 "$key_file"
    
    # Generate certificate signing request
    openssl req -new -key "$key_file" -out "$csr_file" -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/OU=$OU/CN=$DOMAIN/emailAddress=$EMAIL"
    
    # Generate self-signed certificate
    openssl x509 -req -in "$csr_file" -signkey "$key_file" -out "$cert_file" -days $CERT_VALIDITY \
        -extensions v3_req -extfile <(
        echo "[v3_req]"
        echo "basicConstraints = CA:FALSE"
        echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment"
        echo "subjectAltName = @alt_names"
        echo "[alt_names]"
        echo "DNS.1 = $DOMAIN"
        echo "DNS.2 = www.$DOMAIN"
        echo "DNS.3 = localhost"
        echo "IP.1 = 127.0.0.1"
    )
    
    chmod 644 "$cert_file"
    
    # Clean up CSR
    rm -f "$csr_file"
    
    log_info "Self-signed certificate generated successfully"
    log_info "Certificate: $cert_file"
    log_info "Private key: $key_file"
}

# Generate Let's Encrypt certificate using Certbot
generate_letsencrypt() {
    local domain_flag="-d $DOMAIN -d www.$DOMAIN"
    
    log_info "Setting up Let's Encrypt certificate..."
    
    # Check if certbot is installed
    if ! command -v certbot &> /dev/null; then
        log_info "Installing certbot..."
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
        elif command -v yum &> /dev/null; then
            yum install -y certbot python3-certbot-nginx
        else
            log_error "Package manager not supported. Please install certbot manually."
            exit 1
        fi
    fi
    
    # Stop nginx temporarily for standalone mode
    systemctl stop nginx || true
    
    # Generate certificate
    certbot certonly --standalone \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        $domain_flag \
        --preferred-challenges http \
        --http-01-port 80
    
    # Copy certificates to our SSL directory
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/monitor-legislativo.crt"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/monitor-legislativo.key"
    
    # Set proper permissions
    chmod 644 "$SSL_DIR/monitor-legislativo.crt"
    chmod 600 "$SSL_DIR/monitor-legislativo.key"
    
    log_info "Let's Encrypt certificate generated successfully"
}

# Setup automatic renewal for Let's Encrypt
setup_auto_renewal() {
    log_info "Setting up automatic certificate renewal..."
    
    # Create renewal script
    cat > /usr/local/bin/renew-ssl.sh << 'EOF'
#!/bin/bash
# Auto-renewal script for Monitor Legislativo SSL certificates

DOMAIN="monitor-legislativo.com"
SSL_DIR="/etc/nginx/ssl"

# Renew certificate
certbot renew --quiet

# Copy renewed certificates
if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
    cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$SSL_DIR/monitor-legislativo.crt"
    cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$SSL_DIR/monitor-legislativo.key"
    
    # Test nginx configuration
    if nginx -t; then
        systemctl reload nginx
        echo "SSL certificates renewed and nginx reloaded successfully"
    else
        echo "ERROR: nginx configuration test failed after certificate renewal"
        exit 1
    fi
fi
EOF
    
    chmod +x /usr/local/bin/renew-ssl.sh
    
    # Add to crontab (run twice daily)
    (crontab -l 2>/dev/null; echo "0 12,0 * * * /usr/local/bin/renew-ssl.sh >> /var/log/ssl-renewal.log 2>&1") | crontab -
    
    log_info "Auto-renewal setup complete"
}

# Verify SSL configuration
verify_ssl() {
    local cert_file="$SSL_DIR/monitor-legislativo.crt"
    local key_file="$SSL_DIR/monitor-legislativo.key"
    
    log_info "Verifying SSL configuration..."
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate file not found: $cert_file"
        exit 1
    fi
    
    if [[ ! -f "$key_file" ]]; then
        log_error "Private key file not found: $key_file"
        exit 1
    fi
    
    # Check certificate validity
    cert_info=$(openssl x509 -in "$cert_file" -noout -text)
    expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
    
    log_info "Certificate information:"
    echo "  Subject: $(openssl x509 -in "$cert_file" -noout -subject | cut -d= -f2-)"
    echo "  Issuer: $(openssl x509 -in "$cert_file" -noout -issuer | cut -d= -f2-)"
    echo "  Expiry: $expiry_date"
    
    # Verify private key matches certificate
    cert_hash=$(openssl x509 -noout -modulus -in "$cert_file" | openssl md5)
    key_hash=$(openssl rsa -noout -modulus -in "$key_file" | openssl md5)
    
    if [[ "$cert_hash" == "$key_hash" ]]; then
        log_info "Certificate and private key match"
    else
        log_error "Certificate and private key do not match!"
        exit 1
    fi
    
    log_info "SSL verification completed successfully"
}

# Test nginx configuration
test_nginx_config() {
    log_info "Testing nginx configuration..."
    
    if nginx -t; then
        log_info "nginx configuration test passed"
    else
        log_error "nginx configuration test failed"
        exit 1
    fi
}

# Main function
main() {
    local cert_type="${1:-self-signed}"
    
    log_info "Starting SSL setup for Monitor Legislativo v4"
    log_info "Certificate type: $cert_type"
    
    # Only check root for production certificates
    if [[ "$cert_type" == "letsencrypt" ]]; then
        check_root
    fi
    
    create_ssl_directory
    generate_dhparam
    
    case "$cert_type" in
        "self-signed")
            generate_self_signed
            ;;
        "letsencrypt")
            generate_letsencrypt
            setup_auto_renewal
            ;;
        *)
            log_error "Invalid certificate type. Use 'self-signed' or 'letsencrypt'"
            exit 1
            ;;
    esac
    
    verify_ssl
    
    log_info "SSL setup completed successfully!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Update your nginx configuration to use the generated certificates"
    log_info "2. Test the configuration: nginx -t"
    log_info "3. Reload nginx: systemctl reload nginx"
    
    if [[ "$cert_type" == "letsencrypt" ]]; then
        log_info "4. Verify auto-renewal: certbot renew --dry-run"
    fi
}

# Help function
show_help() {
    cat << EOF
SSL Certificate Generation Script for Monitor Legislativo v4

Usage: $0 [CERT_TYPE]

CERT_TYPE:
    self-signed   Generate self-signed certificate for development (default)
    letsencrypt   Generate Let's Encrypt certificate for production

Examples:
    $0                    # Generate self-signed certificate
    $0 self-signed        # Generate self-signed certificate
    $0 letsencrypt        # Generate Let's Encrypt certificate (requires root)

Requirements for Let's Encrypt:
    - Root privileges
    - Domain pointing to this server
    - Port 80 accessible from internet
    - certbot installed (will be installed automatically)

EOF
}

# Script entry point
if [[ "$#" -gt 1 ]]; then
    show_help
    exit 1
fi

if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

main "${1:-self-signed}"