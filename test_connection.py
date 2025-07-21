#!/usr/bin/env python3
"""
Test database connection and provide detailed error information
"""

import socket
import sys

# Database connection details
HOST = "nozomi.proxy.rlwy.net"
PORT = 44844
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def test_tcp_connection():
    """Test basic TCP connection to the database host"""
    print("🔍 Testing TCP connection to database...")
    print(f"Host: {HOST}")
    print(f"Port: {PORT}")
    print("=" * 50)
    
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # 10 second timeout
        
        print("🔄 Attempting to connect...")
        result = sock.connect_ex((HOST, PORT))
        
        if result == 0:
            print("✅ TCP connection successful!")
            print("📊 Connection details:")
            print(f"   Local address: {sock.getsockname()}")
            print(f"   Remote address: {sock.getpeername()}")
            sock.close()
            return True
        else:
            print(f"❌ TCP connection failed with error code: {result}")
            print("📋 Possible issues:")
            print("   - Database server is down")
            print("   - Firewall blocking connection")
            print("   - Network connectivity issues")
            print("   - Railway service is experiencing problems")
            return False
            
    except socket.gaierror as e:
        print(f"❌ DNS resolution failed: {e}")
        return False
    except socket.timeout as e:
        print(f"❌ Connection timed out: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_dns_resolution():
    """Test DNS resolution"""
    print("\n🔍 Testing DNS resolution...")
    try:
        ip_address = socket.gethostbyname(HOST)
        print(f"✅ DNS resolution successful: {HOST} -> {ip_address}")
        return True
    except socket.gaierror as e:
        print(f"❌ DNS resolution failed: {e}")
        return False

def main():
    print("🚀 Database Connection Test")
    print("=" * 50)
    
    # Test DNS resolution
    dns_ok = test_dns_resolution()
    
    # Test TCP connection
    tcp_ok = test_tcp_connection()
    
    print("\n📊 Summary:")
    print(f"   DNS Resolution: {'✅' if dns_ok else '❌'}")
    print(f"   TCP Connection: {'✅' if tcp_ok else '❌'}")
    
    if not tcp_ok:
        print("\n💡 Recommendations:")
        print("   1. Check Railway dashboard for service status")
        print("   2. Verify the connection URL is still valid")
        print("   3. Try connecting from a different network")
        print("   4. Contact Railway support if the service is down")
        print("   5. Check if the database credentials have changed")
    
    return tcp_ok

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 