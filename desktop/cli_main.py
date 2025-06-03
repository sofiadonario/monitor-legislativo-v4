#!/usr/bin/env python3
"""
Monitor Legislativo CLI Application
Command-line interface version for environments without GUI support

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def print_header():
    """Print application header with branding"""
    print("=" * 70)
    print("🏛️  MONITOR LEGISLATIVO V4 - CLI")
    print("📋 Legislative Monitoring & Analysis System")
    print("")
    print("👨‍💻 Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães")
    print("🏢 Organization: MackIntegridade")
    print("💰 Financing: MackPesquisa")
    print("🎨 Brand Color: #e1001e")
    print("=" * 70)

def show_main_menu():
    """Display main application menu"""
    print("\n📋 MAIN MENU:")
    print("1. 🏛️  Legislative Monitoring")
    print("2. 🔍 Search Documents")
    print("3. 📊 Analytics Dashboard")
    print("4. ⚙️  System Configuration")
    print("5. 📄 Export Reports")
    print("6. 💻 System Information")
    print("0. ❌ Exit")
    print("-" * 40)

def show_system_info():
    """Display system information and project details"""
    print("\n💻 SYSTEM INFORMATION:")
    print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🐍 Python Version: {sys.version.split()[0]}")
    print(f"📁 Working Directory: {os.getcwd()}")
    print(f"📊 Project Root: {project_root}")
    
    # Check core modules
    print("\n🔧 CORE MODULES STATUS:")
    modules_to_check = [
        ('core.api.base_service', '🌐 API Service'),
        ('core.auth.jwt_manager', '🔐 Authentication'),
        ('core.security.zero_trust', '🛡️  Security Engine'),
        ('core.utils.application_cache', '🗄️  Cache System'),
        ('core.database.sharding_strategy', '💾 Database Strategy'),
    ]
    
    for module_name, description in modules_to_check:
        try:
            __import__(module_name)
            print(f"✅ {description}")
        except ImportError as e:
            print(f"❌ {description} - {e}")

def show_legislative_monitoring():
    """Demonstrate legislative monitoring capabilities"""
    print("\n🏛️  LEGISLATIVE MONITORING DEMO:")
    print("📋 Available Sources:")
    print("  • 🏛️  Câmara dos Deputados")
    print("  • 🏛️  Senado Federal")
    print("  • 🏛️  Planalto Palace")
    print("  • 🏛️  Regulatory Agencies")
    print("\n⚙️  Features:")
    print("  • Real-time document monitoring")
    print("  • Intelligent alerts and notifications")
    print("  • Document classification and analysis")
    print("  • Trend analysis and reporting")

def demo_search():
    """Demonstrate search functionality"""
    print("\n🔍 SEARCH DEMO:")
    search_term = input("Enter search term (or press Enter for demo): ").strip()
    if not search_term:
        search_term = "política pública"
    
    print(f"\n🔍 Searching for: '{search_term}'")
    print("📊 Search Results (Demo):")
    print("  📄 Document 1: Lei sobre políticas públicas de saúde")
    print("  📄 Document 2: Projeto de lei sobre educação")
    print("  📄 Document 3: Decreto sobre meio ambiente")
    print(f"\n✅ Found 3 documents related to '{search_term}'")

def main():
    """Main CLI application loop"""
    print_header()
    
    while True:
        show_main_menu()
        
        try:
            choice = input("Enter your choice (0-6): ").strip()
            
            if choice == "0":
                print("\n👋 Thank you for using Monitor Legislativo v4!")
                print("🏢 MackIntegridade - Monitoring Brazilian Democracy")
                break
            elif choice == "1":
                show_legislative_monitoring()
            elif choice == "2":
                demo_search()
            elif choice == "3":
                print("\n📊 ANALYTICS DASHBOARD:")
                print("📈 Document trends over time")
                print("🏛️  Source distribution analysis")
                print("🔍 Most searched topics")
                print("⚡ Real-time processing statistics")
            elif choice == "4":
                print("\n⚙️  SYSTEM CONFIGURATION:")
                print("🔧 Configuration files loaded from:")
                print(f"   📁 {project_root / 'configs'}")
                print("🌐 API endpoints configured")
                print("🔐 Security settings active")
            elif choice == "5":
                print("\n📄 EXPORT REPORTS:")
                print("Available formats:")
                print("  📊 Excel (.xlsx)")
                print("  📋 PDF Report")
                print("  📄 JSON Data")
                print("  📊 CSV Files")
            elif choice == "6":
                show_system_info()
            else:
                print("❌ Invalid choice. Please select a number from 0-6.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except EOFError:
            print("\n\n👋 Goodbye!")
            break
        
        # Wait for user to continue
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()