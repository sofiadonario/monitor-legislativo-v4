"""
Monitor Legislativo Desktop Application
Main entry point with improved UI and branding
"""

import sys
import asyncio
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def check_dependencies():
    """Check and install required dependencies"""
    try:
        from PySide6 import QtCore, QtWidgets, QtGui
        return True
    except ImportError:
        try:
            from PyQt5 import QtCore, QtWidgets, QtGui
            return True
        except ImportError:
            print("No Qt bindings found. Please install PySide6 or PyQt5:")
            print("  pip install PySide6")
            print("  or")
            print("  pip install PyQt5")
            return False

def main():
    """Main entry point for desktop application"""
    if not check_dependencies():
        sys.exit(1)
    
    # Import here after dependency check
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QIcon
    except ImportError:
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import Qt
        from PyQt5.QtGui import QIcon
    
    # Add project root to path
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Import main window
    from desktop.ui.main_window import MainWindow
    
    # Create application
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Monitor de Políticas Públicas")
    app.setOrganizationName("MackIntegridade")
    app.setOrganizationDomain("mackintegridade.org")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Create and configure main window
    window = MainWindow()
    window.setWindowTitle("Monitor de Políticas Públicas MackIntegridade")
    
    # Set icon if available
    icon_path = Path(__file__).parent.parent / "resources" / "logos" / "mackintegridade.png"
    if icon_path.exists():
        window.setWindowIcon(QIcon(str(icon_path)))
    
    # Show window
    window.show()
    
    # Run event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()