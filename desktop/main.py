"""
Monitor Legislativo Desktop Application
Main entry point with offline-first capabilities

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import sys
import asyncio
import logging
from pathlib import Path
import atexit

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

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

async def initialize_offline_services():
    """Initialize offline services"""
    try:
        # Import offline services
        from desktop.offline import (
            offline_storage,
            background_sync_service,
            offline_api_client
        )
        
        logger.info("Initializing offline services...")
        
        # Start offline API client
        await offline_api_client.start()
        
        # Start background sync service
        await background_sync_service.start()
        
        logger.info("Offline services initialized successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize offline services: {e}")
        return False

async def shutdown_offline_services():
    """Shutdown offline services"""
    try:
        from desktop.offline import (
            offline_storage,
            background_sync_service,
            offline_api_client,
            offline_cache
        )
        
        logger.info("Shutting down offline services...")
        
        # Stop background sync
        await background_sync_service.stop()
        
        # Close API client
        await offline_api_client.close()
        
        # Close storage
        await offline_storage.close()
        
        # Close cache
        await offline_cache.close()
        
        logger.info("Offline services shutdown complete")
        
    except Exception as e:
        logger.error(f"Error shutting down offline services: {e}")

def main():
    """Main entry point for desktop application"""
    if not check_dependencies():
        sys.exit(1)
    
    # Import here after dependency check
    try:
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import Qt, QTimer
        from PySide6.QtGui import QIcon
        from PySide6.QtAsyncio import QAsyncioEventLoopPolicy
    except ImportError:
        try:
            from PyQt5.QtWidgets import QApplication
            from PyQt5.QtCore import Qt, QTimer
            from PyQt5.QtGui import QIcon
            # PyQt5 doesn't have asyncio integration, we'll handle it differently
            QAsyncioEventLoopPolicy = None
        except ImportError:
            logger.error("No Qt bindings available")
            sys.exit(1)
    
    # Add project root to path
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Set event loop policy for asyncio integration
    if QAsyncioEventLoopPolicy:
        asyncio.set_event_loop_policy(QAsyncioEventLoopPolicy())
    
    # Create application
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Monitor de Políticas Públicas")
    app.setOrganizationName("MackIntegridade")
    app.setOrganizationDomain("mackintegridade.org")
    
    # Set application style
    app.setStyle("Fusion")
    
    # Initialize offline services in background
    async def setup_and_run():
        """Setup offline services and run application"""
        # Initialize offline services
        offline_ready = await initialize_offline_services()
        
        if not offline_ready:
            logger.warning("Offline services failed to initialize, running in limited mode")
        
        # Import main window
        from desktop.ui.main_window import MainWindow
        
        # Create and configure main window
        window = MainWindow(offline_enabled=offline_ready)
        window.setWindowTitle("Monitor de Políticas Públicas MackIntegridade")
        
        # Set icon if available
        icon_path = Path(__file__).parent.parent / "resources" / "logos" / "mackintegridade.png"
        if icon_path.exists():
            window.setWindowIcon(QIcon(str(icon_path)))
        
        # Show window
        window.show()
        
        # Setup cleanup on exit
        def cleanup():
            """Cleanup function for application exit"""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(shutdown_offline_services())
            finally:
                loop.close()
        
        atexit.register(cleanup)
        
        return window
    
    # Run setup
    if QAsyncioEventLoopPolicy:
        # PySide6 with asyncio integration
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            window = loop.run_until_complete(setup_and_run())
            # Run Qt event loop
            sys.exit(app.exec())
        finally:
            # Cleanup
            loop.run_until_complete(shutdown_offline_services())
            loop.close()
    else:
        # PyQt5 - simpler initialization without asyncio integration
        logger.warning("Using PyQt5 - offline features may be limited")
        
        # Import main window
        from desktop.ui.main_window import MainWindow
        
        # Create and configure main window
        window = MainWindow(offline_enabled=False)
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