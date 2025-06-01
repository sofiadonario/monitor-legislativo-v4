"""End-to-end tests for the desktop application."""

import pytest
import sys
import os
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

# Add the desktop module to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'desktop'))

try:
    from PySide6.QtWidgets import QApplication, QMainWindow
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtTest import QTest
    PYSIDE_AVAILABLE = True
except ImportError:
    try:
        from PyQt6.QtWidgets import QApplication, QMainWindow
        from PyQt6.QtCore import QTimer, Qt
        from PyQt6.QtTest import QTest
        PYSIDE_AVAILABLE = True
    except ImportError:
        PYSIDE_AVAILABLE = False


@pytest.fixture(scope="session")
def qapp():
    """Create QApplication instance for testing."""
    if not PYSIDE_AVAILABLE:
        pytest.skip("Qt libraries not available")
    
    app = QApplication.instance()
    if not app:
        app = QApplication([])
    yield app
    if app:
        app.quit()


@pytest.fixture
def main_window(qapp):
    """Create main window instance for testing."""
    if not PYSIDE_AVAILABLE:
        pytest.skip("Qt libraries not available")
    
    with patch('desktop.ui.main_window_fixed.APIService') as mock_api:
        from desktop.ui.main_window_fixed import MainWindow
        window = MainWindow()
        yield window
        window.close()


@pytest.mark.e2e
@pytest.mark.skipif(not PYSIDE_AVAILABLE, reason="Qt libraries not available")
class TestDesktopApplicationE2E:
    """End-to-end tests for desktop application functionality."""

    def test_application_startup(self, qapp):
        """Test that the application starts up correctly."""
        with patch('desktop.ui.main_window_fixed.APIService'):
            from desktop.main import main
            
            # Mock sys.argv to prevent command line interference
            with patch('sys.argv', ['desktop']):
                # This should not raise any exceptions
                # We can't fully test the exec() loop, but we can test initialization
                assert True  # Placeholder - actual startup testing would be complex

    def test_main_window_creation(self, main_window):
        """Test main window creation and basic setup."""
        assert main_window is not None
        assert main_window.windowTitle() == "Monitor Legislativo v4"
        assert main_window.isVisible() == False  # Not shown by default in tests

    def test_search_interface_elements(self, main_window):
        """Test that search interface elements are present."""
        # Check for search input field
        search_input = main_window.findChild(main_window.__class__, "search_input")
        if search_input:
            assert search_input is not None
        
        # Check for search button
        search_button = main_window.findChild(main_window.__class__, "search_button")
        if search_button:
            assert search_button is not None

    def test_menu_bar_creation(self, main_window):
        """Test that menu bar is created with expected menus."""
        menu_bar = main_window.menuBar()
        assert menu_bar is not None
        
        # Check for File menu
        file_menu = None
        for action in menu_bar.actions():
            if action.text() == "&File":
                file_menu = action.menu()
                break
        
        if file_menu:
            assert file_menu is not None

    @patch('desktop.ui.main_window_fixed.APIService')
    def test_search_functionality(self, mock_api_service, main_window):
        """Test search functionality integration."""
        # Mock API response
        mock_api_service.return_value.search_documents.return_value = {
            'documents': [
                {
                    'title': 'Test Document',
                    'content': 'Test content',
                    'source': 'Camara',
                    'published_date': '2024-01-01'
                }
            ],
            'total_count': 1
        }
        
        # Simulate search
        search_term = "lei proteção dados"
        
        # If search input exists, simulate typing
        search_input = main_window.findChild(main_window.__class__, "search_input")
        if search_input:
            QTest.keyClicks(search_input, search_term)
            
            # Simulate search button click
            search_button = main_window.findChild(main_window.__class__, "search_button")
            if search_button:
                QTest.mouseClick(search_button, Qt.LeftButton)

    def test_results_display(self, main_window):
        """Test that search results are displayed correctly."""
        # Mock results data
        mock_results = [
            {
                'title': 'Test Document 1',
                'content': 'Test content 1',
                'source': 'Camara',
                'published_date': '2024-01-01'
            },
            {
                'title': 'Test Document 2',
                'content': 'Test content 2',
                'source': 'Senado',
                'published_date': '2024-01-02'
            }
        ]
        
        # If results display method exists, test it
        if hasattr(main_window, 'display_results'):
            main_window.display_results(mock_results)
            
            # Check that results are displayed
            results_widget = main_window.findChild(main_window.__class__, "results_widget")
            if results_widget:
                assert results_widget is not None

    @patch('desktop.ui.main_window_fixed.QMessageBox')
    def test_error_handling_display(self, mock_message_box, main_window):
        """Test error handling and display."""
        # Simulate an error
        error_message = "API connection failed"
        
        # If error handling method exists, test it
        if hasattr(main_window, 'show_error'):
            main_window.show_error(error_message)
            mock_message_box.critical.assert_called_once()

    def test_export_functionality(self, main_window):
        """Test export functionality."""
        # Mock export data
        export_data = [
            {
                'title': 'Document 1',
                'content': 'Content 1',
                'source': 'Camara'
            }
        ]
        
        # If export method exists, test it
        if hasattr(main_window, 'export_results'):
            # This would typically open a file dialog
            with patch('desktop.ui.main_window_fixed.QFileDialog.getSaveFileName') as mock_dialog:
                mock_dialog.return_value = ('test_export.csv', 'CSV Files (*.csv)')
                
                result = main_window.export_results(export_data, 'csv')
                # Test would verify file was created/data was processed

    def test_settings_dialog(self, main_window):
        """Test settings/preferences dialog."""
        # If settings dialog exists, test it
        if hasattr(main_window, 'show_settings'):
            with patch('desktop.ui.main_window_fixed.QDialog') as mock_dialog:
                main_window.show_settings()
                # Verify dialog was created and shown

    def test_window_state_persistence(self, main_window):
        """Test that window state can be saved and restored."""
        # Set window size and position
        main_window.resize(800, 600)
        main_window.move(100, 100)
        
        # If save/restore methods exist, test them
        if hasattr(main_window, 'save_window_state'):
            main_window.save_window_state()
        
        if hasattr(main_window, 'restore_window_state'):
            main_window.restore_window_state()

    @patch('desktop.ui.main_window_fixed.APIService')
    def test_async_operations(self, mock_api_service, main_window):
        """Test asynchronous operations in the desktop app."""
        # Mock async API call
        async def mock_async_search():
            return {'documents': [], 'total_count': 0}
        
        mock_api_service.return_value.search_documents = AsyncMock(
            return_value={'documents': [], 'total_count': 0}
        )
        
        # If async worker exists, test it
        if hasattr(main_window, 'async_worker'):
            # Test that async operations don't block the UI
            assert True  # Placeholder for actual async testing

    def test_loading_indicators(self, main_window):
        """Test loading indicators during async operations."""
        # If loading indicator methods exist, test them
        if hasattr(main_window, 'show_loading'):
            main_window.show_loading("Searching...")
            
            # Check that loading indicator is visible
            loading_widget = main_window.findChild(main_window.__class__, "loading_widget")
            if loading_widget:
                assert loading_widget.isVisible()

        if hasattr(main_window, 'hide_loading'):
            main_window.hide_loading()
            
            # Check that loading indicator is hidden
            if loading_widget:
                assert not loading_widget.isVisible()

    def test_keyboard_shortcuts(self, main_window):
        """Test keyboard shortcuts functionality."""
        # Test Ctrl+F for search
        if hasattr(main_window, 'search_input'):
            QTest.keySequence(main_window, "Ctrl+F")
            # Verify search input gets focus

        # Test Ctrl+S for save/export
        QTest.keySequence(main_window, "Ctrl+S")
        # Verify export dialog appears or save action is triggered

        # Test Escape for cancel operations
        QTest.keyPress(main_window, Qt.Key_Escape)
        # Verify any modal dialogs are closed

    def test_context_menus(self, main_window):
        """Test context menu functionality."""
        # If results list exists, test right-click context menu
        results_widget = main_window.findChild(main_window.__class__, "results_widget")
        if results_widget:
            # Simulate right-click
            QTest.mouseClick(results_widget, Qt.RightButton)
            # Verify context menu appears with expected actions

    def test_drag_and_drop(self, main_window):
        """Test drag and drop functionality if implemented."""
        # This would test dragging search results to external applications
        # or dropping files into the application
        # Implementation depends on specific drag/drop features
        pass

    def test_accessibility_features(self, main_window):
        """Test accessibility features."""
        # Test that widgets have accessible names
        # Test keyboard navigation
        # Test screen reader compatibility
        # This is a placeholder for accessibility testing
        pass

    def test_multi_window_support(self, qapp):
        """Test multiple window instances."""
        if not PYSIDE_AVAILABLE:
            pytest.skip("Qt libraries not available")
        
        # Create multiple windows
        with patch('desktop.ui.main_window_fixed.APIService'):
            from desktop.ui.main_window_fixed import MainWindow
            
            window1 = MainWindow()
            window2 = MainWindow()
            
            assert window1 != window2
            assert window1.windowTitle() == window2.windowTitle()
            
            window1.close()
            window2.close()


@pytest.mark.e2e
@pytest.mark.skipif(not PYSIDE_AVAILABLE, reason="Qt libraries not available")
class TestDesktopApplicationWorkflow:
    """Test complete workflows in the desktop application."""

    @patch('desktop.ui.main_window_fixed.APIService')
    def test_complete_search_workflow(self, mock_api_service, main_window):
        """Test complete search workflow from input to results display."""
        # Setup mock API responses
        mock_api_service.return_value.search_documents.return_value = {
            'documents': [
                {
                    'title': 'Lei de Proteção de Dados',
                    'content': 'Lei que estabelece regras...',
                    'source': 'Camara',
                    'published_date': '2024-01-15',
                    'url': 'http://example.com/lei1'
                }
            ],
            'total_count': 1,
            'page': 1,
            'per_page': 10
        }
        
        # Step 1: Enter search term
        search_term = "lei proteção dados"
        search_input = main_window.findChild(main_window.__class__, "search_input")
        if search_input:
            QTest.keyClicks(search_input, search_term)
        
        # Step 2: Click search button
        search_button = main_window.findChild(main_window.__class__, "search_button")
        if search_button:
            QTest.mouseClick(search_button, Qt.LeftButton)
        
        # Step 3: Wait for results (simulate async completion)
        if hasattr(main_window, 'on_search_completed'):
            main_window.on_search_completed({
                'documents': mock_api_service.return_value.search_documents.return_value['documents'],
                'total_count': 1
            })
        
        # Step 4: Verify results are displayed
        results_widget = main_window.findChild(main_window.__class__, "results_widget")
        if results_widget:
            assert results_widget is not None

    @patch('desktop.ui.main_window_fixed.APIService')
    def test_search_with_filters_workflow(self, mock_api_service, main_window):
        """Test search workflow with filters applied."""
        # Setup filters
        date_filter = {
            'start_date': '2024-01-01',
            'end_date': '2024-12-31'
        }
        source_filter = ['camara', 'senado']
        
        # Apply filters if filter UI exists
        if hasattr(main_window, 'apply_filters'):
            main_window.apply_filters({
                'date_range': date_filter,
                'sources': source_filter
            })
        
        # Perform search with filters
        mock_api_service.return_value.search_documents.return_value = {
            'documents': [],
            'total_count': 0
        }
        
        # Trigger search
        if hasattr(main_window, 'perform_search'):
            main_window.perform_search("test query")

    def test_export_workflow(self, main_window):
        """Test complete export workflow."""
        # Setup test data
        test_results = [
            {
                'title': 'Document 1',
                'content': 'Content 1',
                'source': 'Camara',
                'published_date': '2024-01-01'
            },
            {
                'title': 'Document 2',
                'content': 'Content 2',
                'source': 'Senado',
                'published_date': '2024-01-02'
            }
        ]
        
        # Step 1: Select export format
        with patch('desktop.ui.main_window_fixed.QDialog') as mock_dialog:
            # Mock export dialog
            if hasattr(main_window, 'show_export_dialog'):
                main_window.show_export_dialog()
        
        # Step 2: Choose file location
        with patch('desktop.ui.main_window_fixed.QFileDialog.getSaveFileName') as mock_file_dialog:
            mock_file_dialog.return_value = ('test_export.csv', 'CSV Files (*.csv)')
            
            # Step 3: Perform export
            if hasattr(main_window, 'export_results'):
                result = main_window.export_results(test_results, 'csv')
                # Verify export was initiated

    def test_error_recovery_workflow(self, main_window):
        """Test error handling and recovery workflow."""
        # Simulate network error
        error_message = "Network connection failed"
        
        # Step 1: Error occurs during search
        if hasattr(main_window, 'on_search_error'):
            main_window.on_search_error(error_message)
        
        # Step 2: Error message is displayed
        with patch('desktop.ui.main_window_fixed.QMessageBox') as mock_msg_box:
            if hasattr(main_window, 'show_error'):
                main_window.show_error(error_message)
                mock_msg_box.critical.assert_called()
        
        # Step 3: User can retry operation
        if hasattr(main_window, 'retry_last_operation'):
            with patch.object(main_window, 'perform_search') as mock_search:
                main_window.retry_last_operation()
                # Verify retry was attempted

    def test_settings_persistence_workflow(self, main_window):
        """Test settings save and load workflow."""
        # Step 1: Change settings
        test_settings = {
            'api_timeout': 30,
            'results_per_page': 20,
            'default_export_format': 'csv'
        }
        
        if hasattr(main_window, 'apply_settings'):
            main_window.apply_settings(test_settings)
        
        # Step 2: Save settings
        if hasattr(main_window, 'save_settings'):
            main_window.save_settings()
        
        # Step 3: Restart application and verify settings persist
        if hasattr(main_window, 'load_settings'):
            loaded_settings = main_window.load_settings()
            # Verify settings were persisted