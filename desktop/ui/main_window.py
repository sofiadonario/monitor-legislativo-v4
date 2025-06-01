"""
Main window for Monitor Legislativo Desktop
Implements modern UI with MackIntegridade branding
"""

import asyncio
import logging
import sys
from datetime import datetime, timedelta
from typing import List, Optional
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from PySide6.QtWidgets import *
    from PySide6.QtCore import *
    from PySide6.QtGui import *
except ImportError:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *

from core.api.api_service import APIService
from core.models.models import SearchResult, APIStatus, DataSource
from core.utils.export_service import ExportService
from core.config.config import Config


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.config = Config()
        
        # Initialize services
        self.api_service = APIService()
        self.export_service = ExportService()
        
        # Current search results
        self.current_results = []
        
        # Setup UI
        self.setup_ui()
        self.apply_branding()
        
        # Setup status monitoring
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_api_status)
        self.status_timer.start(30000)  # Update every 30 seconds
        
        # Initial status check
        QTimer.singleShot(1000, self.update_api_status)
    
    def setup_ui(self):
        """Setup the user interface"""
        # Set window properties
        self.setMinimumSize(1200, 800)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Header
        self.create_header(main_layout)
        
        # Content area
        content_widget = QWidget()
        content_widget.setObjectName("contentWidget")
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(20, 20, 20, 20)
        
        # Search section
        self.create_search_section(content_layout)
        
        # Results section
        self.create_results_section(content_layout)
        
        main_layout.addWidget(content_widget, 1)
        
        # Status bar
        self.create_status_bar()
        
        # Menu bar
        self.create_menu_bar()
    
    def create_header(self, parent_layout):
        """Create application header with branding"""
        header = QWidget()
        header.setObjectName("header")
        header.setFixedHeight(100)
        
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 10, 20, 10)
        
        # Logo
        logo_label = QLabel()
        logo_label.setPixmap(QPixmap(100, 80))  # Placeholder
        logo_label.setScaledContents(True)
        logo_label.setMaximumSize(150, 80)
        header_layout.addWidget(logo_label)
        
        # Title and subtitle
        title_layout = QVBoxLayout()
        title_layout.setSpacing(5)
        
        title = QLabel("Monitor de Políticas Públicas")
        title.setObjectName("headerTitle")
        title_layout.addWidget(title)
        
        subtitle = QLabel("MackIntegridade - Monitoramento Legislativo Integrado")
        subtitle.setObjectName("headerSubtitle")
        title_layout.addWidget(subtitle)
        
        title_layout.addStretch()
        header_layout.addLayout(title_layout, 1)
        
        # API Status indicators
        self.status_widget = QWidget()
        self.status_layout = QHBoxLayout(self.status_widget)
        self.status_layout.setSpacing(10)
        header_layout.addWidget(self.status_widget)
        
        parent_layout.addWidget(header)
    
    def create_search_section(self, parent_layout):
        """Create search input section"""
        search_group = QGroupBox("Busca")
        search_group.setObjectName("searchGroup")
        search_layout = QVBoxLayout(search_group)
        
        # Search input row
        search_row = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Digite os termos de busca...")
        self.search_input.returnPressed.connect(self.perform_search)
        search_row.addWidget(self.search_input, 1)
        
        self.search_button = QPushButton("Buscar")
        self.search_button.setObjectName("primaryButton")
        self.search_button.clicked.connect(self.perform_search)
        self.search_button.setMinimumWidth(120)
        search_row.addWidget(self.search_button)
        
        search_layout.addLayout(search_row)
        
        # Filters
        filters_widget = QWidget()
        filters_layout = QHBoxLayout(filters_widget)
        filters_layout.setContentsMargins(0, 10, 0, 0)
        
        # Date range
        filters_layout.addWidget(QLabel("Período:"))
        
        self.start_date = QDateEdit()
        self.start_date.setCalendarPopup(True)
        self.start_date.setDate(QDate.currentDate().addDays(-30))
        self.start_date.setDisplayFormat("dd/MM/yyyy")
        filters_layout.addWidget(self.start_date)
        
        filters_layout.addWidget(QLabel("até"))
        
        self.end_date = QDateEdit()
        self.end_date.setCalendarPopup(True)
        self.end_date.setDate(QDate.currentDate())
        self.end_date.setDisplayFormat("dd/MM/yyyy")
        filters_layout.addWidget(self.end_date)
        
        filters_layout.addSpacing(20)
        
        # Sources
        filters_layout.addWidget(QLabel("Fontes:"))
        
        self.source_checkboxes = {}
        sources = self.api_service.get_available_sources()
        
        for key, name in sources.items():
            checkbox = QCheckBox(name)
            checkbox.setChecked(True)
            self.source_checkboxes[key] = checkbox
            filters_layout.addWidget(checkbox)
        
        filters_layout.addStretch()
        
        search_layout.addWidget(filters_widget)
        parent_layout.addWidget(search_group)
    
    def create_results_section(self, parent_layout):
        """Create results display section"""
        results_group = QGroupBox("Resultados")
        results_group.setObjectName("resultsGroup")
        results_layout = QVBoxLayout(results_group)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        self.results_label = QLabel("Nenhuma busca realizada")
        toolbar.addWidget(self.results_label)
        
        toolbar.addStretch()
        
        # Export buttons
        export_label = QLabel("Exportar:")
        toolbar.addWidget(export_label)
        
        for format in ["CSV", "HTML", "PDF", "JSON", "XLSX"]:
            btn = QPushButton(format)
            btn.setObjectName("exportButton")
            btn.clicked.connect(lambda checked, f=format: self.export_results(f))
            toolbar.addWidget(btn)
        
        results_layout.addLayout(toolbar)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setSortingEnabled(True)
        
        # Set columns
        columns = ["Fonte", "Tipo", "Número/Ano", "Título", "Autores", 
                  "Data", "Status", "Ações"]
        self.results_table.setColumnCount(len(columns))
        self.results_table.setHorizontalHeaderLabels(columns)
        
        # Configure header
        header = self.results_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # Stretch title column
        
        results_layout.addWidget(self.results_table)
        
        # Pagination
        pagination_layout = QHBoxLayout()
        pagination_layout.addStretch()
        
        self.page_info = QLabel("Página 1 de 1")
        pagination_layout.addWidget(self.page_info)
        
        self.prev_button = QPushButton("< Anterior")
        self.prev_button.clicked.connect(self.previous_page)
        pagination_layout.addWidget(self.prev_button)
        
        self.next_button = QPushButton("Próxima >")
        self.next_button.clicked.connect(self.next_page)
        pagination_layout.addWidget(self.next_button)
        
        results_layout.addLayout(pagination_layout)
        
        parent_layout.addWidget(results_group, 1)
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Pronto")
    
    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("Arquivo")
        
        export_action = QAction("Exportar Resultados...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.show_export_dialog)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Sair", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Ferramentas")
        
        clear_cache_action = QAction("Limpar Cache", self)
        clear_cache_action.triggered.connect(self.clear_cache)
        tools_menu.addAction(clear_cache_action)
        
        refresh_status_action = QAction("Atualizar Status das APIs", self)
        refresh_status_action.setShortcut("F5")
        refresh_status_action.triggered.connect(self.update_api_status)
        tools_menu.addAction(refresh_status_action)
        
        # Help menu
        help_menu = menubar.addMenu("Ajuda")
        
        about_action = QAction("Sobre", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def apply_branding(self):
        """Apply MackIntegridade branding and styling"""
        style = """
        /* Main window */
        QMainWindow {
            background-color: #f5f5f5;
        }
        
        /* Header */
        #header {
            background-color: #003366;
            border-bottom: 3px solid #0066CC;
        }
        
        #headerTitle {
            color: white;
            font-size: 24px;
            font-weight: bold;
        }
        
        #headerSubtitle {
            color: #cccccc;
            font-size: 14px;
        }
        
        /* Content area */
        #contentWidget {
            background-color: white;
        }
        
        /* Group boxes */
        QGroupBox {
            font-size: 16px;
            font-weight: bold;
            color: #003366;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            margin-top: 10px;
            padding-top: 10px;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 20px;
            padding: 0 10px 0 10px;
        }
        
        /* Buttons */
        QPushButton {
            padding: 8px 16px;
            border-radius: 4px;
            font-size: 14px;
        }
        
        #primaryButton {
            background-color: #0066CC;
            color: white;
            border: none;
            font-weight: bold;
        }
        
        #primaryButton:hover {
            background-color: #0052A3;
        }
        
        #primaryButton:pressed {
            background-color: #003D7A;
        }
        
        #exportButton {
            background-color: #f0f0f0;
            border: 1px solid #d0d0d0;
        }
        
        #exportButton:hover {
            background-color: #e0e0e0;
        }
        
        /* Input fields */
        QLineEdit, QDateEdit {
            padding: 8px;
            border: 1px solid #d0d0d0;
            border-radius: 4px;
            font-size: 14px;
        }
        
        QLineEdit:focus, QDateEdit:focus {
            border-color: #0066CC;
            outline: none;
        }
        
        /* Table */
        QTableWidget {
            border: 1px solid #d0d0d0;
            gridline-color: #e0e0e0;
        }
        
        QTableWidget::item {
            padding: 8px;
        }
        
        QTableWidget::item:selected {
            background-color: #0066CC;
            color: white;
        }
        
        QHeaderView::section {
            background-color: #f0f0f0;
            padding: 8px;
            border: none;
            border-right: 1px solid #d0d0d0;
            font-weight: bold;
        }
        
        /* Status indicators */
        .statusIndicator {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        """
        
        self.setStyleSheet(style)
    
    def perform_search(self):
        """Perform search operation"""
        query = self.search_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Aviso", "Por favor, digite um termo de busca.")
            return
        
        # Get selected sources
        selected_sources = [key for key, cb in self.source_checkboxes.items() if cb.isChecked()]
        if not selected_sources:
            QMessageBox.warning(self, "Aviso", "Por favor, selecione pelo menos uma fonte.")
            return
        
        # Prepare filters
        filters = {
            "start_date": self.start_date.date().toString("yyyy-MM-dd"),
            "end_date": self.end_date.date().toString("yyyy-MM-dd")
        }
        
        # Update UI
        self.search_button.setEnabled(False)
        self.search_button.setText("Buscando...")
        self.status_bar.showMessage("Realizando busca...")
        self.results_table.setRowCount(0)
        
        # Create and run search task
        self.search_task = SearchTask(self.api_service, query, filters, selected_sources)
        self.search_task.finished.connect(self.on_search_finished)
        self.search_task.error.connect(self.on_search_error)
        self.search_task.start()
    
    def on_search_finished(self, results: List[SearchResult]):
        """Handle search completion"""
        self.current_results = results
        self.search_button.setEnabled(True)
        self.search_button.setText("Buscar")
        
        # Count total results
        total = sum(len(r.propositions) for r in results)
        self.results_label.setText(f"{total} resultados encontrados")
        self.status_bar.showMessage("Busca concluída")
        
        # Populate table
        self.populate_results_table()
    
    def on_search_error(self, error_msg: str):
        """Handle search error"""
        self.search_button.setEnabled(True)
        self.search_button.setText("Buscar")
        self.status_bar.showMessage("Erro na busca")
        QMessageBox.critical(self, "Erro", f"Erro durante a busca: {error_msg}")
    
    def populate_results_table(self):
        """Populate results table with search results"""
        self.results_table.setRowCount(0)
        
        for result in self.current_results:
            for prop in result.propositions:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                # Source
                self.results_table.setItem(row, 0, QTableWidgetItem(prop.source.value))
                
                # Type
                self.results_table.setItem(row, 1, QTableWidgetItem(prop.type.value))
                
                # Number/Year
                self.results_table.setItem(row, 2, QTableWidgetItem(f"{prop.number}/{prop.year}"))
                
                # Title
                title_item = QTableWidgetItem(prop.title)
                title_item.setToolTip(prop.summary)
                self.results_table.setItem(row, 3, title_item)
                
                # Authors
                self.results_table.setItem(row, 4, QTableWidgetItem(prop.author_names))
                
                # Date
                self.results_table.setItem(row, 5, QTableWidgetItem(
                    prop.publication_date.strftime("%d/%m/%Y")
                ))
                
                # Status
                self.results_table.setItem(row, 6, QTableWidgetItem(prop.status.value))
                
                # Actions
                actions_widget = QWidget()
                actions_layout = QHBoxLayout(actions_widget)
                actions_layout.setContentsMargins(4, 0, 4, 0)
                
                view_btn = QPushButton("Ver")
                view_btn.clicked.connect(lambda checked, url=prop.url: self.open_url(url))
                actions_layout.addWidget(view_btn)
                
                self.results_table.setCellWidget(row, 7, actions_widget)
        
        # Adjust column sizes
        self.results_table.resizeColumnsToContents()
    
    def open_url(self, url: str):
        """Open URL in browser"""
        QDesktopServices.openUrl(QUrl(url))
    
    def export_results(self, format: str):
        """Export results to file"""
        if not self.current_results:
            QMessageBox.warning(self, "Aviso", "Nenhum resultado para exportar.")
            return
        
        # Get file path
        default_name = f"resultados_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format.lower()}"
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar Resultados",
            default_name,
            f"{format} Files (*.{format.lower()})"
        )
        
        if not file_path:
            return
        
        # Export
        metadata = {
            "query": self.search_input.text(),
            "filters": f"{self.start_date.date().toString('dd/MM/yyyy')} - {self.end_date.date().toString('dd/MM/yyyy')}"
        }
        
        success = self.export_service.export(
            self.current_results,
            format,
            file_path,
            metadata
        )
        
        if success:
            QMessageBox.information(self, "Sucesso", f"Resultados exportados para:\n{file_path}")
        else:
            QMessageBox.critical(self, "Erro", "Erro ao exportar resultados.")
    
    def update_api_status(self):
        """Update API status indicators"""
        # Create and run status check task
        self.status_task = StatusTask(self.api_service)
        self.status_task.finished.connect(self.on_status_updated)
        self.status_task.start()
    
    def on_status_updated(self, statuses: List[APIStatus]):
        """Update status indicators"""
        # Clear existing indicators
        while self.status_layout.count():
            item = self.status_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Add new indicators
        for status in statuses:
            indicator = QLabel(status.name)
            indicator.setProperty("class", "statusIndicator")
            
            if status.is_healthy:
                indicator.setStyleSheet("""
                    background-color: #4CAF50;
                    color: white;
                """)
                indicator.setToolTip(f"Operacional ({status.response_time:.1f}s)")
            else:
                indicator.setStyleSheet("""
                    background-color: #f44336;
                    color: white;
                """)
                indicator.setToolTip(f"Indisponível: {status.error_message}")
            
            self.status_layout.addWidget(indicator)
    
    def clear_cache(self):
        """Clear application cache"""
        reply = QMessageBox.question(
            self,
            "Limpar Cache",
            "Deseja limpar todo o cache da aplicação?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Clear cache asynchronously
            try:
                import asyncio
                asyncio.run(self.api_service.clear_cache())
                QMessageBox.information(self, "Sucesso", "Cache limpo com sucesso.")
            except Exception as e:
                QMessageBox.warning(self, "Erro", f"Erro ao limpar cache: {e}")
    
    def show_export_dialog(self):
        """Show export dialog"""
        # TODO: Implement advanced export dialog
        pass
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
        <h2>Monitor de Políticas Públicas</h2>
        <p>Versão {self.config.VERSION}</p>
        <p>© 2025 MackIntegridade</p>
        <br>
        <p>Sistema integrado de monitoramento legislativo brasileiro com suporte 
        para múltiplas fontes governamentais e agências reguladoras.</p>
        <br>
        <p><a href="https://www.mackintegridade.org">www.mackintegridade.org</a></p>
        """
        
        QMessageBox.about(self, "Sobre", about_text)
    
    def previous_page(self):
        """Go to previous page"""
        # TODO: Implement pagination
        pass
    
    def next_page(self):
        """Go to next page"""
        # TODO: Implement pagination
        pass


class SearchTask(QThread):
    """Background task for search operations"""
    finished = Signal(list)
    error = Signal(str)
    
    def __init__(self, api_service, query, filters, sources):
        super().__init__()
        self.api_service = api_service
        self.query = query
        self.filters = filters
        self.sources = sources
    
    def run(self):
        """Run search in background"""
        try:
            # Create event loop for async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Run search
            results = loop.run_until_complete(
                self.api_service.search_all(self.query, self.filters, self.sources)
            )
            
            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class StatusTask(QThread):
    """Background task for status checks"""
    finished = Signal(list)
    
    def __init__(self, api_service):
        super().__init__()
        self.api_service = api_service
    
    def run(self):
        """Check API status in background"""
        try:
            # Create event loop for async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Get status
            statuses = loop.run_until_complete(
                self.api_service.get_api_status(force_check=True)
            )
            
            self.finished.emit(statuses)
            
        except Exception as e:
            # Emit empty list on error
            self.finished.emit([])
        finally:
            loop.close()