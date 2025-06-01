"""
Error handling and user-friendly error display for Desktop UI
"""

import logging
import traceback
from typing import Optional, Callable, Any
from functools import wraps

try:
    from PySide6.QtWidgets import *
    from PySide6.QtCore import *
    from PySide6.QtGui import *
except ImportError:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *

logger = logging.getLogger(__name__)


class ErrorDialog(QDialog):
    """User-friendly error dialog"""
    
    def __init__(self, error_title: str, error_message: str, 
                 details: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Erro")
        self.setModal(True)
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout(self)
        
        # Icon and title
        header_layout = QHBoxLayout()
        
        icon_label = QLabel()
        icon_label.setPixmap(self.style().standardPixmap(QStyle.SP_MessageBoxCritical))
        header_layout.addWidget(icon_label)
        
        title_label = QLabel(f"<h3>{error_title}</h3>")
        header_layout.addWidget(title_label, 1)
        
        layout.addLayout(header_layout)
        
        # Error message
        message_label = QLabel(error_message)
        message_label.setWordWrap(True)
        layout.addWidget(message_label)
        
        # Details section (collapsible)
        if details:
            details_group = QGroupBox("Detalhes técnicos")
            details_group.setCheckable(True)
            details_group.setChecked(False)
            
            details_layout = QVBoxLayout()
            details_text = QTextEdit()
            details_text.setPlainText(details)
            details_text.setReadOnly(True)
            details_text.setMaximumHeight(200)
            details_layout.addWidget(details_text)
            
            details_group.setLayout(details_layout)
            layout.addWidget(details_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        ok_button = QPushButton("OK")
        ok_button.clicked.connect(self.accept)
        ok_button.setDefault(True)
        button_layout.addWidget(ok_button)
        
        layout.addLayout(button_layout)


class ErrorHandler:
    """Central error handling for the application"""
    
    @staticmethod
    def handle_error(error: Exception, context: str = "operação", 
                    parent=None, show_details: bool = True) -> bool:
        """
        Handle an error with user-friendly dialog
        
        Returns:
            True if error was handled, False if should propagate
        """
        logger.error(f"Error in {context}: {error}", exc_info=True)
        
        # Get error details
        error_type = type(error).__name__
        error_str = str(error)
        
        # Create user-friendly messages
        title, message = ErrorHandler._get_user_friendly_message(error, context)
        
        # Get technical details if enabled
        details = None
        if show_details:
            details = f"Tipo: {error_type}\n"
            details += f"Mensagem: {error_str}\n\n"
            details += "Stack trace:\n"
            details += traceback.format_exc()
        
        # Show dialog
        dialog = ErrorDialog(title, message, details, parent)
        dialog.exec()
        
        return True
    
    @staticmethod
    def _get_user_friendly_message(error: Exception, context: str) -> tuple:
        """Get user-friendly error title and message"""
        
        # Network errors
        if isinstance(error, (ConnectionError, TimeoutError)):
            return (
                "Erro de Conexão",
                f"Não foi possível conectar ao servidor durante {context}.\n\n"
                "Verifique sua conexão com a internet e tente novamente."
            )
        
        # API errors
        if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
            status_code = error.response.status_code
            if status_code == 401:
                return (
                    "Autenticação Necessária",
                    "Você precisa fazer login para acessar este recurso."
                )
            elif status_code == 403:
                return (
                    "Acesso Negado",
                    "Você não tem permissão para realizar esta ação."
                )
            elif status_code == 404:
                return (
                    "Recurso Não Encontrado",
                    f"O recurso solicitado não foi encontrado durante {context}."
                )
            elif status_code >= 500:
                return (
                    "Erro no Servidor",
                    "O servidor está com problemas. Tente novamente mais tarde."
                )
        
        # File errors
        if isinstance(error, (IOError, OSError)):
            return (
                "Erro de Arquivo",
                f"Erro ao acessar arquivo durante {context}.\n\n"
                "Verifique se você tem permissão para acessar o arquivo."
            )
        
        # Value errors (validation)
        if isinstance(error, ValueError):
            return (
                "Dados Inválidos",
                f"Os dados fornecidos são inválidos para {context}.\n\n"
                f"Detalhes: {str(error)}"
            )
        
        # Default message
        return (
            "Erro Inesperado",
            f"Ocorreu um erro inesperado durante {context}.\n\n"
            "Se o problema persistir, entre em contato com o suporte."
        )


def error_boundary(context: str = "operação", show_details: bool = True):
    """
    Decorator to add error boundary to functions
    
    Usage:
        @error_boundary("busca de documentos")
        def search_documents(self):
            # code that might raise exceptions
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Try to get parent widget for dialog
                parent = None
                if args and hasattr(args[0], 'window'):
                    parent = args[0].window()
                elif args and isinstance(args[0], QWidget):
                    parent = args[0]
                
                ErrorHandler.handle_error(e, context, parent, show_details)
                
                # Return None or appropriate default
                return None
        
        return wrapper
    return decorator


class ErrorMixin:
    """
    Mixin class to add error handling capabilities to widgets
    
    Usage:
        class MyWidget(QWidget, ErrorMixin):
            def some_method(self):
                try:
                    # risky operation
                except Exception as e:
                    self.show_error(e, "operação")
    """
    
    def show_error(self, error: Exception, context: str = "operação", 
                  show_details: bool = True):
        """Show error dialog for this widget"""
        parent = self.window() if hasattr(self, 'window') else self
        ErrorHandler.handle_error(error, context, parent, show_details)
    
    def show_warning(self, title: str, message: str):
        """Show warning dialog"""
        QMessageBox.warning(self, title, message)
    
    def show_info(self, title: str, message: str):
        """Show information dialog"""
        QMessageBox.information(self, title, message)
    
    def show_success(self, message: str):
        """Show success message"""
        QMessageBox.information(self, "Sucesso", message)
    
    def confirm_action(self, title: str, message: str) -> bool:
        """Show confirmation dialog"""
        reply = QMessageBox.question(
            self, title, message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        return reply == QMessageBox.Yes


class SafeWorker(QObject):
    """Base worker class with error handling"""
    
    finished = Signal(object)
    error = Signal(Exception, str)  # error, context
    progress = Signal(int, str)
    
    def __init__(self, context: str = "operação"):
        super().__init__()
        self.context = context
    
    def safe_run(self, func: Callable, *args, **kwargs):
        """Run function with error handling"""
        try:
            result = func(*args, **kwargs)
            self.finished.emit(result)
        except Exception as e:
            logger.error(f"Worker error in {self.context}: {e}", exc_info=True)
            self.error.emit(e, self.context)


# Example usage in main window
class ExampleWidget(QWidget, ErrorMixin):
    """Example widget showing error handling usage"""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Button that might fail
        risky_button = QPushButton("Operação Arriscada")
        risky_button.clicked.connect(self.risky_operation)
        layout.addWidget(risky_button)
        
        # Async operation button
        async_button = QPushButton("Operação Assíncrona")
        async_button.clicked.connect(self.async_operation)
        layout.addWidget(async_button)
    
    @error_boundary("operação arriscada")
    def risky_operation(self):
        """Method with error boundary decorator"""
        # This will be caught and shown in a nice dialog
        raise ValueError("Algo deu errado!")
    
    def async_operation(self):
        """Async operation with error handling"""
        worker = SafeWorker("busca de dados")
        worker.error.connect(lambda e, ctx: self.show_error(e, ctx))
        worker.finished.connect(self.on_async_finished)
        
        # Simulate async work
        worker.safe_run(self._do_async_work)
    
    def _do_async_work(self):
        """Simulated async work that might fail"""
        import random
        if random.random() < 0.5:
            raise ConnectionError("Falha na conexão com o servidor")
        return "Success!"
    
    def on_async_finished(self, result):
        """Handle async operation success"""
        self.show_success(f"Operação concluída: {result}")