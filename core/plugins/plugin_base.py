"""
Plugin Base Classes for Monitor Legislativo v4
Provides extensibility through plugin architecture

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import abc
import logging
from typing import Dict, Any, List, Optional, Type
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)

class PluginType(Enum):
    """Types of plugins supported"""
    DATA_SOURCE = "data_source"
    PROCESSOR = "processor"
    EXPORTER = "exporter"
    NOTIFIER = "notifier"
    ANALYZER = "analyzer"
    VALIDATOR = "validator"

@dataclass
class PluginMetadata:
    """Metadata for plugin identification"""
    name: str
    version: str
    author: str
    description: str
    plugin_type: PluginType
    requires: List[str] = None
    config_schema: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.requires is None:
            self.requires = []
        if self.config_schema is None:
            self.config_schema = {}

class PluginInterface(abc.ABC):
    """Base interface for all plugins"""
    
    @abc.abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    @abc.abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin with configuration"""
        pass
    
    @abc.abstractmethod
    async def shutdown(self) -> None:
        """Clean shutdown of the plugin"""
        pass
    
    @abc.abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate plugin configuration"""
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """Check plugin health status"""
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat()
        }

class DataSourcePlugin(PluginInterface):
    """Base class for data source plugins"""
    
    @abc.abstractmethod
    async def fetch_data(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch data from the source"""
        pass
    
    @abc.abstractmethod
    async def search(self, query: str, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Search data from the source"""
        pass
    
    @abc.abstractmethod
    def get_supported_filters(self) -> Dict[str, str]:
        """Return supported filter parameters"""
        pass

class ProcessorPlugin(PluginInterface):
    """Base class for data processor plugins"""
    
    @abc.abstractmethod
    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single data item"""
        pass
    
    @abc.abstractmethod
    async def process_batch(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process multiple data items"""
        pass
    
    def supports_batch(self) -> bool:
        """Whether this processor supports batch processing"""
        return True

class ExporterPlugin(PluginInterface):
    """Base class for data exporter plugins"""
    
    @abc.abstractmethod
    async def export(self, data: List[Dict[str, Any]], options: Dict[str, Any] = None) -> str:
        """Export data and return file path or identifier"""
        pass
    
    @abc.abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Return list of supported export formats"""
        pass
    
    @abc.abstractmethod
    def get_export_options(self) -> Dict[str, Any]:
        """Return available export options"""
        pass

class NotifierPlugin(PluginInterface):
    """Base class for notification plugins"""
    
    @abc.abstractmethod
    async def send_notification(self, 
                              recipient: str,
                              subject: str,
                              content: str,
                              data: Dict[str, Any] = None) -> bool:
        """Send a notification"""
        pass
    
    @abc.abstractmethod
    async def send_batch_notifications(self,
                                     notifications: List[Dict[str, Any]]) -> Dict[str, bool]:
        """Send multiple notifications"""
        pass
    
    @abc.abstractmethod
    def get_notification_types(self) -> List[str]:
        """Return supported notification types"""
        pass

class AnalyzerPlugin(PluginInterface):
    """Base class for data analyzer plugins"""
    
    @abc.abstractmethod
    async def analyze(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze data and return insights"""
        pass
    
    @abc.abstractmethod
    def get_analysis_types(self) -> List[str]:
        """Return supported analysis types"""
        pass
    
    @abc.abstractmethod
    async def generate_report(self, analysis: Dict[str, Any], format: str = "json") -> str:
        """Generate analysis report"""
        pass

class ValidatorPlugin(PluginInterface):
    """Base class for data validator plugins"""
    
    @abc.abstractmethod
    async def validate(self, data: Dict[str, Any]) -> tuple[bool, List[str]]:
        """Validate data and return status with errors"""
        pass
    
    @abc.abstractmethod
    def get_validation_rules(self) -> Dict[str, Any]:
        """Return validation rules"""
        pass
    
    @abc.abstractmethod
    async def validate_batch(self, data: List[Dict[str, Any]]) -> Dict[str, tuple[bool, List[str]]]:
        """Validate multiple items"""
        pass

class PluginError(Exception):
    """Base exception for plugin errors"""
    pass

class PluginInitializationError(PluginError):
    """Raised when plugin fails to initialize"""
    pass

class PluginConfigurationError(PluginError):
    """Raised when plugin configuration is invalid"""
    pass

class PluginExecutionError(PluginError):
    """Raised when plugin execution fails"""
    pass