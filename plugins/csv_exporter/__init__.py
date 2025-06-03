"""
CSV Exporter Plugin for Monitor Legislativo v4
Exports legislative data to CSV format

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import csv
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

from core.plugins.plugin_base import ExporterPlugin, PluginMetadata, PluginType

logger = logging.getLogger(__name__)

class CSVExporterPlugin(ExporterPlugin):
    """Plugin for exporting data to CSV format"""
    
    def __init__(self):
        self.config = {}
        self.export_directory = "data/exports"
        
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="csv_exporter",
            version="1.0.0",
            author="Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            description="Exports legislative data to CSV format with customizable fields",
            plugin_type=PluginType.EXPORTER,
            requires=[],
            config_schema={
                "export_directory": {
                    "type": "string",
                    "description": "Directory for exported files",
                    "default": "data/exports"
                },
                "delimiter": {
                    "type": "string",
                    "description": "CSV delimiter character",
                    "default": ","
                },
                "include_headers": {
                    "type": "boolean",
                    "description": "Include column headers",
                    "default": True
                },
                "encoding": {
                    "type": "string",
                    "description": "File encoding",
                    "default": "utf-8"
                }
            }
        )
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin"""
        try:
            self.config = config
            self.export_directory = config.get("export_directory", "data/exports")
            
            # Create export directory if it doesn't exist
            os.makedirs(self.export_directory, exist_ok=True)
            
            logger.info(f"CSV Exporter initialized with directory: {self.export_directory}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize CSV Exporter: {e}")
            return False
    
    async def shutdown(self) -> None:
        """Shutdown the plugin"""
        logger.info("CSV Exporter shutting down")
    
    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate plugin configuration"""
        # Check export directory
        export_dir = config.get("export_directory", "data/exports")
        try:
            # Try to create directory to validate path
            os.makedirs(export_dir, exist_ok=True)
        except Exception as e:
            return False, f"Invalid export directory: {e}"
        
        # Check delimiter
        delimiter = config.get("delimiter", ",")
        if len(delimiter) != 1:
            return False, "Delimiter must be a single character"
        
        # Check encoding
        encoding = config.get("encoding", "utf-8")
        try:
            "test".encode(encoding)
        except LookupError:
            return False, f"Invalid encoding: {encoding}"
        
        return True, None
    
    async def export(self, data: List[Dict[str, Any]], options: Dict[str, Any] = None) -> str:
        """Export data to CSV file"""
        if not data:
            return ""
        
        options = options or {}
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = options.get("filename", f"export_{timestamp}.csv")
        if not filename.endswith(".csv"):
            filename += ".csv"
        
        filepath = os.path.join(self.export_directory, filename)
        
        # Get configuration
        delimiter = self.config.get("delimiter", ",")
        include_headers = self.config.get("include_headers", True)
        encoding = self.config.get("encoding", "utf-8")
        
        # Determine fields
        if "fields" in options:
            fields = options["fields"]
        else:
            # Use all fields from first item
            fields = list(data[0].keys()) if data else []
        
        # Write CSV
        with open(filepath, 'w', newline='', encoding=encoding) as f:
            writer = csv.DictWriter(f, fieldnames=fields, delimiter=delimiter)
            
            if include_headers:
                writer.writeheader()
            
            for item in data:
                # Filter only requested fields
                row = {field: item.get(field, "") for field in fields}
                # Convert complex types to strings
                for key, value in row.items():
                    if isinstance(value, (list, dict)):
                        row[key] = str(value)
                    elif isinstance(value, datetime):
                        row[key] = value.isoformat()
                
                writer.writerow(row)
        
        logger.info(f"Exported {len(data)} items to {filepath}")
        return filepath
    
    def get_supported_formats(self) -> List[str]:
        """Return supported formats"""
        return ["csv", "tsv"]
    
    def get_export_options(self) -> Dict[str, Any]:
        """Return available export options"""
        return {
            "filename": {
                "type": "string",
                "description": "Output filename (without extension)",
                "required": False
            },
            "fields": {
                "type": "array",
                "description": "List of fields to export",
                "required": False
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Check plugin health"""
        health = {
            "status": "healthy",
            "export_directory": self.export_directory,
            "directory_writable": os.access(self.export_directory, os.W_OK),
            "timestamp": datetime.now().isoformat()
        }
        
        if not health["directory_writable"]:
            health["status"] = "degraded"
            health["error"] = "Export directory is not writable"
        
        return health

# Make the plugin class discoverable
__plugin__ = CSVExporterPlugin