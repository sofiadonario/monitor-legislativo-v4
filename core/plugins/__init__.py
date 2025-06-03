"""
Plugin System for Monitor Legislativo v4
Provides extensibility through plugins

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .plugin_base import (
    PluginInterface,
    PluginType,
    PluginMetadata,
    DataSourcePlugin,
    ProcessorPlugin,
    ExporterPlugin,
    NotifierPlugin,
    AnalyzerPlugin,
    ValidatorPlugin,
    PluginError,
    PluginInitializationError,
    PluginConfigurationError,
    PluginExecutionError
)

from .plugin_manager import (
    PluginManager,
    plugin_manager,
    load_plugin,
    get_plugin,
    discover_plugins
)

__all__ = [
    # Base classes
    "PluginInterface",
    "PluginType",
    "PluginMetadata",
    "DataSourcePlugin",
    "ProcessorPlugin",
    "ExporterPlugin",
    "NotifierPlugin",
    "AnalyzerPlugin",
    "ValidatorPlugin",
    
    # Exceptions
    "PluginError",
    "PluginInitializationError",
    "PluginConfigurationError",
    "PluginExecutionError",
    
    # Manager
    "PluginManager",
    "plugin_manager",
    "load_plugin",
    "get_plugin",
    "discover_plugins"
]