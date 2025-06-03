"""
Plugin Manager for Monitor Legislativo v4
Manages plugin lifecycle and registration

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import os
import importlib
import importlib.util
import logging
import asyncio
from typing import Dict, List, Optional, Type, Any
from pathlib import Path
import json
import yaml

from .plugin_base import (
    PluginInterface, PluginType, PluginMetadata,
    PluginError, PluginInitializationError, PluginConfigurationError
)

logger = logging.getLogger(__name__)

class PluginManager:
    """Manages plugin discovery, loading, and lifecycle"""
    
    def __init__(self, plugin_directories: List[str] = None):
        self.plugin_directories = plugin_directories or ["plugins"]
        self.plugins: Dict[str, PluginInterface] = {}
        self.plugin_metadata: Dict[str, PluginMetadata] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        
    async def discover_plugins(self) -> List[PluginMetadata]:
        """Discover all available plugins"""
        discovered = []
        
        for directory in self.plugin_directories:
            if not os.path.exists(directory):
                logger.warning(f"Plugin directory not found: {directory}")
                continue
                
            plugin_dir = Path(directory)
            
            # Look for plugin packages (directories with __init__.py)
            for item in plugin_dir.iterdir():
                if item.is_dir() and (item / "__init__.py").exists():
                    try:
                        metadata = await self._load_plugin_metadata(item)
                        if metadata:
                            discovered.append(metadata)
                            logger.info(f"Discovered plugin: {metadata.name} v{metadata.version}")
                    except Exception as e:
                        logger.error(f"Error discovering plugin in {item}: {e}")
                        
            # Look for single-file plugins
            for item in plugin_dir.glob("*.py"):
                if item.name.startswith("_"):
                    continue
                try:
                    metadata = await self._load_plugin_metadata(item)
                    if metadata:
                        discovered.append(metadata)
                        logger.info(f"Discovered plugin: {metadata.name} v{metadata.version}")
                except Exception as e:
                    logger.error(f"Error discovering plugin {item}: {e}")
                    
        return discovered
    
    async def _load_plugin_metadata(self, path: Path) -> Optional[PluginMetadata]:
        """Load plugin metadata from path"""
        # Check for metadata file
        metadata_file = None
        if path.is_dir():
            for ext in [".json", ".yaml", ".yml"]:
                candidate = path / f"plugin{ext}"
                if candidate.exists():
                    metadata_file = candidate
                    break
        
        if metadata_file:
            # Load from metadata file
            with open(metadata_file, 'r') as f:
                if metadata_file.suffix == ".json":
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
                    
            return PluginMetadata(
                name=data["name"],
                version=data["version"],
                author=data["author"],
                description=data["description"],
                plugin_type=PluginType(data["type"]),
                requires=data.get("requires", []),
                config_schema=data.get("config_schema", {})
            )
        else:
            # Try to load plugin and get metadata
            try:
                plugin_class = await self._import_plugin_class(path)
                if plugin_class:
                    instance = plugin_class()
                    return instance.get_metadata()
            except Exception as e:
                logger.debug(f"Could not load metadata from {path}: {e}")
                
        return None
    
    async def _import_plugin_class(self, path: Path) -> Optional[Type[PluginInterface]]:
        """Import and return the main plugin class"""
        try:
            if path.is_dir():
                # Package plugin
                module_name = f"plugins.{path.name}"
                spec = importlib.util.spec_from_file_location(
                    module_name,
                    path / "__init__.py"
                )
            else:
                # Single file plugin
                module_name = f"plugins.{path.stem}"
                spec = importlib.util.spec_from_file_location(
                    module_name,
                    path
                )
                
            if not spec or not spec.loader:
                return None
                
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find the plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, PluginInterface) and 
                    attr is not PluginInterface and
                    not attr.__name__.startswith("_")):
                    return attr
                    
        except Exception as e:
            logger.error(f"Error importing plugin from {path}: {e}")
            
        return None
    
    async def load_plugin(self, plugin_name: str, config: Dict[str, Any] = None) -> bool:
        """Load and initialize a specific plugin"""
        try:
            # Find plugin
            plugin_path = None
            for directory in self.plugin_directories:
                dir_path = Path(directory)
                
                # Check for package
                package_path = dir_path / plugin_name
                if package_path.is_dir() and (package_path / "__init__.py").exists():
                    plugin_path = package_path
                    break
                    
                # Check for single file
                file_path = dir_path / f"{plugin_name}.py"
                if file_path.exists():
                    plugin_path = file_path
                    break
                    
            if not plugin_path:
                raise PluginError(f"Plugin not found: {plugin_name}")
                
            # Import plugin class
            plugin_class = await self._import_plugin_class(plugin_path)
            if not plugin_class:
                raise PluginError(f"No plugin class found in {plugin_path}")
                
            # Create instance
            instance = plugin_class()
            metadata = instance.get_metadata()
            
            # Validate configuration
            if config:
                valid, error = instance.validate_config(config)
                if not valid:
                    raise PluginConfigurationError(f"Invalid configuration: {error}")
            else:
                config = {}
                
            # Initialize plugin
            success = await instance.initialize(config)
            if not success:
                raise PluginInitializationError(f"Plugin initialization failed")
                
            # Store plugin
            self.plugins[plugin_name] = instance
            self.plugin_metadata[plugin_name] = metadata
            self.plugin_configs[plugin_name] = config
            
            logger.info(f"Loaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False
    
    async def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name not in self.plugins:
            return False
            
        try:
            plugin = self.plugins[plugin_name]
            await plugin.shutdown()
            
            del self.plugins[plugin_name]
            del self.plugin_metadata[plugin_name]
            del self.plugin_configs[plugin_name]
            
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_name}: {e}")
            return False
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """Reload a plugin with same configuration"""
        if plugin_name not in self.plugins:
            return False
            
        config = self.plugin_configs.get(plugin_name, {})
        await self.unload_plugin(plugin_name)
        return await self.load_plugin(plugin_name, config)
    
    def get_plugin(self, plugin_name: str) -> Optional[PluginInterface]:
        """Get a loaded plugin instance"""
        return self.plugins.get(plugin_name)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginInterface]:
        """Get all loaded plugins of a specific type"""
        result = []
        for name, plugin in self.plugins.items():
            metadata = self.plugin_metadata[name]
            if metadata.plugin_type == plugin_type:
                result.append(plugin)
        return result
    
    def list_loaded_plugins(self) -> List[Dict[str, Any]]:
        """List all loaded plugins with their metadata"""
        result = []
        for name, metadata in self.plugin_metadata.items():
            result.append({
                "name": name,
                "version": metadata.version,
                "type": metadata.plugin_type.value,
                "author": metadata.author,
                "description": metadata.description,
                "loaded": name in self.plugins
            })
        return result
    
    async def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Run health check on all loaded plugins"""
        results = {}
        for name, plugin in self.plugins.items():
            try:
                results[name] = await plugin.health_check()
            except Exception as e:
                results[name] = {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
        return results
    
    async def shutdown_all(self) -> None:
        """Shutdown all loaded plugins"""
        logger.info("Shutting down all plugins...")
        
        tasks = []
        for name, plugin in self.plugins.items():
            tasks.append(self._shutdown_plugin(name, plugin))
            
        await asyncio.gather(*tasks, return_exceptions=True)
        
        self.plugins.clear()
        self.plugin_metadata.clear()
        self.plugin_configs.clear()
        
    async def _shutdown_plugin(self, name: str, plugin: PluginInterface) -> None:
        """Shutdown a single plugin"""
        try:
            await plugin.shutdown()
            logger.info(f"Shutdown plugin: {name}")
        except Exception as e:
            logger.error(f"Error shutting down plugin {name}: {e}")

# Global plugin manager instance
plugin_manager = PluginManager()

# Convenience functions
async def load_plugin(name: str, config: Dict[str, Any] = None) -> bool:
    """Load a plugin"""
    return await plugin_manager.load_plugin(name, config)

def get_plugin(name: str) -> Optional[PluginInterface]:
    """Get a loaded plugin"""
    return plugin_manager.get_plugin(name)

async def discover_plugins() -> List[PluginMetadata]:
    """Discover available plugins"""
    return await plugin_manager.discover_plugins()