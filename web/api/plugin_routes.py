"""
Plugin Management Routes for Monitor Legislativo v4
API endpoints for plugin discovery and management

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from core.plugins import plugin_manager, PluginType
from core.auth.decorators import require_admin

router = APIRouter(tags=["plugins"])

class PluginConfig(BaseModel):
    """Plugin configuration model"""
    config: Dict[str, Any]

class PluginInfo(BaseModel):
    """Plugin information model"""
    name: str
    version: str
    type: str
    author: str
    description: str
    loaded: bool

@router.get("/plugins/discover", response_model=List[PluginInfo])
async def discover_plugins():
    """
    Discover all available plugins
    """
    try:
        plugins = await plugin_manager.discover_plugins()
        
        result = []
        for plugin in plugins:
            result.append(PluginInfo(
                name=plugin.name,
                version=plugin.version,
                type=plugin.plugin_type.value,
                author=plugin.author,
                description=plugin.description,
                loaded=plugin.name in plugin_manager.plugins
            ))
        
        return result
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/plugins/loaded", response_model=List[PluginInfo])
async def list_loaded_plugins():
    """
    List all currently loaded plugins
    """
    return plugin_manager.list_loaded_plugins()

@router.post("/plugins/{plugin_name}/load")
async def load_plugin(
    plugin_name: str,
    config: Optional[PluginConfig] = None,
    _admin = Depends(require_admin)
):
    """
    Load a specific plugin (requires admin)
    """
    try:
        plugin_config = config.config if config else {}
        success = await plugin_manager.load_plugin(plugin_name, plugin_config)
        
        if success:
            return {"message": f"Plugin {plugin_name} loaded successfully"}
        else:
            raise HTTPException(status_code=400, detail=f"Failed to load plugin {plugin_name}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/plugins/{plugin_name}/unload")
async def unload_plugin(
    plugin_name: str,
    _admin = Depends(require_admin)
):
    """
    Unload a specific plugin (requires admin)
    """
    try:
        success = await plugin_manager.unload_plugin(plugin_name)
        
        if success:
            return {"message": f"Plugin {plugin_name} unloaded successfully"}
        else:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/plugins/{plugin_name}/reload")
async def reload_plugin(
    plugin_name: str,
    _admin = Depends(require_admin)
):
    """
    Reload a plugin with same configuration (requires admin)
    """
    try:
        success = await plugin_manager.reload_plugin(plugin_name)
        
        if success:
            return {"message": f"Plugin {plugin_name} reloaded successfully"}
        else:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/plugins/{plugin_name}/health")
async def plugin_health_check(plugin_name: str):
    """
    Check health status of a specific plugin
    """
    plugin = plugin_manager.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
    
    try:
        health = await plugin.health_check()
        return health
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

@router.get("/plugins/health")
async def all_plugins_health():
    """
    Check health status of all loaded plugins
    """
    try:
        return await plugin_manager.health_check_all()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/plugins/types")
async def list_plugin_types():
    """
    List all available plugin types
    """
    return [
        {
            "type": plugin_type.value,
            "description": get_type_description(plugin_type)
        }
        for plugin_type in PluginType
    ]

def get_type_description(plugin_type: PluginType) -> str:
    """Get description for plugin type"""
    descriptions = {
        PluginType.DATA_SOURCE: "Plugins that provide data from external sources",
        PluginType.PROCESSOR: "Plugins that process and transform data",
        PluginType.EXPORTER: "Plugins that export data to various formats",
        PluginType.NOTIFIER: "Plugins that send notifications",
        PluginType.ANALYZER: "Plugins that analyze data and provide insights",
        PluginType.VALIDATOR: "Plugins that validate data integrity"
    }
    return descriptions.get(plugin_type, "Unknown plugin type")

# Plugin-specific endpoints for common operations

@router.post("/plugins/export/{plugin_name}")
async def export_with_plugin(
    plugin_name: str,
    data: List[Dict[str, Any]],
    options: Optional[Dict[str, Any]] = None
):
    """
    Export data using a specific exporter plugin
    """
    plugin = plugin_manager.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
    
    metadata = plugin_manager.plugin_metadata.get(plugin_name)
    if metadata.plugin_type != PluginType.EXPORTER:
        raise HTTPException(status_code=400, detail=f"Plugin {plugin_name} is not an exporter")
    
    try:
        result = await plugin.export(data, options)
        return {"filepath": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/plugins/analyze/{plugin_name}")
async def analyze_with_plugin(
    plugin_name: str,
    data: List[Dict[str, Any]]
):
    """
    Analyze data using a specific analyzer plugin
    """
    plugin = plugin_manager.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
    
    metadata = plugin_manager.plugin_metadata.get(plugin_name)
    if metadata.plugin_type != PluginType.ANALYZER:
        raise HTTPException(status_code=400, detail=f"Plugin {plugin_name} is not an analyzer")
    
    try:
        result = await plugin.analyze(data)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))