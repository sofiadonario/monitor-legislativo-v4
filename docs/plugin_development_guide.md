# Plugin Development Guide - Monitor Legislativo v4

**Developed by:** Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães  
**Organization:** MackIntegridade  
**Financing:** MackPesquisa

## Overview

The Monitor Legislativo v4 plugin system allows developers to extend functionality without modifying core code. Plugins can provide new data sources, process data, export to different formats, send notifications, analyze trends, or validate data integrity.

## Plugin Types

### 1. Data Source Plugin
Provides data from external sources (APIs, databases, files)

### 2. Processor Plugin  
Transforms and enriches data

### 3. Exporter Plugin
Exports data to various formats (CSV, PDF, Excel)

### 4. Notifier Plugin
Sends notifications (email, SMS, webhooks)

### 5. Analyzer Plugin
Analyzes data and provides insights

### 6. Validator Plugin
Validates data integrity and compliance

## Creating a Plugin

### Basic Structure

```python
from core.plugins.plugin_base import ExporterPlugin, PluginMetadata, PluginType

class MyPlugin(ExporterPlugin):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            version="1.0.0",
            author="Your Name",
            description="Plugin description",
            plugin_type=PluginType.EXPORTER,
            requires=[],
            config_schema={
                "option1": {
                    "type": "string",
                    "description": "Option description",
                    "default": "value"
                }
            }
        )
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        # Initialize plugin
        return True
    
    async def shutdown(self) -> None:
        # Cleanup resources
        pass
    
    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        # Validate configuration
        return True, None
```

### Plugin Location

Plugins can be:
1. **Single file**: `plugins/my_plugin.py`
2. **Package**: `plugins/my_plugin/__init__.py`

### Plugin Discovery

Add metadata file `plugin.yaml` or `plugin.json`:

```yaml
name: my_plugin
version: 1.0.0
author: Your Name
description: Plugin description
type: exporter
requires: []
config_schema:
  option1:
    type: string
    description: Option description
    default: value
```

## Example Plugins

### CSV Exporter
```python
class CSVExporterPlugin(ExporterPlugin):
    async def export(self, data: List[Dict[str, Any]], options: Dict[str, Any] = None) -> str:
        # Export to CSV
        filepath = "export.csv"
        with open(filepath, 'w') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        return filepath
```

### Email Notifier
```python
class EmailNotifierPlugin(NotifierPlugin):
    async def send_notification(self, recipient: str, subject: str, content: str, data: Dict[str, Any] = None) -> bool:
        # Send email
        return True
```

### Keyword Analyzer
```python
class KeywordAnalyzerPlugin(AnalyzerPlugin):
    async def analyze(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Analyze keywords
        keywords = Counter()
        for item in data:
            text = item.get("title", "") + " " + item.get("summary", "")
            words = text.lower().split()
            keywords.update(words)
        
        return {
            "top_keywords": keywords.most_common(10)
        }
```

## Plugin API

### Loading Plugins
```python
from core.plugins import plugin_manager

# Discover available plugins
plugins = await plugin_manager.discover_plugins()

# Load a plugin
success = await plugin_manager.load_plugin("csv_exporter", {
    "export_directory": "/path/to/exports"
})

# Get plugin instance
plugin = plugin_manager.get_plugin("csv_exporter")

# Use plugin
filepath = await plugin.export(data)
```

### REST API Endpoints

- `GET /api/v1/plugins/discover` - Discover available plugins
- `GET /api/v1/plugins/loaded` - List loaded plugins
- `POST /api/v1/plugins/{name}/load` - Load a plugin
- `POST /api/v1/plugins/{name}/unload` - Unload a plugin
- `GET /api/v1/plugins/{name}/health` - Check plugin health

## Best Practices

1. **Error Handling**: Always handle exceptions gracefully
2. **Logging**: Use the logging module for debugging
3. **Configuration**: Validate all configuration parameters
4. **Resources**: Clean up resources in shutdown()
5. **Documentation**: Provide clear metadata and descriptions
6. **Testing**: Include unit tests for your plugin

## Testing Your Plugin

```python
import pytest
from plugins.my_plugin import MyPlugin

@pytest.mark.asyncio
async def test_plugin_initialization():
    plugin = MyPlugin()
    assert await plugin.initialize({}) == True

@pytest.mark.asyncio 
async def test_plugin_functionality():
    plugin = MyPlugin()
    await plugin.initialize({})
    result = await plugin.export([{"test": "data"}])
    assert result is not None
```

## Publishing Your Plugin

1. Create a repository for your plugin
2. Include plugin.yaml with metadata
3. Add README with usage instructions
4. Submit to the plugin registry (coming soon)

## Security Considerations

- Validate all inputs
- Don't expose sensitive configuration
- Use secure communication protocols
- Follow the principle of least privilege
- Sanitize data before processing

## Support

For plugin development support:
- Check existing plugins for examples
- Review the plugin base classes
- Contact the development team

Happy plugin development! 🎉