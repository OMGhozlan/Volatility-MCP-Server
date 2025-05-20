from typing import Dict, Type
from .base_plugin import BasePlugin
from . import windows, linux, mac, common

class PluginFactory:
    """Factory class for creating plugin instances"""
    
    _plugins: Dict[str, Type[BasePlugin]] = {}
    
    @classmethod
    def register_plugin(cls, name: str, plugin_class: Type[BasePlugin]) -> None:
        """Register a plugin class with the factory"""
        cls._plugins[name] = plugin_class
        
    @classmethod
    def get_plugin(cls, name: str, volatility_runner) -> BasePlugin:
        """Get a plugin instance by name"""
        if name not in cls._plugins:
            raise ValueError(f"Plugin '{name}' not found")
        return cls._plugins[name](volatility_runner)
        
    @classmethod
    def list_plugins(cls) -> Dict[str, str]:
        """List all registered plugins and their descriptions"""
        return {
            name: plugin.__doc__ or "No description available"
            for name, plugin in cls._plugins.items()
        }
        
    @classmethod
    def register_windows_plugins(cls, volatility_runner) -> None:
        """Register all Windows plugins"""
        from .windows import __all__ as windows_plugins
        for plugin_name in windows_plugins:
            plugin_class = getattr(windows, plugin_name)
            cls.register_plugin(f"windows.{plugin_name}", plugin_class)
            
    @classmethod
    def register_linux_plugins(cls, volatility_runner) -> None:
        """Register all Linux plugins"""
        from .linux import __all__ as linux_plugins
        for plugin_name in linux_plugins:
            plugin_class = getattr(linux, plugin_name)
            cls.register_plugin(f"linux.{plugin_name}", plugin_class)
            
    @classmethod
    def register_mac_plugins(cls, volatility_runner) -> None:
        """Register all macOS plugins"""
        from .mac import __all__ as mac_plugins
        for plugin_name in mac_plugins:
            plugin_class = getattr(mac, plugin_name)
            cls.register_plugin(f"mac.{plugin_name}", plugin_class)
            
    @classmethod
    def register_common_plugins(cls, volatility_runner) -> None:
        """Register all common plugins"""
        from .common import __all__ as common_plugins
        for plugin_name in common_plugins:
            plugin_class = getattr(common, plugin_name)
            cls.register_plugin(plugin_name, plugin_class) 