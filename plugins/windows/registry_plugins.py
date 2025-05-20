from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class RegistryHiveList(BasePlugin):
    """Lists all registry hives in memory"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the RegistryHiveList plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.registry.hivelist.HiveList"]
        # Add any relevant args from kw_args if needed by RegistryHiveList
            
        return await self.volatility_runner(cmd_args)

class RegistryPrintKey(BasePlugin):
    """Prints the contents of a registry key"""
    
    async def run(self, memory_dump_path: str, key: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the RegistryPrintKey plugin with the given memory dump, a key, and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.registry.printkey.PrintKey", "--key", key]
        # run_plugin in volatility_mcp_server.py will handle passing key from kw_args if present
        # Add any other relevant args from kw_args if needed by RegistryPrintKey
            
        return await self.volatility_runner(cmd_args) 