from typing import Optional
from ..base_plugin import BasePlugin

class RegistryHiveList(BasePlugin):
    """Lists all registry hives in memory"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.registry.hivelist.HiveList"])

class RegistryPrintKey(BasePlugin):
    """Prints the contents of a registry key"""
    
    async def run(self, memory_dump_path: str, key: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.registry.printkey.PrintKey", "--key", key]) 