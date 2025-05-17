from typing import Optional
from ..base_plugin import BasePlugin

class NetScan(BasePlugin):
    """Lists all network connections for all processes"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.netscan.NetScan"]) 