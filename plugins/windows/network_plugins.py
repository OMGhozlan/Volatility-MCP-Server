from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class NetScan(BasePlugin):
    """Lists all network connections for all processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the NetScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.netscan.NetScan"]
        # Add any relevant args from kw_args if needed by NetScan
            
        return await self.volatility_runner(cmd_args) 