from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class RegExScan(BasePlugin):
    """Scans kernel memory using RegEx patterns"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common RegExScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "regexscan.RegExScan"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class YaraScan(BasePlugin):
    """Scans kernel memory using yara rules (string or file)"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common YaraScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "yarascan.YaraScan"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Vmscan(BasePlugin):
    """Scans for Intel VT-d structures and generates VM volatility configs for them"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common Vmscan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "vmscan.Vmscan"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args) 