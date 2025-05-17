from typing import Optional
from ..base_plugin import BasePlugin

class RegExScan(BasePlugin):
    """Scans kernel memory using RegEx patterns"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "regexscan.RegExScan"])

class YaraScan(BasePlugin):
    """Scans kernel memory using yara rules (string or file)"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "yarascan.YaraScan"])

class Vmscan(BasePlugin):
    """Scans for Intel VT-d structures and generates VM volatility configs for them"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "vmscan.Vmscan"]) 