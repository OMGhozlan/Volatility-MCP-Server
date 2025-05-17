from typing import Optional
from ..base_plugin import BasePlugin

class PsList(BasePlugin):
    """Lists running processes"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.pslist.PsList"])

class PsTree(BasePlugin):
    """Shows process tree"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.pstree.PsTree"])

class PsScan(BasePlugin):
    """Scans for processes that might be hidden"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.psscan.PsScan"]) 