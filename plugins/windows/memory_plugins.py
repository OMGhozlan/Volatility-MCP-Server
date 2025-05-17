from typing import Optional
from ..base_plugin import BasePlugin

class Malfind(BasePlugin):
    """Lists process memory ranges that potentially contain injected code"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.malfind.Malfind"])

class MemMap(BasePlugin):
    """Shows the memory map for a specific process"""
    
    async def run(self, memory_dump_path: str, pid: int) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.memmap.Memmap", "--pid", str(pid)]) 