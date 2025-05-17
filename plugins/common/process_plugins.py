from typing import Optional
from ..base_plugin import BasePlugin

class PsList(BasePlugin):
    """Lists the processes present in a memory image"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "pslist.PsList"])

class PsTree(BasePlugin):
    """Plugin for listing processes in a tree based on their parent process ID"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "pstree.PsTree"])

class PsScan(BasePlugin):
    """Scans for processes present in a memory image"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "psscan.PsScan"])

class PsAux(BasePlugin):
    """Lists processes with their command line arguments"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "psaux.PsAux"])

class PsCallStack(BasePlugin):
    """Enumerates the call stack of each task"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "pscallstack.PsCallStack"])

class PIDHashTable(BasePlugin):
    """Enumerates processes through the PID hash table"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "pidhashtable.PIDHashTable"]) 