from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class PsList(BasePlugin):
    """Lists the processes present in a memory image"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common PsList plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "pslist.PsList"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsTree(BasePlugin):
    """Plugin for listing processes in a tree based on their parent process ID"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common PsTree plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "pstree.PsTree"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsScan(BasePlugin):
    """Scans for processes present in a memory image"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common PsScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "psscan.PsScan"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsAux(BasePlugin):
    """Lists processes with their command line arguments"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common PsAux plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "psaux.PsAux"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsCallStack(BasePlugin):
    """Enumerates the call stack of each task"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common PsCallStack plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "pscallstack.PsCallStack"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PIDHashTable(BasePlugin):
    """Enumerates processes through the PID hash table"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common PIDHashTable plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "pidhashtable.PIDHashTable"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args) 