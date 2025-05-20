from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class PsList(BasePlugin):
    """Lists running processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the PsList plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.pslist.PsList"]
        # Add any relevant args from kw_args if needed by PsList
        # Example: if PsList had an optional --pid argument
        # if kw_args and "pid" in kw_args:
        #     cmd_args.extend(["--pid", str(kw_args["pid"])])
            
        return await self.volatility_runner(cmd_args)

class PsTree(BasePlugin):
    """Shows process tree"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the PsTree plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.pstree.PsTree"]
        # Add any relevant args from kw_args if needed by PsTree
            
        return await self.volatility_runner(cmd_args)

class PsScan(BasePlugin):
    """Scans for processes that might be hidden"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the PsScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.psscan.PsScan"]
        # Add any relevant args from kw_args if needed by PsScan
            
        return await self.volatility_runner(cmd_args) 