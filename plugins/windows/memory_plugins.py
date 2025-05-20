from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class Malfind(BasePlugin):
    """Lists process memory ranges that potentially contain injected code"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Malfind plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.malfind.Malfind"]
        # Add any relevant args from kw_args if needed by Malfind
        # Example: if Malfind had an optional --dump-dir argument
        # if kw_args and "dump_dir" in kw_args:
        #     cmd_args.extend(["--dump-dir", str(kw_args["dump_dir"])])
            
        return await self.volatility_runner(cmd_args)

class MemMap(BasePlugin):
    """Shows the memory map for a specific process"""
    
    async def run(self, memory_dump_path: str, pid: int, kw_args: Dict[str, Any] = None) -> str:
        """Run the MemMap plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.memmap.Memmap", "--pid", str(pid)]
        # run_plugin in volatility_mcp_server.py will handle passing pid from kw_args if present
        # Add any other relevant args from kw_args if needed by MemMap
            
        return await self.volatility_runner(cmd_args) 