from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class SvcScan(BasePlugin):
    """Lists Windows services"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the SvcScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.svcscan.SvcScan"])

class CmdLine(BasePlugin):
    """Shows process command line arguments"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the CmdLine plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.cmdline.CmdLine"])

class DllList(BasePlugin):
    """Lists loaded DLLs for each process"""
    
    async def run(self, memory_dump_path: str, pid: Optional[int] = None, kw_args: Dict[str, Any] = None) -> str:
        """Run the DllList plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.dlllist.DllList"]
        if pid is not None:
            cmd_args.extend(["--pid", str(pid)])
        # run_plugin in volatility_mcp_server.py will handle passing pid from kw_args if present
            
        return await self.volatility_runner(cmd_args)

class Handles(BasePlugin):
    """Lists open handles for each process"""
    
    async def run(self, memory_dump_path: str, pid: Optional[int] = None, kw_args: Dict[str, Any] = None) -> str:
        """Run the Handles plugin with the given memory dump and optional keyword arguments.""" 
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.handles.Handles"]
        if pid is not None:
            cmd_args.extend(["--pid", str(pid)])
        # run_plugin in volatility_mcp_server.py will handle passing pid from kw_args if present
            
        return await self.volatility_runner(cmd_args)

class FileScan(BasePlugin):
    """Scans for file objects"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the FileScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.filescan.FileScan"])

class ImageInfo(BasePlugin):
    """Gets information about a memory dump file"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the ImageInfo plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.info.Info"]) 