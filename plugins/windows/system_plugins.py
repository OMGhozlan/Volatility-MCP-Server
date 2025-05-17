from typing import Optional
from ..base_plugin import BasePlugin

class SvcScan(BasePlugin):
    """Lists Windows services"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.svcscan.SvcScan"])

class CmdLine(BasePlugin):
    """Shows process command line arguments"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.cmdline.CmdLine"])

class DllList(BasePlugin):
    """Lists loaded DLLs for each process"""
    
    async def run(self, memory_dump_path: str, pid: Optional[int] = None) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.dlllist.DllList"]
        if pid is not None:
            cmd_args.extend(["--pid", str(pid)])
            
        return await self.volatility_runner(cmd_args)

class Handles(BasePlugin):
    """Lists open handles for each process"""
    
    async def run(self, memory_dump_path: str, pid: Optional[int] = None) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "windows.handles.Handles"]
        if pid is not None:
            cmd_args.extend(["--pid", str(pid)])
            
        return await self.volatility_runner(cmd_args)

class FileScan(BasePlugin):
    """Scans for file objects"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.filescan.FileScan"])

class ImageInfo(BasePlugin):
    """Gets information about a memory dump file"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.info.Info"]) 