from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class ADSScan(BasePlugin):
    """Scans for Alternate Data Stream"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the MFT ADS plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.mftscan.ADS"])

class MFTScan(BasePlugin):
    """Scans for MFT FILE objects"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the MFTScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "windows.mftscan.MFTScan"])

class ResidentData(BasePlugin):
    """Scans for MFT Records with Resident Data"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the ResidentData plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
                
        return await self.volatility_runner(["-f", memory_dump_path, "windows.mftscan.ResidentData"]) 