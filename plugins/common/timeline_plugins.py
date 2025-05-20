from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class Timeliner(BasePlugin):
    """Runs all relevant plugins that provide time related information and orders the results by time"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common Timeliner plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "timeliner.Timeliner"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Timeline(BasePlugin):
    """Generates a timeline of events from memory"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the common Timeline plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "timeliner.Timeline"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args) 