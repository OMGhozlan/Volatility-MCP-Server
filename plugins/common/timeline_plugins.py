from typing import Optional
from ..base_plugin import BasePlugin

class Timeliner(BasePlugin):
    """Runs all relevant plugins that provide time related information and orders the results by time"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "timeliner.Timeliner"])

class Timeline(BasePlugin):
    """Generates a timeline of events from memory"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "timeliner.Timeline"]) 