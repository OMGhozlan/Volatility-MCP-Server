from typing import Optional
from ..base_plugin import BasePlugin

class Banners(BasePlugin):
    """Attempts to identify potential linux banners in an image"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "banners.Banners"])

class ConfigWriter(BasePlugin):
    """Runs the automagics and both prints and outputs configuration in the output directory"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "configwriter.ConfigWriter"])

class FrameworkInfo(BasePlugin):
    """Plugin to list the various modular components of Volatility"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "frameworkinfo.FrameworkInfo"])

class IsfInfo(BasePlugin):
    """Determines information about the currently available ISF files, or a specific one"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "isfinfo.IsfInfo"])

class LayerWriter(BasePlugin):
    """Runs the automagics and writes out the primary layer produced by the stacker"""
    
    async def run(self, memory_dump_path: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        return await self.volatility_runner(["-f", memory_dump_path, "layerwriter.LayerWriter"]) 