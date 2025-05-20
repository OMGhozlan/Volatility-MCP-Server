from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class Banners(BasePlugin):
    """Attempts to identify potential linux banners in an image"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Banners plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "banners.Banners"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class ConfigWriter(BasePlugin):
    """Runs the automagics and both prints and outputs configuration in the output directory"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the ConfigWriter plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "configwriter.ConfigWriter"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class FrameworkInfo(BasePlugin):
    """Plugin to list the various modular components of Volatility"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the FrameworkInfo plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "frameworkinfo.FrameworkInfo"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class IsfInfo(BasePlugin):
    """Determines information about the currently available ISF files, or a specific one"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the IsfInfo plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "isfinfo.IsfInfo"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class LayerWriter(BasePlugin):
    """Runs the automagics and writes out the primary layer produced by the stacker"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the LayerWriter plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "layerwriter.LayerWriter"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args) 