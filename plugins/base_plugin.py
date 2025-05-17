from abc import ABC, abstractmethod
from typing import List, Optional, Union
from pathlib import Path

class BasePlugin(ABC):
    """Base class for all Volatility plugins"""
    
    def __init__(self, volatility_runner):
        self.volatility_runner = volatility_runner
        
    def validate_memory_dump(self, memory_dump_path: str) -> str:
        """Validate that the memory dump file exists"""
        memory_dump_path = str(Path(memory_dump_path).resolve())
        if not Path(memory_dump_path).is_file():
            return f"Error: Memory dump file not found at {memory_dump_path}"
        return memory_dump_path
        
    @abstractmethod
    async def run(self, memory_dump_path: str) -> str:
        """Run the plugin with the given memory dump"""
        pass 