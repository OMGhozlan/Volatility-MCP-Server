from ..base_plugin import BasePlugin

class PluginHelp(BasePlugin):
    """
    Lists the command parameters for a given plugin by appending --help
    to the plugin's name.
    """
    async def run(self, memory_dump_path: str, plugin_name: str) -> str:
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        # Call volatility_runner with the --help flag after the plugin name
        return await self.volatility_runner(["-f", memory_dump_path, plugin_name, "--help"])