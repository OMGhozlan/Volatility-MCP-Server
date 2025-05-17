#!/usr/bin/env python3
import os
import sys
import json
import subprocess
import asyncio
from typing import List, Dict, Any, Optional, Union
from fastmcp import FastMCP
from dotenv import load_dotenv
import logging
from pathlib import Path

from rich_logger import RichLogger
from plugins.plugin_factory import PluginFactory

# Initialize logger
logger = RichLogger.get_logger("volatility3_mcp")

# Loading environment variables
load_dotenv()

# Create an MCP server
mcp = FastMCP("Volatility3Forensics")

# Configuration
# Use environment variables for Docker compatibility
VOLATILITY_PYTHON = os.environ.get("VOLATILITY_PYTHON", sys.executable)
VOLATILITY_DIR = os.environ.get("VOLATILITY_DIR", "/opt/volatility3")
VOLATILITY_SCRIPT = os.environ.get("VOLATILITY_SCRIPT", os.path.join(VOLATILITY_DIR, "vol.py"))
SYMBOLS_DIR = os.environ.get("SYMBOLS_DIR", os.path.join(VOLATILITY_DIR, "symbols"))

class VolatilityRunner:
    """Class to handle Volatility command execution with proper error handling and logging"""

    def __init__(
        self,
        volatility_python: Path,
        volatility_script: Path,
        volatility_dir: Path,   
        timeout: int,
        log_level: int = logging.INFO
    ):
        """
        Initialize VolatilityRunner

        Args:
            volatility_python: Path to Python executable
            volatility_script: Path to Volatility script
            volatility_dir: Working directory for Volatility
            log_level: Logging level (default: logging.INFO)
        """
        self.volatility_python = str(volatility_python)
        self.volatility_script = str(volatility_script)
        self.volatility_dir = str(volatility_dir)
        self.timeout = timeout

        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)

        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        # Validate paths
        self._validate_paths()

    def _validate_paths(self) -> None:
        """Validate that all required paths exist"""
        paths = {
            "Volatility Python": self.volatility_python,
            "Volatility Script": self.volatility_script,
            "Volatility Directory": self.volatility_dir
        }

        for name, path in paths.items():
            if not Path(path).exists():
                error_msg = f"{name} path does not exist: {path}"
                self.logger.error(error_msg)
                raise FileNotFoundError(error_msg)

    async def __call__(
        self,
        cmd_args: List[str],
        timeout: Optional[int] = None
    ) -> Union[str, Exception]:
        """
        Run a Volatility command

        Args:
            cmd_args: List of command arguments
            timeout: Command timeout in seconds

        Returns:
            Command output or error message
        """
        cmd = [self.volatility_python, self.volatility_script] + cmd_args
        cmd_str = ' '.join(cmd)

        self.logger.info(f"Running command: {cmd_str}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.volatility_dir
            )

            try:
                timeout = timeout or self.timeout 
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                error_msg = f"Command timed out after {timeout} seconds: {cmd_str}"
                self.logger.error(error_msg)
                return error_msg

            if process.returncode != 0:
                stderr_text = stderr.decode('utf-8', errors='replace')
                error_msg = f"Command failed with return code {process.returncode}: {stderr_text}"
                self.logger.error(error_msg)
                return error_msg

            output = stdout.decode('utf-8', errors='replace')
            self.logger.debug(f"Command completed successfully: {cmd_str}")
            return output

        except Exception as e:
            error_msg = f"Exception running command {cmd_str}: {str(e)}"
            self.logger.exception(error_msg)
            return error_msg

volatility_runner = VolatilityRunner(
    volatility_python=VOLATILITY_PYTHON,
    volatility_dir=VOLATILITY_DIR,
    volatility_script=VOLATILITY_SCRIPT,
    timeout=60  # Seconds
)

# Register all plugins
PluginFactory.register_windows_plugins(volatility_runner)
PluginFactory.register_linux_plugins(volatility_runner)
PluginFactory.register_mac_plugins(volatility_runner)
PluginFactory.register_common_plugins(volatility_runner)

@mcp.tool()
async def list_available_plugins() -> str:
    """
    List all available Volatility plugins

    Returns:
        A string containing all available Volatility plugins and their descriptions
    """
    plugins = PluginFactory.list_plugins()
    return json.dumps(plugins, indent=2)

@mcp.tool()
async def run_plugin(memory_dump_path: str, plugin_name: str) -> str:
    """
    Run a specific Volatility plugin

    Args:
        memory_dump_path: Full path to the memory dump file
        plugin_name: Name of the plugin to run

    Returns:
        Output from the specified plugin
    """
    try:
        plugin = PluginFactory.get_plugin(plugin_name, volatility_runner)
        return await plugin.run(memory_dump_path)
    except ValueError as e:
        return str(e)
    except Exception as e:
        logger.exception(f"Error running plugin {plugin_name}: {str(e)}")
        return f"Error running plugin: {str(e)}"

@mcp.tool()
async def list_memory_dumps(search_dir: str = str(os.getcwd())) -> str:
    """
    List available memory dump files in a directory

    Args:
        search_dir: Directory to search for memory dumps (defaults to current directory)

    Returns:
        List of potential memory dump files with their sizes
    """
    if not search_dir:
        search_dir = os.getcwd()

    search_dir = os.path.normpath(search_dir)
    if not os.path.isdir(search_dir):
        return f"Error: Directory not found at {search_dir}"

    # Look for common memory dump extensions
    memory_extensions = ['.raw', '.vmem', '.dmp', '.mem', '.bin', '.img', '.001', '.dump']
    memory_files = []

    for root, _, files in os.walk(search_dir):
        for file in files:
            if any(file.lower().endswith(ext) for ext in memory_extensions):
                full_path = os.path.join(root, file)
                size_mb = os.path.getsize(full_path) / (1024 * 1024)
                memory_files.append(f"{full_path} (Size: {size_mb:.2f} MB)")

    if not memory_files:
        return f"No memory dump files found in {search_dir}"

    return "Found memory dump files:\n" + "\n".join(memory_files)

@mcp.tool()
async def download_symbols(symbol_type: str = "windows") -> str:
    """
    Download symbol files for Volatility analysis

    Args:
        symbol_type: Type of symbols to download (windows, mac, linux)

    Returns:
        Status of symbol download operation
    """
    import requests
    import zipfile

    if symbol_type not in ["windows", "mac", "linux"]:
        return f"Error: Invalid symbol type '{symbol_type}'. Choose from: windows, mac, linux"

    symbol_urls = {
        "windows": "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip",
        "mac": "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip",
        "linux": "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip",
    }

    url = symbol_urls[symbol_type]
    destination = os.path.join(SYMBOLS_DIR, f"{symbol_type}.zip")
    extraction_dir = SYMBOLS_DIR

    # Create symbols directory if it doesn't exist
    os.makedirs(extraction_dir, exist_ok=True)

    # Check if symbols already exist
    if os.path.exists(os.path.join(extraction_dir, symbol_type)):
        return f"{symbol_type.capitalize()} symbols already exist."

    try:
        # Download symbols
        logger.info(f"Downloading {symbol_type} symbols from {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(destination, "wb") as f:
            for chunk in response.iter_content(8192):
                f.write(chunk)

        # Extract symbols
        logger.info(f"Extracting {symbol_type} symbols to {extraction_dir}")
        with zipfile.ZipFile(destination, 'r') as zip_ref:
            zip_ref.extractall(extraction_dir)

        # Clean up zip file
        os.remove(destination)

        return f"Successfully downloaded and extracted {symbol_type} symbols."
    except Exception as e:
        logger.exception(f"Failed to download symbols: {str(e)}")
        return f"Error downloading symbols: {str(e)}"

# Run the server
if __name__ == "__main__":
    logger.info(f"Starting Volatility3 MCP Server from: {VOLATILITY_DIR}")
    logger.info(f"Using Python: {VOLATILITY_PYTHON}")
    logger.info(f"Using Volatility script: {VOLATILITY_SCRIPT}")
    logger.info(f"Symbols directory: {SYMBOLS_DIR}")

    # Ensure directories exist
    os.makedirs(VOLATILITY_DIR, exist_ok=True)
    os.makedirs(SYMBOLS_DIR, exist_ok=True)

    # Check if the volatility script exists
    if not os.path.isfile(VOLATILITY_SCRIPT):
        logger.error(f"Volatility script not found at {VOLATILITY_SCRIPT}")
        sys.exit(1)

    try:
        # Run the MCP server
        port = int(os.environ.get("MCP_PORT", 8080))
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        logger.info(f"Starting MCP server on {host}:{port}")

        # Start the server
        mcp.run(transport="sse")
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.exception(f"Error starting server: {str(e)}")
        sys.exit(1)