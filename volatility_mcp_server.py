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
from pydantic import BaseModel, Field  
  

from rich_logger import RichLogger
from plugins.plugin_factory import PluginFactory

# Initialize logger
logger = RichLogger.get_logger("volatility3_mcp")

# Loading environment variables
load_dotenv()

class KeywordArgs(BaseModel):  
    # Required fields  
    operation: str  
    # Optional dictionary that can contain any additional parameters  
    extra_params: Dict[str, Any] = Field(default_factory=dict)  

# Create an MCP server
mcp = FastMCP("Volatility3Forensics")

# Configuration
# Use environment variables for Docker compatibility
VOLATILITY_PYTHON = os.environ.get("VOLATILITY_PYTHON", sys.executable)
VOLATILITY_DIR = os.environ.get("VOLATILITY_DIR", "/opt/volatility3")
VOLATILITY_SCRIPT = os.environ.get("VOLATILITY_SCRIPT", os.path.join(VOLATILITY_DIR, "vol.py"))
SYMBOLS_DIR = os.environ.get("SYMBOLS_DIR", os.path.join(VOLATILITY_DIR, "symbols"))
# Add new configuration for memory images directory
MEMORY_IMAGES_DIR = os.environ.get("MEMORY_IMAGES_DIR", "/tmp/memimages/")

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
    timeout=360  # Seconds
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
async def run_plugin(memory_dump_path: str, plugin_name: str, os_type: str = 'windows', kw_args: dict = None) -> str:
    """
    Run a specific Volatility plugin with optional keyword arguments.

    Args:
        memory_dump_path: Full path to the memory dump file OR just the filename if it exists in /tmp/memimages/
        plugin_name: Name of the plugin to run.
        os_type: Optional 'windows', 'linux', or 'mac' (required for common plugins)
        kw_args: Optional dictionary of keyword arguments to pass to the plugin.

    Returns:
        Output from the specified plugin or an error message.
    """
    try:
        # Check if the path is just a filename or a full path
        if not os.path.isabs(memory_dump_path) or not os.path.exists(memory_dump_path):
            # Try to find the file in MEMORY_IMAGES_DIR
            potential_path = os.path.join(MEMORY_IMAGES_DIR, os.path.basename(memory_dump_path))
            if os.path.exists(potential_path):
                memory_dump_path = potential_path
                logger.info(f"Using memory dump from {MEMORY_IMAGES_DIR}: {memory_dump_path}")
            elif not os.path.exists(memory_dump_path):
                return f"Error: Memory dump file not found at {memory_dump_path} or in {MEMORY_IMAGES_DIR}"

        plugin = PluginFactory.get_plugin(plugin_name, volatility_runner)

        # Inspect the plugin's run method for parameters
        import inspect
        run_signature = inspect.signature(plugin.run)
        run_params = run_signature.parameters

        # Prepare arguments to pass to plugin.run
        plugin_args = {}
        if 'memory_dump_path' in run_params:
            plugin_args['memory_dump_path'] = memory_dump_path

        if kw_args:
            for param_name, param in run_params.items():
                # Check if the parameter is not memory_dump_path and is in kw_args
                if param_name != 'memory_dump_path' and param_name in kw_args:
                    plugin_args[param_name] = kw_args[param_name]

        return await plugin.run(**plugin_args)
    except ValueError as e:
        return str(e)
    except Exception as e:
        logger.exception(f"Error running plugin {plugin_name}: {str(e)}")
        return f"Error running plugin: {str(e)}"

@mcp.tool()
async def list_memory_dumps(search_dir: str = None) -> str:
    """
    List available memory dump files in a directory

    Args:
        search_dir: Directory to search for memory dumps (defaults to /tmp/memimages/ and current directory)

    Returns:
        List of potential memory dump files with their sizes
    """
    # If no search_dir specified, search in both MEMORY_IMAGES_DIR and current directory
    if not search_dir:
        search_dirs = [MEMORY_IMAGES_DIR, os.getcwd()]
    else:
        search_dirs = [os.path.normpath(search_dir)]
    
    # Look for common memory dump extensions
    memory_extensions = ['.raw', '.vmem', '.dmp', '.mem', '.bin', '.img', '.001', '.dump']
    all_memory_files = []

    for search_dir in search_dirs:
        if not os.path.isdir(search_dir):
            logger.warning(f"Directory not found: {search_dir}")
            continue
            
        memory_files = []
        for root, _, files in os.walk(search_dir):
            for file in files:
                if any(file.lower().endswith(ext) for ext in memory_extensions):
                    full_path = os.path.join(root, file)
                    size_mb = os.path.getsize(full_path) / (1024 * 1024)
                    memory_files.append(f"{full_path} (Size: {size_mb:.2f} MB)")
        
        if memory_files:
            all_memory_files.append(f"\n=== Memory dumps in {search_dir} ===")
            all_memory_files.extend(memory_files)

    if not all_memory_files:
        return f"No memory dump files found in searched directories: {', '.join(search_dirs)}"

    return "Found memory dump files:" + "\n".join(all_memory_files)

@mcp.tool()
async def download_memory_dump(url: str, filename: str = None) -> str:
    """
    Download a memory dump file from a URL to /tmp/memimages/

    Args:
        url: URL of the memory dump file to download
        filename: Optional custom filename (defaults to extracting from URL)

    Returns:
        Status message indicating success or failure with the saved file path
    """
    import aiohttp
    import aiofiles
    from urllib.parse import urlparse
    
    try:
        # Ensure the memory images directory exists
        os.makedirs(MEMORY_IMAGES_DIR, exist_ok=True)
        
        # Determine filename
        if not filename:
            parsed_url = urlparse(url)
            filename = os.path.basename(parsed_url.path)
            if not filename:
                filename = "memory_dump.raw"
        
        # Ensure the filename has a proper extension
        if not any(filename.lower().endswith(ext) for ext in ['.raw', '.vmem', '.dmp', '.mem', '.bin', '.img', '.001', '.dump']):
            filename += '.raw'
        
        destination_path = os.path.join(MEMORY_IMAGES_DIR, filename)
        
        # Check if file already exists
        if os.path.exists(destination_path):
            size_mb = os.path.getsize(destination_path) / (1024 * 1024)
            return f"File already exists at {destination_path} (Size: {size_mb:.2f} MB). Use a different filename if you want to download it again."
        
        logger.info(f"Downloading memory dump from {url} to {destination_path}")
        
        # Download the file
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                response.raise_for_status()
                
                # Get the total file size if available
                total_size = int(response.headers.get('content-length', 0))
                
                # Stream download to file
                async with aiofiles.open(destination_path, 'wb') as file:
                    downloaded = 0
                    chunk_size = 8192
                    
                    async for chunk in response.content.iter_chunked(chunk_size):
                        await file.write(chunk)
                        downloaded += len(chunk)
                        
                        # Log progress every 10MB
                        if downloaded % (10 * 1024 * 1024) < chunk_size:
                            if total_size:
                                progress = (downloaded / total_size) * 100
                                logger.info(f"Download progress: {progress:.1f}% ({downloaded / (1024*1024):.1f} MB / {total_size / (1024*1024):.1f} MB)")
                            else:
                                logger.info(f"Downloaded: {downloaded / (1024*1024):.1f} MB")
        
        # Verify the file was created and get its size
        if os.path.exists(destination_path):
            size_mb = os.path.getsize(destination_path) / (1024 * 1024)
            return f"Successfully downloaded memory dump to {destination_path} (Size: {size_mb:.2f} MB)"
        else:
            return f"Error: File was not created at {destination_path}"
            
    except aiohttp.ClientError as e:
        error_msg = f"Error downloading file from {url}: {str(e)}"
        logger.error(error_msg)
        # Clean up partial download if it exists
        if os.path.exists(destination_path):
            os.remove(destination_path)
        return error_msg
    except Exception as e:
        error_msg = f"Unexpected error downloading file: {str(e)}"
        logger.exception(error_msg)
        # Clean up partial download if it exists
        if os.path.exists(destination_path):
            os.remove(destination_path)
        return error_msg

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
    logger.info(f"Memory images directory: {MEMORY_IMAGES_DIR}")

    # Ensure directories exist
    os.makedirs(VOLATILITY_DIR, exist_ok=True)
    os.makedirs(SYMBOLS_DIR, exist_ok=True)
    os.makedirs(MEMORY_IMAGES_DIR, exist_ok=True)

    # Check if the volatility script exists
    if not os.path.isfile(VOLATILITY_SCRIPT):
        logger.error(f"Volatility script not found at {VOLATILITY_SCRIPT}")
        sys.exit(1)

    try:
        # Run the MCP server
        port = int(os.environ.get("MCP_PORT", 8080))
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        logger.info(f"Starting MCP server on {host}:{port}")
        
        asyncio.run(
        mcp.run_sse_async(
            host=host,
            port=port,
            log_level="debug"
        )
    )     
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.exception(f"Error starting server: {str(e)}")
        sys.exit(1)     