# ❄️ Volatility MCP Server

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Volatility 3](https://img.shields.io/badge/Volatility-3.x-success)](https://github.com/volatilityfoundation/volatility3)
[![Docker (Not) Ready](https://img.shields.io/badge/Docker-Ready-green)](https://hub.docker.com/)
[![FastMCP](https://img.shields.io/badge/FastMCP-Server-red.svg)](https://github.com/Textualize/fastmcp)

---

## 📌 Overview

The Volatility MCP Server is a powerful memory forensics automation toolkit powered by **Volatility 3**. It provides a modular, extensible interface for running Volatility plugins across Windows, Linux, and macOS memory dumps.

It makes memory analysis faster and more accessible via:

✅ Plugin automation  
✅ Cross-platform support (Windows, Linux, macOS)  
✅ Modular plugin architecture  
✅ Rich logging with beautiful formatting  
✅ Easy plugin registration and management  

---

## 💡 Key Features

- 🔍 Powered by **Volatility 3**
- 🧠 Supports Windows, Linux, and macOS plugins
- ⚙️ Asynchronous plugin execution
- 📤 JSON output format
- 📊 Built-in error handling and validation
- 👨‍💻 FastMCP server interface
- 🐳 Docker-ready environment

---

## 📦 Requirements

```bash
python 3.11+
pip install -r requirements.txt
```

**requirements.txt:**
```
fastmcp
rich
python-dotenv
```

---

## 📁 Project Structure

```
Volatility-MCP-Server/
├── volatility_mcp_server.py    # Main server implementation
├── plugins/                    # Plugin modules
│   ├── base_plugin.py         # Base plugin class
│   ├── plugin_factory.py      # Plugin registration
│   ├── windows/               # Windows plugins
│   ├── linux/                 # Linux plugins
│   ├── mac/                   # macOS plugins
│   └── common/                # Common plugins
├── requirements.txt           # Dependencies
└── README.md                 # This file
```

---

## 🖥️ Usage

### 🔧 Local Connection
#### Using `stdio`
Create a `.cursor/mcp.json` file with:

```json
{
  "mcpServers": {
    "Volatility3": {
      "command": "fastmcp",
      "args": ["run", "path/to/volatility_mcp_server.py:mcp", "--transport", "stdio"]
    }
  }
}
```
#### Using `sse`
Run the server using
```pwsh
fastmcp run volatility_mcp_server.py:mcp --transport sse
```
For Claude desktop
```json
{
    "mcpServers": {
      "volatility3": {
        "command": "npx",
        "args": ["mcp-remote", "http://localhost:8000/sse"]
      }
    }
  }
```
For Cursor
```json
{
  "mcpServers": {
    "Volatility3": {
      "url": "http://localhost:8000/sse"
    }
  }
}
```

### 📊 Available Plugins

#### Windows Plugins
- Process: `PsList`, `PsTree`, `PsScan`
- Memory: `Malfind`, `MemMap`
- Network: `NetScan`
- Registry: `RegistryHiveList`, `RegistryPrintKey`
- System: `SvcScan`, `CmdLine`, `DllList`, `Handles`, `FileScan`
- Disk: `ADS`, `MFTScan`, `ResidentData`

#### Linux Plugins
- Process: `PsList`, `PsTree`, `PsScan`, `PsAux`, `PsCallStack`
- System: `Bash`, `Boottime`, `Capabilities`
- Network: `IpAddr`, `IpLink`, `Netfilter`
- Memory: `Malfind`, `ModuleExtract`
- File System: `Files`, `InodePages`, `RecoverFs`

#### macOS Plugins
- Process: `PsList`, `PsTree`, `Psaux`
- System: `Bash`, `Dmesg`, `Lsmod`
- Network: `Ifconfig`, `Netstat`
- Security: `Check_syscall`, `Check_sysctl`, `Check_trap_table`

#### Common Plugins
- Framework: `Banners`, `ConfigWriter`, `FrameworkInfo`, `IsfInfo`, `LayerWriter`
- Scan: `RegExScan`, `YaraScan`, `Vmscan`
- Timeline: `Timeliner`

---

## 🐳 Docker Usage (No idea what I wanted to do here but might be useful in the future)

### ⚙️ 1. Build the Docker Image

From the root directory:

```bash
docker build -t volatility-mcp .
```

### ▶️ 2. Run the Server

```bash
docker run --rm -it \
  -v $(pwd)/memdumps:/memdumps \
  -v $(pwd)/output:/output \
  volatility-mcp
```

---

## 🔧 Developer/Contributor Guide

### 🧱 Setup Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 🧪 Run Locally

```bash
python volatility_mcp_server.py
```

---

## ✍️ Customization Tips

- 📀 Want to add a new plugin? Extend `BasePlugin` and register it in `plugin_factory.py`
- 🧩 Want to add a new OS? Create a new plugin directory and implement the plugins
- 📚 Want to add new features? The modular architecture makes it easy to extend

---

## 🙋 FAQ

> 🟠 **Does this support Volatility 2.x?**  
🔻 No. This server supports **Volatility 3 only** for modern plugin support.

> 🔵 **Can I add custom plugins?**  
✅ Yes! Just extend the `BasePlugin` class and register it in the factory.

> 🔴 **Why use FastMCP?**  
It provides a clean, efficient interface for running Volatility plugins with proper error handling and async support.

---

## 📜 License

MIT ©️ 2025

---

## 🌐 More Tools?

You may also like:
- [Volatility Foundation](https://www.volatilityfoundation.org/)
- [FastMCP Documentation](https://github.com/Textualize/fastmcp)
- [Python-dotenv](https://github.com/theskumar/python-dotenv)
