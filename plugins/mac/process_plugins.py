from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class PsList(BasePlugin):
    """Lists the processes present in a particular mac memory image"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS PsList plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.pslist.PsList"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsTree(BasePlugin):
    """Plugin for listing processes in a tree based on their parent process ID"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS PsTree plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.pstree.PsTree"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Bash(BasePlugin):
    """Recovers bash command history from memory"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Bash plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.bash.Bash"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_syscall(BasePlugin):
    """Check system call table for hooks"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Check_syscall plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.check_syscall.Check_syscall"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_sysctl(BasePlugin):
    """Check sysctl handlers for hooks"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Check_sysctl plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.check_sysctl.Check_sysctl"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_trap_table(BasePlugin):
    """Check mach trap table for hooks"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Check_trap_table plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.check_trap_table.Check_trap_table"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Dmesg(BasePlugin):
    """Prints the kernel log buffer"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Dmesg plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.dmesg.Dmesg"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Ifconfig(BasePlugin):
    """Lists network interface information for all devices"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Ifconfig plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.ifconfig.Ifconfig"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Kauth_listeners(BasePlugin):
    """Lists kauth listeners and their status"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Kauth_listeners plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.kauth_listeners.Kauth_listeners"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Kauth_scopes(BasePlugin):
    """Lists kauth scopes and their status"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Kauth_scopes plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.kauth_scopes.Kauth_scopes"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Kevents(BasePlugin):
    """Lists event handlers registered by processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Kevents plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.kevents.Kevents"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class List_Files(BasePlugin):
    """Lists all open file descriptors for all processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS List_Files plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.list_files.List_Files"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Lsmod(BasePlugin):
    """Lists loaded kernel modules"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Lsmod plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.lsmod.Lsmod"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Lsof(BasePlugin):
    """Lists all open file descriptors for all processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Lsof plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.lsof.Lsof"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Malfind(BasePlugin):
    """Lists process memory ranges that potentially contain injected code"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Malfind plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.malfind.Malfind"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Mount(BasePlugin):
    """A module containing a collection of plugins that produce data typically found in Mac's mount command"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Mount plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.mount.Mount"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Netstat(BasePlugin):
    """Lists all network connections for all processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Netstat plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.netstat.Netstat"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Maps(BasePlugin):
    """Lists process memory ranges that potentially contain injected code"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Maps plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.proc_maps.Maps"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Psaux(BasePlugin):
    """Recovers program command line arguments"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Psaux plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.psaux.Psaux"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Socket_filters(BasePlugin):
    """Enumerates kernel socket filters"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Socket_filters plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.socket_filters.Socket_filters"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Timers(BasePlugin):
    """Check for malicious kernel timers"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Timers plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.timers.Timers"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Trustedbsd(BasePlugin):
    """Checks for malicious trustedbsd modules"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS Trustedbsd plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.trustedbsd.Trustedbsd"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class VFSevents(BasePlugin):
    """Lists processes that are filtering file system events"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the macOS VFSevents plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "mac.vfsevents.VFSevents"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args) 