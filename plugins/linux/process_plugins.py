from typing import Optional, Dict, Any
from ..base_plugin import BasePlugin

class PsList(BasePlugin):
    """Lists the processes present in a particular linux memory image"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux PsList plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.pslist.PsList"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsTree(BasePlugin):
    """Plugin for listing processes in a tree based on their parent process ID"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux PsTree plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.pstree.PsTree"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsScan(BasePlugin):
    """Scans for processes present in a particular linux image"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux PsScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.psscan.PsScan"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsAux(BasePlugin):
    """Lists processes with their command line arguments"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux PsAux plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.psaux.PsAux"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PsCallStack(BasePlugin):
    """Enumerates the call stack of each task"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux PsCallStack plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.pscallstack.PsCallStack"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PIDHashTable(BasePlugin):
    """Enumerates processes through the PID hash table"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux PIDHashTable plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.pidhashtable.PIDHashTable"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Bash(BasePlugin):
    """Recovers bash command history from memory"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Bash plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.bash.Bash"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Boottime(BasePlugin):
    """Shows the time the system was started"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Boottime plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.boottime.Boottime"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Capabilities(BasePlugin):
    """Lists process capabilities"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Capabilities plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.capabilities.Capabilities"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_afinfo(BasePlugin):
    """Verifies the operation function pointers of network protocols"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Check_afinfo plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.check_afinfo.Check_afinfo"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_creds(BasePlugin):
    """Checks if any processes are sharing credential structures"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Check_creds plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.check_creds.Check_creds"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_idt(BasePlugin):
    """Checks if the IDT has been altered"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Check_idt plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.check_idt.Check_idt"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_modules(BasePlugin):
    """Compares module list to sysfs info, if available"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Check_modules plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.check_modules.Check_modules"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Check_syscall(BasePlugin):
    """Check system call table for hooks"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Check_syscall plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.check_syscall.Check_syscall"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class EBPF(BasePlugin):
    """Enumerate eBPF programs"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux EBPF plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.ebpf.EBPF"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Elfs(BasePlugin):
    """Lists all memory mapped ELF files for all processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Elfs plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.elfs.Elfs"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Envars(BasePlugin):
    """Lists processes with their environment variables"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Envars plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.envars.Envars"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Fbdev(BasePlugin):
    """Extract framebuffers from the fbdev graphics subsystem"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Fbdev plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.graphics.fbdev.Fbdev"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Hidden_modules(BasePlugin):
    """Carves memory to find hidden kernel modules"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Hidden_modules plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.hidden_modules.Hidden_modules"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class IOMem(BasePlugin):
    """Generates an output similar to /proc/iomem on a running system"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux IOMem plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.iomem.IOMem"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class IpAddr(BasePlugin):
    """Lists network interface information for all devices"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux IpAddr plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.ip.Addr"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class IpLink(BasePlugin):
    """Lists information about network interfaces similar to `ip link show`"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux IpLink plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.ip.Link"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Kallsyms(BasePlugin):
    """Kallsyms symbols enumeration plugin"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Kallsyms plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.kallsyms.Kallsyms"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Keyboard_notifiers(BasePlugin):
    """Parses the keyboard notifier call chain"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Keyboard_notifiers plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.keyboard_notifiers.Keyboard_notifiers"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Kmsg(BasePlugin):
    """Kernel log buffer reader"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Kmsg plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.kmsg.Kmsg"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Kthreads(BasePlugin):
    """Lists kernel threads"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Kthreads plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.kthreads.Kthreads"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class LibraryList(BasePlugin):
    """Lists the libraries used by processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux LibraryList plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.librarylist.LibraryList"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Lsmod(BasePlugin):
    """Lists loaded kernel modules"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Lsmod plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.lsmod.Lsmod"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Lsof(BasePlugin):
    """Lists open files for each process"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Lsof plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.lsof.Lsof"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Malfind(BasePlugin):
    """Lists process memory ranges that potentially contain injected code"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Malfind plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.malfind.Malfind"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class ModuleExtract(BasePlugin):
    """Extracts loaded kernel modules"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux ModuleExtract plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.module_extract.ModuleExtract"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Modxview(BasePlugin):
    """View the kernel module in memory"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Modxview plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.modxview.Modxview"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class MountInfo(BasePlugin):
    """Displays information about the mount points"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux MountInfo plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.mountinfo.MountInfo"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Netfilter(BasePlugin):
    """Lists Netfilter hooks and objects"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Netfilter plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.netfilter.Netfilter"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Files(BasePlugin):
    """Lists file objects present in a memory image"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Files plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.files.Files"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class InodePages(BasePlugin):
    """Lists inode pages"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux InodePages plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.files.inode_pages.InodePages"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class RecoverFs(BasePlugin):
    """Recovers a file system from a memory dump"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux RecoverFs plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.files.recoverfs.RecoverFs"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class ProcMaps(BasePlugin):
    """Lists memory mapped files for each process"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux ProcMaps plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.proc.maps.ProcMaps"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Ptrace(BasePlugin):
    """Examines ptrace relationships between processes"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Ptrace plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.ptrace.Ptrace"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class Sockstat(BasePlugin):
    """Lists active network connections from sockstat"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux Sockstat plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.sockstat.Sockstat"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class CheckFtrace(BasePlugin):
    """Checks ftrace handlers for hooks"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux CheckFtrace plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.systemd.check_ftrace.CheckFtrace"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class PerfEvents(BasePlugin):
    """Lists registered perf events"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux PerfEvents plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.systemd.perf_events.PerfEvents"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class CheckTracepoints(BasePlugin):
    """Checks tracepoints for hooks"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux CheckTracepoints plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.systemd.check_tracepoints.CheckTracepoints"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class TtyCheck(BasePlugin):
    """Checks tty structures for hooks"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux TtyCheck plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.tty.tty_check.TtyCheck"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class VmaRegExScan(BasePlugin):
    """Scans address spaces using RegEx patterns"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux VmaRegExScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.vma.regexscan.VmaRegExScan"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class VmaYaraScan(BasePlugin):
    """Scans address spaces using yara rules (string or file)"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux VmaYaraScan plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.vma.yarascan.VmaYaraScan"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args)

class VMCoreInfo(BasePlugin):
    """Collects memory information from a VMCore dump"""
    
    async def run(self, memory_dump_path: str, kw_args: Dict[str, Any] = None) -> str:
        """Run the Linux VMCoreInfo plugin with the given memory dump and optional keyword arguments."""
        memory_dump_path = self.validate_memory_dump(memory_dump_path)
        if memory_dump_path.startswith("Error"):
            return memory_dump_path
            
        cmd_args = ["-f", memory_dump_path, "linux.vmcoreinfo.VMCoreInfo"]
        # Add any relevant args from kw_args
            
        return await self.volatility_runner(cmd_args) 