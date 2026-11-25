"""Executor module for running compiled loaders."""

import csv
import ctypes
import os
import subprocess
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ExecutionResult:
    """Result of execution."""
    success: bool
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    runtime_seconds: float = 0.0
    process_id: Optional[int] = None
    error: Optional[str] = None
    crashed: bool = False
    
    # Success criteria results
    shellcode_success: bool = False  # Did the shellcode achieve its goal?
    success_details: Dict[str, Any] = field(default_factory=dict)


class Executor:
    """Executes compiled loaders and monitors their execution."""
    
    def __init__(self, config: dict):
        """Initialize executor.
        
        Args:
            config: Execution configuration from config.yaml
        """
        self.config = config
        self.wait_after_execute = config.get('wait_after_execute', 10)
        self.sandbox_mode = config.get('sandbox_mode', True)
        
        # Success criteria
        success_config = config.get('success_criteria', {})
        self.success_enabled = success_config.get('enabled', False)
        self.success_type = success_config.get('type', 'none')
        self.success_config = success_config
    
    def check_success_criteria(
        self,
        process_baseline: Optional[Dict[int, float]] = None,
        process_started_after: Optional[float] = None,
    ) -> tuple:
        """Check if shellcode execution was successful based on criteria.
        
        Returns:
            Tuple of (success: bool, details: dict)
        """
        if not self.success_enabled or self.success_type == 'none':
            return (True, {'note': 'No success criteria configured'})
        
        if self.success_type == 'process':
            return self._check_process_success(process_baseline, process_started_after)
        elif self.success_type == 'file':
            return self._check_file_success()
        elif self.success_type == 'network':
            return self._check_network_success()
        
        return (True, {'note': 'Unknown success type'})
    
    def _get_process_start_time(self, pid: int) -> Optional[float]:
        """Return a Windows process creation time as Unix seconds."""
        if os.name != 'nt':
            return None

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        EPOCH_AS_FILETIME = 116444736000000000
        HUNDREDS_OF_NS = 10000000
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None

        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        try:
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ):
                return None
        finally:
            kernel32.CloseHandle(handle)

        creation_ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return (creation_ticks - EPOCH_AS_FILETIME) / HUNDREDS_OF_NS

    def _list_matching_processes(self, process_name: str) -> Dict[int, float]:
        """Return {pid: creation_time} for exact executable-name matches.

        Processes whose creation time cannot be read are deliberately excluded so
        a process success criterion cannot silently degrade to a global name-only
        check.
        """
        if not process_name:
            return {}
        try:
            result = subprocess.run(
                ['tasklist', '/FI', f'IMAGENAME eq {process_name}', '/FO', 'CSV', '/NH'],
                capture_output=True,
                text=True,
                timeout=5
            )
            processes = {}
            for row in csv.reader(result.stdout.splitlines()):
                if len(row) < 2 or row[0].lower() != process_name.lower():
                    continue
                try:
                    pid = int(row[1].replace(',', ''))
                except ValueError:
                    continue
                started_at = self._get_process_start_time(pid)
                if started_at is not None:
                    processes[pid] = started_at
            return processes
        except Exception:
            return {}

    def _check_process_success_once(
        self,
        process_name: str,
        process_baseline: Dict[int, float],
        process_started_after: float,
    ) -> Optional[Dict[str, Any]]:
        """Return a process created by the current execution, if present."""
        for pid, started_at in self._list_matching_processes(process_name).items():
            baseline_started_at = process_baseline.get(pid)
            is_baseline_identity = (
                baseline_started_at is not None
                and abs(baseline_started_at - started_at) < 0.001
            )
            if not is_baseline_identity and started_at >= process_started_after:
                return {'process_id': pid, 'process_start_time': started_at}
        return None

    def _check_process_success(
        self,
        process_baseline: Optional[Dict[int, float]],
        process_started_after: Optional[float],
    ) -> tuple:
        """Check if expected process was spawned."""
        process_config = self.success_config.get('process', {})
        process_name = process_config.get('name', '')
        timeout = process_config.get('timeout', 5)
        
        if not process_name:
            return (True, {'note': 'No process name configured'})

        if process_started_after is None:
            return (False, {
                'process_expected': process_name,
                'message': 'Process success could not be correlated to this execution'
            })

        process_baseline = process_baseline or {}
        
        # Check for process multiple times within timeout
        start_time = time.time()
        while time.time() - start_time < timeout:
            match = self._check_process_success_once(
                process_name,
                process_baseline,
                process_started_after,
            )
            if match:
                return (True, {
                    'process_found': process_name,
                    **match,
                    'message': (
                        f'Process {process_name} was created during the current execution '
                        f'(PID {match["process_id"]})'
                    )
                })
            time.sleep(0.5)
        
        return (False, {
            'process_expected': process_name,
            'message': f'Process {process_name} was NOT found within {timeout}s'
        })
    
    def _check_file_success(self) -> tuple:
        """Check if expected file was created."""
        file_config = self.success_config.get('file', {})
        file_path = file_config.get('path', '')
        
        if not file_path:
            return (True, {'note': 'No file path configured'})
        
        if os.path.exists(file_path):
            return (True, {
                'file_found': file_path,
                'message': f'File {file_path} was created'
            })
        
        return (False, {
            'file_expected': file_path,
            'message': f'File {file_path} was NOT created'
        })
    
    def _check_network_success_once(self, host: str, port: int) -> bool:
        """Single check: is there an established TCP connection to host:port? (Windows: netstat)"""
        if not host or not port:
            return False
        try:
            result = subprocess.run(
                ['netstat', '-an'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # netstat -an: "TCP  local_ip:port  remote_ip:port  ESTABLISHED"
            target = f"{host}:{port}"
            for line in result.stdout.splitlines():
                if 'ESTABLISHED' in line and target in line:
                    return True
            return False
        except Exception:
            return False

    def _check_network_success(self) -> tuple:
        """Check for outbound connection to C2 (e.g. Havoc callback). Polls for timeout."""
        network_config = self.success_config.get('network', {})
        host = (network_config.get('host') or '').strip()
        port = int(network_config.get('port') or 0)
        timeout = int(network_config.get('timeout') or 15)

        if not host or not port:
            return (True, {'note': 'No network host:port configured'})

        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._check_network_success_once(host, port):
                return (True, {
                    'connection': f'{host}:{port}',
                    'message': f'Connection to {host}:{port} (ESTABLISHED)'
                })
            time.sleep(0.5)

        return (False, {
            'connection_expected': f'{host}:{port}',
            'message': f'No connection to {host}:{port} within {timeout}s'
        })
    
    def execute(
        self,
        exe_path: str,
        timeout: int = 30,
        wait_for_detectors: bool = True
    ) -> ExecutionResult:
        """Execute the loader.
        
        Args:
            exe_path: Path to executable (or script)
            timeout: Maximum execution time in seconds
            wait_for_detectors: Whether to wait after execution for detector updates
            
        Returns:
            ExecutionResult with execution details
        """
        if not os.path.exists(exe_path):
            return ExecutionResult(
                success=False,
                error=f"Executable not found: {exe_path}"
            )
        
        start_time = time.time()
        
        try:
            # Check script extension
            cmd_args = [exe_path]
            if exe_path.endswith('.py'):
                import sys
                cmd_args = [sys.executable, exe_path]
            elif exe_path.endswith('.cs'):
                # Try dotnet run or simple stub fallback
                cmd_args = ['dotnet', 'run', '--project', exe_path]
                
            # Start the process
            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(exe_path)
            )
            
            pid = process.pid
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                exit_code = process.returncode
                crashed = exit_code != 0 and exit_code != None
                
                runtime = time.time() - start_time
                
                # Record crash information
                if crashed and not stderr and exit_code is not None:
                    hex_code = f"0x{exit_code & 0xFFFFFFFF:08X}"
                    stderr = f"Process crashed with exit code {exit_code} ({hex_code})".encode('utf-8')
                
                return ExecutionResult(
                    success=not crashed,
                    exit_code=exit_code,
                    stdout=stdout.decode('utf-8', errors='replace') if stdout else "",
                    stderr=stderr.decode('utf-8', errors='replace') if stderr else "",
                    runtime_seconds=runtime,
                    process_id=pid,
                    crashed=crashed
                )
                
            except subprocess.TimeoutExpired:
                # Process is still running (might be expected for shellcode)
                process.kill()
                stdout, stderr = process.communicate()
                
                runtime = time.time() - start_time
                
                return ExecutionResult(
                    success=True,  # Timeout might be expected behavior
                    exit_code=None,
                    stdout=stdout.decode('utf-8', errors='replace') if stdout else "",
                    stderr=stderr.decode('utf-8', errors='replace') if stderr else "",
                    runtime_seconds=runtime,
                    process_id=pid,
                    error="Process timed out (killed)"
                )
                
        except Exception as e:
            return ExecutionResult(
                success=False,
                runtime_seconds=time.time() - start_time,
                error=str(e)
            )
    
    def execute_with_shellcode(
        self,
        exe_path: str,
        shellcode_path: str,
        timeout: int = 30
    ) -> ExecutionResult:
        """Execute loader with shellcode file as argument.
        
        Args:
            exe_path: Path to loader executable (or script)
            shellcode_path: Path to shellcode file
            timeout: Maximum execution time
            
        Returns:
            ExecutionResult
        """
        if not os.path.exists(exe_path):
            return ExecutionResult(
                success=False,
                error=f"Executable not found: {exe_path}"
            )
        
        if not os.path.exists(shellcode_path):
            return ExecutionResult(
                success=False,
                error=f"Shellcode not found: {shellcode_path}"
            )
        
        exe_path = os.path.abspath(exe_path)
        shellcode_path = os.path.abspath(shellcode_path)
        
        print(f"\n[EXECUTOR DEBUG]")
        print(f"  Executable: {exe_path}")
        print(f"  Shellcode:  {shellcode_path}")
        
        # Check script extension
        cmd_list = [exe_path, shellcode_path]
        if exe_path.endswith('.py'):
            import sys
            cmd_list = [sys.executable, exe_path, shellcode_path]
        elif exe_path.endswith('.cs'):
            # Try dotnet run style execution or custom binary execution if compilation fell back to cs source
            csc_exe_path = exe_path.replace('.cs', '.exe')
            if os.path.exists(csc_exe_path):
                cmd_list = [csc_exe_path, shellcode_path]
                exe_path = csc_exe_path
            else:
                cmd_list = ['dotnet', 'run', '--project', exe_path, '--', shellcode_path]
                
        print(f"  Command:    {' '.join(cmd_list)}")
        print(f"  Working dir: {os.path.dirname(exe_path)}")

        process_config = self.success_config.get('process', {})
        network_config = self.success_config.get('network', {})
        success_process_name = process_config.get('name', '') if self.success_type == 'process' else ''
        success_network_host = (network_config.get('host') or '').strip() if self.success_type == 'network' else ''
        success_network_port = int(network_config.get('port') or 0) if self.success_type == 'network' else 0

        # Snapshot identities, not just names. A process that existed before this
        # loader run must not satisfy this run's process success criterion.
        process_baseline = (
            self._list_matching_processes(success_process_name)
            if success_process_name else {}
        )
        start_time = time.time()
        shellcode_success = False
        success_details = {'message': 'Success criteria not checked'}

        try:
            print(f"  Full command: {cmd_list}\n")
            process = subprocess.Popen(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.path.dirname(exe_path)
            )

            pid = process.pid
            print(f"  Process started: PID={pid}")

            # Poll for success criteria *while* loader is running (process or network).
            success_timeout = (
                process_config.get('timeout', 15) if self.success_type == 'process'
                else int(network_config.get('timeout', 15))
            ) if self.success_type in ('process', 'network') else 15
            poll_end = time.time() + success_timeout

            while time.time() < poll_end:
                if self.success_type == 'process' and success_process_name:
                    match = self._check_process_success_once(
                        success_process_name,
                        process_baseline,
                        start_time,
                    )
                    if match:
                        shellcode_success = True
                        success_details = {
                            'process_found': success_process_name,
                            **match,
                            'message': (
                                f'Process {success_process_name} was created during the '
                                f'current execution (PID {match["process_id"]})'
                            )
                        }
                        break
                if self.success_type == 'network' and success_network_host and success_network_port and self._check_network_success_once(success_network_host, success_network_port):
                    shellcode_success = True
                    success_details = {
                        'connection': f'{success_network_host}:{success_network_port}',
                        'message': f'Connection to {success_network_host}:{success_network_port} (ESTABLISHED)'
                    }
                    break
                if process.poll() is not None:
                    break  # loader already exited and no correlated success was found
                time.sleep(0.5)

            try:
                remaining = max(1, int(timeout - (time.time() - start_time)))
                stdout, stderr = process.communicate(timeout=remaining)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                exit_code = None

            runtime = time.time() - start_time

            crashed = exit_code != 0 and exit_code is not None
            if crashed:
                if not stderr and exit_code is not None:
                    hex_code = f"0x{exit_code & 0xFFFFFFFF:08X}"
                    stderr = f"Process crashed with exit code {exit_code} ({hex_code})".encode('utf-8')

            # If we didn't find success process during the poll, check once more
            # (e.g. calc appeared right as loader exited)
            if not crashed and not shellcode_success and (self.success_enabled and self.success_type != 'none'):
                shellcode_success, success_details = self.check_success_criteria(
                    process_baseline=process_baseline,
                    process_started_after=start_time,
                )

            # A non-zero exit is authoritative: the loader did not complete
            # successfully, even if a success artifact was observed concurrently.
            if crashed:
                ignored_observation = success_details if shellcode_success else None
                shellcode_success = False
                success_details = {
                    'loader_exit_code': exit_code,
                    'message': f'Loader exited with code {exit_code}; success criteria rejected'
                }
                if ignored_observation:
                    success_details['ignored_success_observation'] = ignored_observation

            return ExecutionResult(
                success=exit_code == 0 or exit_code is None,
                exit_code=exit_code,
                stdout=stdout.decode('utf-8', errors='replace') if stdout else "",
                stderr=stderr.decode('utf-8', errors='replace') if stderr else "",
                runtime_seconds=runtime,
                process_id=pid,
                crashed=exit_code != 0 and exit_code is not None,
                shellcode_success=shellcode_success,
                success_details=success_details
            )

        except Exception as e:
            return ExecutionResult(
                success=False,
                runtime_seconds=time.time() - start_time,
                error=str(e),
                shellcode_success=False,
                success_details=success_details
            )
    
    def check_process_exists(self, pid: int) -> bool:
        """Check if a process is still running.
        
        Args:
            pid: Process ID
            
        Returns:
            True if process exists
        """
        try:
            result = subprocess.run(
                ['tasklist', '/FI', f'PID eq {pid}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return str(pid) in result.stdout
        except Exception:
            return False
    
    def kill_process(self, pid: int) -> bool:
        """Kill a process by PID.
        
        Args:
            pid: Process ID
            
        Returns:
            True if successfully killed
        """
        try:
            subprocess.run(
                ['taskkill', '/F', '/PID', str(pid)],
                capture_output=True,
                timeout=10
            )
            return True
        except Exception:
            return False
