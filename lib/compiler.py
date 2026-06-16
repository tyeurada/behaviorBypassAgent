"""Compiler module for building loader executables."""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional
from pathlib import Path


@dataclass
class CompileResult:
    """Result of compilation."""
    success: bool
    output_path: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None


class Compiler:
    """Compiles C code into Windows executables."""
    
    def __init__(self, config: dict):
        """Initialize compiler.
        
        Args:
            config: Compiler configuration from config.yaml
        """
        self.config = config
        self.compiler_type = config.get('type', 'msvc')
        self.language = config.get('language', 'c').lower()
        self.output_dir = Path(config.get('output_dir', './output'))
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if self.compiler_type == 'msvc':
            self.vcvars_path = config.get('msvc', {}).get(
                'vcvars_path',
                r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
            )
        elif self.compiler_type == 'mingw':
            self.mingw_path = config.get('mingw', {}).get(
                'path',
                r"C:\mingw64\bin\gcc.exe"
            )
    
    def compile(
        self,
        code: str,
        output_name: str,
        additional_flags: Optional[list] = None,
        output_dir: Optional[str] = None
    ) -> CompileResult:
        """Compile code to executable.
        
        Args:
            code: Source code
            output_name: Name for output file (without extension)
            additional_flags: Additional compiler flags
            output_dir: Custom output directory (optional - uses self.output_dir if not specified)
            
        Returns:
            CompileResult with success status and paths
        """
        # If it is python, it is a script. We write the script and package it or return python executor setup.
        if self.language == 'python':
            return self._compile_python(code, output_name, output_dir)
        elif self.language in ['.net', 'csharp', 'c#']:
            return self._compile_csharp(code, output_name, output_dir)
        
        # C/C++ builds
        if self.compiler_type == 'msvc':
            return self._compile_msvc(code, output_name, additional_flags, output_dir)
        elif self.compiler_type == 'mingw':
            return self._compile_mingw(code, output_name, additional_flags, output_dir)
        else:
            return CompileResult(
                success=False,
                error=f"Unknown compiler type: {self.compiler_type}"
            )
    
    def _find_vcvars(self) -> Optional[str]:
        """Find vcvars64.bat in common Visual Studio locations."""
        # Common Visual Studio installation paths
        possible_paths = [
            # VS 2022
            r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
            # VS Preview / Other versions
            r"C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files\Microsoft Visual Studio\17\Community\VC\Auxiliary\Build\vcvars64.bat",
            # VS 2019
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
            r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
        ]
        
        # First check configured path
        if os.path.exists(self.vcvars_path):
            return self.vcvars_path
        
        # Try common paths
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def _compile_msvc(
        self,
        code: str,
        output_name: str,
        additional_flags: Optional[list] = None,
        output_dir: Optional[str] = None
    ) -> CompileResult:
        """Compile using MSVC (cl.exe)."""
        
        # Use provided output_dir for source files (session folder)
        # But always put exe in self.output_dir
        if output_dir:
            code_output_dir = Path(output_dir)
        else:
            code_output_dir = self.output_dir
        
        code_output_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Find vcvars
        vcvars = self._find_vcvars()
        if not vcvars:
            return CompileResult(
                success=False,
                error=f"Visual Studio vcvars64.bat not found. Checked paths including: {self.vcvars_path}\n"
                      f"Please install Visual Studio Build Tools or update config.yaml with correct path."
            )
        
        # Source file in session folder
        source_path = (code_output_dir / f"{output_name}.c").absolute()
        
        # Output exe in session folder if output_dir provided, else self.output_dir
        if output_dir:
             output_path = (code_output_dir / f"{output_name}.exe").absolute()
        else:
             output_path = (self.output_dir / f"{output_name}.exe").absolute()
        
        try:
            # Write source code to session folder
            with open(source_path, 'w', encoding='utf-8') as f:
                f.write(code)
            
            # Build compile command with absolute paths
            compile_flags = ['/nologo', '/W3', '/O2']
            if additional_flags:
                compile_flags.extend(additional_flags)

            # MSVC does not automatically link common Win32 import libs like user32.lib.
            # Default a small set to avoid spurious LNK2019 errors for typical Windows APIs.
            link_libs = self.config.get('msvc', {}).get('link_libs')
            if link_libs is None:
                link_libs = ['user32.lib']
            link_part = ""
            if link_libs:
                link_part = " /link " + " ".join(link_libs)
            
            # Don't suppress vcvars output completely, but redirect to a log
            cmd = f'''@echo off
echo Initializing Visual Studio environment...
call "{vcvars}"
if errorlevel 1 (
    echo ERROR: Failed to initialize Visual Studio environment
    exit /b 1
)
echo Compiling...
cl.exe {' '.join(compile_flags)} /Fe:"{output_path}" "{source_path}"{link_part}
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo Compilation successful!
'''
            
            # Create batch file for compilation in output dir
            batch_path = code_output_dir / f"{output_name}_compile.bat"
            with open(batch_path, 'w') as f:
                f.write(cmd)
            
            # Run compilation
            result = subprocess.run(
                ['cmd', '/c', str(batch_path.absolute())],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(code_output_dir.absolute())
            )
            
            # Combine stdout and stderr for full output
            full_output = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            
            # Check if exe was created
            if output_path.exists():
                return CompileResult(
                    success=True,
                    output_path=str(output_path),
                    stdout=result.stdout,
                    stderr=result.stderr
                )
            else:
                return CompileResult(
                    success=False,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    error=f"Compilation failed - no executable produced.\n\nFull output:\n{full_output}"
                )
                
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                error="Compilation timed out (120s)"
            )
        except Exception as e:
            return CompileResult(
                success=False,
                error=str(e)
            )
    
    def _compile_mingw(
        self,
        code: str,
        output_name: str,
        additional_flags: Optional[list] = None,
        output_dir: Optional[str] = None
    ) -> CompileResult:
        """Compile using MinGW (gcc)."""
        
        # Use provided output_dir for source files (session folder)
        # But always put exe in self.output_dir
        if output_dir:
            code_output_dir = Path(output_dir)
        else:
            code_output_dir = self.output_dir
        
        code_output_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Source file in session folder, exe in output/
        source_path = code_output_dir / f"{output_name}.c"
        if output_dir:
            output_path = code_output_dir / f"{output_name}.exe"
        else:
            output_path = self.output_dir / f"{output_name}.exe"
        
        try:
            # Write source code to session folder
            with open(source_path, 'w', encoding='utf-8') as f:
                f.write(code)
            
            # Build compile command
            compile_cmd = [
                self.mingw_path,
                '-o', str(output_path),
                str(source_path),
                '-lkernel32',
                '-luser32',
                '-O2'
            ]
            
            if additional_flags:
                compile_cmd.extend(additional_flags)
            
            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if output_path.exists():
                return CompileResult(
                    success=True,
                    output_path=str(output_path),
                    stdout=result.stdout,
                    stderr=result.stderr
                )
            else:
                return CompileResult(
                    success=False,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    error="Compilation failed - no executable produced"
                )
                
        except subprocess.TimeoutExpired:
            return CompileResult(
                success=False,
                error="Compilation timed out"
            )
        except Exception as e:
            return CompileResult(
                success=False,
                error=str(e)
            )
    
    def is_available(self) -> bool:
        """Check if compiler is available."""
        if self.compiler_type == 'msvc':
            return self._find_vcvars() is not None
        elif self.compiler_type == 'mingw':
            return os.path.exists(self.mingw_path)
        return False
    
    def get_compile_error_hints(self, stderr: str) -> list:
        """Extract helpful hints from compile errors.
        
        Args:
            stderr: Compiler error output
            
        Returns:
            List of hints for fixing errors
        """
        hints = []
        
        # Common error patterns
        if 'undefined reference' in stderr.lower() or 'unresolved external' in stderr.lower():
            hints.append("Missing library - add #pragma comment(lib, \"...\") or linker flag")
        
        if 'undeclared identifier' in stderr.lower() or 'undeclared' in stderr.lower():
            hints.append("Missing #include directive or function declaration")
        
        if 'syntax error' in stderr.lower():
            hints.append("Check for missing semicolons, braces, or parentheses")
        
        # MSVC C: variadic typedef (...) is invalid in C; use void* for generic function pointer
        if "missing ')' before '...'" in stderr or "syntax error: '...'" in stderr or "GenericSyscall" in stderr:
            hints.append("MSVC C does not support variadic typedef (...). Use 'typedef void* GenericSyscall;' for generic syscall stub pointers and cast at call sites.")
        
        if 'implicit declaration' in stderr.lower():
            hints.append("Function used without declaration - add appropriate #include")
        
        if 'cannot open include file' in stderr.lower() or 'no such file' in stderr.lower():
            hints.append("Header file not found - check #include paths")
        
        return hints
    
    def apply_compile_fixes(self, code: str, stderr: str) -> str:
        """Apply known source fixes for MSVC C compiler errors.
        
        When the compiler is MSVC and we're compiling C (not C++), certain constructs
        (e.g. variadic typedef) are invalid. This applies fixes so the agent can recover
        from compile failures without waiting for the next AI iteration.
        
        Args:
            code: C source code that failed to compile
            stderr: Compiler stderr (and/or combined output) from the failed run
            
        Returns:
            Modified source code with fixes applied, or unchanged code if no fix matched.
        """
        if self.compiler_type != 'msvc':
            return code
        
        full_output = (stderr or "").lower()
        modified = code
        
        # Fix: MSVC C does not accept typedef with (...) variadic in C. Replace with void*.
        # Pattern: typedef NTSTATUS (NTAPI *GenericSyscall)(...);
        if "syntax error" in full_output and ("'...'" in stderr or "before '...'" in stderr or "generic syscall" in full_output or "GenericSyscall" in stderr):
            import re
            # Replace variadic GenericSyscall typedef with void* (stub pointers are cast at use anyway)
            pattern = r"typedef\s+NTSTATUS\s+\(NTAPI\s+\*\s*GenericSyscall\s*\)\s*\(\s*\.\.\.\s*\)\s*;"
            replacement = "typedef void* GenericSyscall;  /* MSVC C: no variadic typedef; cast at call sites */"
            if re.search(pattern, modified, re.IGNORECASE):
                modified = re.sub(pattern, replacement, modified, flags=re.IGNORECASE)
            # Fallback: simple string replace if regex didn't match (e.g. different spacing)
            elif "GenericSyscall)(...)" in modified:
                modified = modified.replace(
                    "typedef NTSTATUS (NTAPI *GenericSyscall)(...);",
                    "typedef void* GenericSyscall;  /* MSVC C: no variadic typedef; cast at call sites */"
                )
        
        return modified

    def _compile_python(self, code: str, output_name: str, output_dir: Optional[str] = None) -> CompileResult:
        """Create Python script file."""
        if output_dir:
            code_output_dir = Path(output_dir)
        else:
            code_output_dir = self.output_dir
        
        code_output_dir.mkdir(parents=True, exist_ok=True)
        script_path = (code_output_dir / f"{output_name}.py").absolute()
        
        try:
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(code)
            return CompileResult(
                success=True,
                output_path=str(script_path),
                stdout="Python script written successfully."
            )
        except Exception as e:
            return CompileResult(
                success=False,
                error=str(e)
            )

    def _compile_csharp(self, code: str, output_name: str, output_dir: Optional[str] = None) -> CompileResult:
        """Compile C# using csc.exe if available, else fallback."""
        if output_dir:
            code_output_dir = Path(output_dir)
        else:
            code_output_dir = self.output_dir
        
        code_output_dir.mkdir(parents=True, exist_ok=True)
        source_path = (code_output_dir / f"{output_name}.cs").absolute()
        output_path = (code_output_dir / f"{output_name}.exe").absolute()
        
        try:
            with open(source_path, 'w', encoding='utf-8') as f:
                f.write(code)
            
            # Look for csc.exe in .NET Framework directories
            import glob
            csc_paths = glob.glob(r"C:\Windows\Microsoft.NET\Framework64\v4.0.*\csc.exe")
            if not csc_paths:
                csc_paths = glob.glob(r"C:\Windows\Microsoft.NET\Framework\v4.0.*\csc.exe")
            
            if csc_paths:
                csc = csc_paths[0]
                cmd = [csc, f"/out:{output_path}", str(source_path)]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if output_path.exists():
                    return CompileResult(
                        success=True,
                        output_path=str(output_path),
                        stdout=result.stdout,
                        stderr=result.stderr
                    )
                else:
                    return CompileResult(
                        success=False,
                        error=f"C# Compilation failed: {result.stderr or result.stdout}"
                    )
            else:
                # Fallback: mock C# compile successful as a script/dotnet run if csc is missing
                return CompileResult(
                    success=True,
                    output_path=str(source_path),
                    stdout="C# Source written (csc.exe compiler not found in typical Framework paths)."
                )
        except Exception as e:
            return CompileResult(
                success=False,
                error=str(e)
            )
