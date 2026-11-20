@echo off
echo Initializing Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to initialize Visual Studio environment
    exit /b 1
)
echo Compiling...
cl.exe /nologo /W3 /O2 /Fe:"C:\Users\mslr74l\Desktop\dev\behaviorBypassAgent\output\20260930_064708_direct_syscall\iter_3\loader_direct_syscall_3.exe" "C:\Users\mslr74l\Desktop\dev\behaviorBypassAgent\output\20260930_064708_direct_syscall\iter_3\loader_direct_syscall_3.c" /link user32.lib
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo Compilation successful!
