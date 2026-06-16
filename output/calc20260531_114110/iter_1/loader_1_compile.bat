@echo off
echo Initializing Visual Studio environment...
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo ERROR: Failed to initialize Visual Studio environment
    exit /b 1
)
echo Compiling...
cl.exe /nologo /W3 /O2 /Fe:"C:\Users\terada\Documents\GitHub\evasiveAIAgent_LangGraph\output\20260531_114110\iter_1\loader_1.exe" "C:\Users\terada\Documents\GitHub\evasiveAIAgent_LangGraph\output\20260531_114110\iter_1\loader_1.c" /link user32.lib
if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)
echo Compilation successful!
