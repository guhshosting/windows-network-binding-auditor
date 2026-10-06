@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
dumpbin /imports build\Release\windows-network-binding-auditor.exe
dumpbin /headers build\Release\windows-network-binding-auditor.exe