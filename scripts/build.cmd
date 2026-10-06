@echo off
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
if errorlevel 1 exit /b 1
cmake --build build --config Release
exit /b %errorlevel%