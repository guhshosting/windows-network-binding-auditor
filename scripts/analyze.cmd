@echo off
cmake -S . -B build-analyze -G "Visual Studio 18 2026" -A x64 -DWNBA_ANALYZE=ON
if errorlevel 1 exit /b 1
cmake --build build-analyze --config Release
exit /b %errorlevel%