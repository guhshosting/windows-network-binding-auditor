@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
"C:\Program Files\LLVM\bin\clang-tidy.exe" src\model.cpp src\windows.cpp src\main.cpp tests\tests.cpp --checks=-*,clang-analyzer-*,bugprone-*,performance-* --warnings-as-errors=* -- -std=c++17 -x c++ -fexceptions -fcxx-exceptions -fms-extensions -fms-compatibility -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -D_WIN32_WINNT=0x0A00 -Isrc
exit /b %errorlevel%