@echo off
"C:\Program Files\Cppcheck\cppcheck.exe" --enable=warning,style,performance,portability --error-exitcode=1 --inline-suppr --std=c++17 --platform=win64 --suppress=missingIncludeSystem -D_WIN32 -D_MSC_VER=1951 -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX -Isrc src tests
exit /b %errorlevel%