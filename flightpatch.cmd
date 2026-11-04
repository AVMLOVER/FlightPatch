@echo off
setlocal DisableDelayedExpansion
set "binary=flightpatch-x64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "binary=flightpatch-x86.exe"
"%~dp0%binary%" %*
exit /b %errorlevel%
