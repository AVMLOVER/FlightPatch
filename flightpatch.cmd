@echo off
setlocal DisableDelayedExpansion
set "binary=nttimebomb-x64.exe"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" if not defined PROCESSOR_ARCHITEW6432 set "binary=nttimebomb-x86.exe"
"%~dp0%binary%" %*
exit /b %errorlevel%
