@echo off
rem ===========================================================================
rem  HashCalc release build
rem
rem    build.bat            build x64
rem    build.bat x86        build 32-bit
rem    build.bat all        build x64 and x86
rem
rem  Each run increments the minor version in version.h (restored if the build
rem  fails) and copies the portable executable to dist\HashCalc-<arch>.exe.
rem  The one executable is both the GUI and the command line tool.
rem ===========================================================================
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "TARGETS=x64"
if /i "%~1"=="x86" set "TARGETS=Win32"
if /i "%~1"=="win32" set "TARGETS=Win32"
if /i "%~1"=="all" set "TARGETS=x64 Win32"

rem --- Locate MSBuild (Visual Studio 2022) ------------------------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found. Is Visual Studio 2022 installed?
    exit /b 1
)
set "MSBUILD="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%i"
if not defined MSBUILD (
    echo ERROR: MSBuild not found.
    exit /b 1
)

rem --- Increment the minor version ------------------------------------------
set "VERSION_MAJOR="
set "VERSION_MINOR="
for /f "tokens=2,3" %%a in ('findstr /b /c:"#define VERSION_MAJOR" /c:"#define VERSION_MINOR" version.h') do set "%%a=%%b"
if not defined VERSION_MAJOR (
    echo ERROR: could not read VERSION_MAJOR from version.h
    exit /b 1
)
if not defined VERSION_MINOR (
    echo ERROR: could not read VERSION_MINOR from version.h
    exit /b 1
)

set /a VERSION_MINOR+=1
set "VERSION=%VERSION_MAJOR%.%VERSION_MINOR%"

copy /y version.h version.h.bak >nul
(
    echo #pragma once
    echo // Updated by build.bat: the minor version increments on every build.
    echo #define VERSION_MAJOR %VERSION_MAJOR%
    echo #define VERSION_MINOR %VERSION_MINOR%
    echo #define VERSION_STR "%VERSION%"
) > version.h

echo Building HashCalc %VERSION%
echo.

rem --- Build ------------------------------------------------------------------
if not exist dist mkdir dist
for %%p in (%TARGETS%) do (
    echo === %%p ===
    "%MSBUILD%" HashCalc.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=%%p /m /nologo /v:minimal
    if errorlevel 1 goto :failed

    set "ARCH=%%p"
    if /i "%%p"=="Win32" set "ARCH=x86"
    copy /y "build\%%p\Release\HashCalc.exe" "dist\HashCalc-!ARCH!.exe" >nul
    if errorlevel 1 goto :failed
    for %%f in ("dist\HashCalc-!ARCH!.exe") do echo   -^> %%~ff  (%%~zf bytes^)
    echo.
)

del version.h.bak >nul 2>&1
echo Build succeeded: HashCalc %VERSION%
exit /b 0

:failed
echo.
echo BUILD FAILED - version.h restored to the previous version.
move /y version.h.bak version.h >nul
exit /b 1
