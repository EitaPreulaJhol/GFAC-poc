@echo off
setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0"

rem ===========================================================================
rem  GFAC.sys local-privilege-escalation PoC -- build script
rem
rem    * finds the Visual C++ x64 toolchain (works from the "x64 Native Tools
rem      Command Prompt", or auto-detects a Visual Studio install via vswhere)
rem    * compiles GFAC_LPE_PoC.rc  (embeds ..\GFAC.sys as RCDATA id 101)
rem    * compiles + links GFAC_LPE_PoC.cpp   ->   GFAC_LPE_PoC.exe
rem
rem  Usage:
rem    build.bat            build (embeds ..\GFAC.sys when it is present)
rem    build.bat nopause    build without the final "press any key" prompt
rem    build.bat clean      delete build artifacts
rem    build.bat help       show this help
rem
rem  Requires: MSVC (Visual Studio 2017+) + Windows SDK, x64 target.
rem  RESEARCH / AUTHORIZED TESTING ONLY -- run the produced exe elevated.
rem ===========================================================================

set "SRC=GFAC_LPE_PoC.cpp"
set "RCS=GFAC_LPE_PoC.rc"
set "RES=GFAC_LPE_PoC.res"
set "OBJ=GFAC_LPE_PoC.obj"
set "OUT=GFAC_LPE_PoC.exe"
set "DRIVER=..\GFAC.sys"

set "PF=%ProgramFiles%"
set "PF86=%ProgramFiles(x86)%"

set "DO_PAUSE=1"
if /i "%~1"=="nopause" set "DO_PAUSE=0"
if /i "%~1"=="clean"   goto :do_clean
if /i "%~1"=="help"    goto :usage
if /i "%~1"=="/?"      goto :usage
if /i "%~1"=="-h"      goto :usage
if /i "%~1"=="--help"  goto :usage

echo ===========================================================================
echo  GFAC.sys LPE PoC -- build
echo ===========================================================================

rem -- locate the x64 toolchain ----------------------------------------------
where cl.exe >nul 2>nul
if errorlevel 1 call :setup_vs
where cl.exe >nul 2>nul
if errorlevel 1 (
    echo [x] cl.exe ^(Visual C++ compiler^) was not found.
    echo     * Run this script from the "x64 Native Tools Command Prompt for VS", or
    echo     * install the "Desktop development with C++" workload, then retry.
    goto :fail
)
echo [*] Compiler:
cl 2>&1 | findstr /i /c:"Optimizing Compiler Version"

rem -- embed the driver (optional) -------------------------------------------
if exist "%DRIVER%" (
    echo [*] Embedding "%DRIVER%" into the executable ...
    rc /nologo /fo "%RES%" "%RCS%"
    if errorlevel 1 (
        echo [x] Resource compilation ^(rc.exe^) failed.
        goto :fail
    )
) else (
    echo [!] "%DRIVER%" not found -- building WITHOUT the embedded driver.
    echo     The PoC will fall back to a GFAC.sys placed next to the exe.
    set "RES="
)

rem -- compile + link ---------------------------------------------------------
echo [*] Compiling "%SRC%" ...
cl /nologo /EHsc /std:c++17 /W4 /Fe:"%OUT%" "%SRC%" %RES% advapi32.lib
if errorlevel 1 (
    echo [x] Compilation / link failed.
    goto :fail
)
if not exist "%OUT%" (
    echo [x] "%OUT%" was not produced.
    goto :fail
)

for %%F in ("%OUT%") do echo [+] Built "%%~fF" ^(%%~zF bytes^)
echo.
echo     Next: run GFAC_LPE_PoC.exe from an ELEVATED prompt on the target VM.
goto :done

rem -- helpers ----------------------------------------------------------------

:do_clean
set "DO_PAUSE=0"

echo [*] Removing build artifacts ...
del /q "%RES%" "%OBJ%" "%OUT%" 2>nul
echo [+] Done.
goto :done

:usage
set "DO_PAUSE=0"

echo Usage:
echo     build.bat            build the PoC ^(embeds ..\GFAC.sys when present^)
echo     build.bat nopause    build without the final "press any key" prompt
echo     build.bat clean      delete build artifacts
echo     build.bat help       show this help
goto :done

:setup_vs
rem Prefer vswhere (ships with Visual Studio 2017 and later).
set "VSWHERE=%PF86%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"
)
if defined VSROOT if exist "!VSROOT!\VC\Auxiliary\Build\vcvars64.bat" (
    echo [*] Setting up the x64 toolchain from "!VSROOT!" ...
    call "!VSROOT!\VC\Auxiliary\Build\vcvars64.bat" >nul
    exit /b 0
)
rem Fallback: scan the usual install roots.
for %%R in ("%PF%" "%PF86%") do (
    for %%V in (2022 2019 2017) do (
        for %%E in (Enterprise Professional Community BuildTools) do (
            if exist "%%~R\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat" (
                echo [*] Setting up the x64 toolchain from VS %%V %%E ...
                call "%%~R\Microsoft Visual Studio\%%V\%%E\VC\Auxiliary\Build\vcvars64.bat" >nul
                exit /b 0
            )
        )
    )
)
exit /b 0

:done
popd
if "%DO_PAUSE%"=="1" pause
endlocal
exit /b 0

:fail
popd
if "%DO_PAUSE%"=="1" pause
endlocal
exit /b 1
