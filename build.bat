@echo off
rem Build anyproxy packages on Windows. Interactive: prompts for which package(s)
rem to build. Non-interactive: pass the same choice as the first argument, e.g.
rem "build.bat 3", to skip the prompt (handy from scripts/CI).
setlocal
set CGO_ENABLED=0
set RC=0
if not exist dist mkdir dist

rem Version from the latest git tag; fall back to dev when git/tag is absent.
set VER=dev
for /f %%i in ('git rev-list --tags --max-count^=1 2^>nul') do set REV=%%i
if defined REV for /f %%i in ('git describe --tags %REV% 2^>nul') do set VER=%%i

set CHOICE=%~1
if not "%CHOICE%"=="" goto :dispatch

:prompt
echo Which package(s) to build?
echo   1. Windows 64-bit (amd64, with WinDivert)
echo   2. Windows 32-bit (386, with WinDivert)
echo   3. Linux (amd64)
echo   4. All
set /p CHOICE=Select [1-4, default 4]:
if "%CHOICE%"=="" set CHOICE=4

:dispatch
if "%CHOICE%"=="1" (
    call :build_windows amd64 x64
    goto :done
)
if "%CHOICE%"=="2" (
    call :build_windows 386 x86
    goto :done
)
if "%CHOICE%"=="3" (
    call :build_linux
    goto :done
)
if "%CHOICE%"=="4" (
    call :build_windows amd64 x64
    if errorlevel 1 goto :done
    call :build_windows 386 x86
    if errorlevel 1 goto :done
    call :build_linux
    goto :done
)
echo invalid choice: %CHOICE%
set CHOICE=
goto :prompt

rem One self-contained package dir per arch: dist\anyproxy-windows-<arch>-<VER>\
rem The exe ships next to its own WinDivert runtime. WinDivert.dll has a fixed
rem name but different content for 64/32-bit, so separate dirs avoid clobbering.
rem %1 = GOARCH (amd64/386), %2 = WinDivert runtime subdir (x64/x86).
:build_windows
set GOOS=windows
set GOARCH=%~1
set WDDIR=%~2
echo building dist\anyproxy-windows-%GOARCH%-%VER%\anyproxy-windows-%GOARCH%-%VER%.exe ...
if not exist "dist\anyproxy-windows-%GOARCH%-%VER%" mkdir "dist\anyproxy-windows-%GOARCH%-%VER%"
rem -trimpath strips the absolute source path embedded in the binary
go build -trimpath -o "dist\anyproxy-windows-%GOARCH%-%VER%\anyproxy-windows-%GOARCH%-%VER%.exe" .
if errorlevel 1 (
    echo build failed for %GOARCH%
    set RC=1
    exit /b 1
)
rem WinDivert runtime must sit next to the exe (or set tun.windows.windivertDir).
copy /Y "WinDivert-2.2.2-A\%WDDIR%\*" "dist\anyproxy-windows-%GOARCH%-%VER%\" >nul
echo build ok: dist\anyproxy-windows-%GOARCH%-%VER%
exit /b 0

rem Linux/amd64 package, cross-compiled from Windows: CGO_ENABLED=0 already set
rem above, so this needs no gcc/WSL, just a plain "go build" with GOOS switched.
rem No WinDivert copy and no .exe suffix here -- both are Windows-only, unlike
rem scripts/build.sh linux this doesn't embed -ldflags version info, matching
rem the Windows build above which also skips it.
:build_linux
set GOOS=linux
set GOARCH=amd64
echo building dist\anyproxy-amd64-%VER% ...
go build -trimpath -o "dist\anyproxy-amd64-%VER%" .
if errorlevel 1 (
    echo build failed for linux/amd64
    set RC=1
    exit /b 1
)
echo build ok: dist\anyproxy-amd64-%VER%
exit /b 0

:done
rem Pause only when double-clicked (launched from Explorer), so running from an
rem existing console does not force an extra keypress. Reached on success and
rem failure alike, so a failed build stays visible instead of vanishing.
echo %cmdcmdline% | find /i "%~nx0" >nul && pause
endlocal & exit /b %RC%
