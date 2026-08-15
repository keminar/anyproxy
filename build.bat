@echo off
rem Build the windows anyproxy packages (amd64 + 386) on Windows.
rem Usage: double-click, or run build.bat in cmd/PowerShell.
setlocal
set CGO_ENABLED=0
set GOOS=windows
set RC=0
if not exist dist mkdir dist

rem Version from the latest git tag; fall back to dev when git/tag is absent.
set VER=dev
for /f %%i in ('git rev-list --tags --max-count^=1 2^>nul') do set REV=%%i
if defined REV for /f %%i in ('git describe --tags %REV% 2^>nul') do set VER=%%i

rem One self-contained package dir per arch: dist\anyproxy-windows-<arch>-<VER>\
rem The exe ships next to its own WinDivert runtime. WinDivert.dll has a fixed
rem name but different content for 64/32-bit, so separate dirs avoid clobbering.
rem arch to WinDivert runtime dir: amd64 -> x64, 386 -> x86.
for %%p in (amd64:x64 386:x86) do (
    for /f "tokens=1,2 delims=:" %%a in ("%%p") do (
        set GOARCH=%%a
        echo building dist\anyproxy-windows-%%a-%VER%\anyproxy-windows-%%a-%VER%.exe ...
        if not exist "dist\anyproxy-windows-%%a-%VER%" mkdir "dist\anyproxy-windows-%%a-%VER%"
        rem -trimpath strips the absolute source path embedded in the binary
        go build -trimpath -o "dist\anyproxy-windows-%%a-%VER%\anyproxy-windows-%%a-%VER%.exe" .
        if errorlevel 1 (
            echo build failed for %%a
            set RC=1
            goto :done
        )
        rem WinDivert runtime must sit next to the exe (or set tun.windows.windivertDir).
        copy /Y "WinDivert-2.2.2-A\%%b\*" "dist\anyproxy-windows-%%a-%VER%\" >nul
        echo build ok: dist\anyproxy-windows-%%a-%VER%
    )
)

:done
rem Pause only when double-clicked (launched from Explorer), so running from an
rem existing console does not force an extra keypress. Reached on success and
rem failure alike, so a failed build stays visible instead of vanishing.
echo %cmdcmdline% | find /i "%~nx0" >nul && pause
endlocal & exit /b %RC%
