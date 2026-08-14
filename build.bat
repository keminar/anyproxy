@echo off
rem Build the windows executable of anyproxy on Windows.
rem Usage: double-click, or run build.bat in cmd/PowerShell.
setlocal

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
set HTTP_PROXY=http://127.0.0.1:3000
set HTTPS_PROXY=http://127.0.0.1:3000
set http_proxy=http://127.0.0.1:3000
set https_proxy=http://127.0.0.1:3000
if not exist dist mkdir dist

echo building dist\anyproxy-windows-amd64.exe ...
go build -o dist\anyproxy-windows-amd64.exe .
if %ERRORLEVEL% neq 0 (
    echo build failed
    exit /b %ERRORLEVEL%
)

echo build ok: dist\anyproxy-windows-amd64.exe
pause
endlocal
