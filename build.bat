@echo off
rem Build the windows anyproxy packages (amd64 + 386) on Windows.
rem Usage: double-click, or run build.bat in cmd/PowerShell.
setlocal
set CGO_ENABLED=0
set GOOS=windows
set HTTP_PROXY=http://127.0.0.1:3000
set HTTPS_PROXY=http://127.0.0.1:3000
set http_proxy=http://127.0.0.1:3000
set https_proxy=http://127.0.0.1:3000
if not exist dist mkdir dist

rem 版本号(取最新 tag; 无 git/无 tag 时回退 dev)。
set VER=dev
for /f %%i in ('git rev-list --tags --max-count^=1 2^>nul') do set REV=%%i
if defined REV for /f %%i in ('git describe --tags %REV% 2^>nul') do set VER=%%i

rem 每个架构打成独立成套的包目录 dist\anyproxy-windows-<arch>-<VER>\:
rem exe 与它自己的 WinDivert 运行时放在一起。WinDivert.dll 是固定文件名且
rem 64/32 位内容不同, 分目录隔离避免互相覆盖。
rem arch 与 WinDivert 子目录映射: amd64->x64, 386->x86。
for %%p in (amd64:x64 386:x86) do (
    for /f "tokens=1,2 delims=:" %%a in ("%%p") do (
        set GOARCH=%%a
        echo building dist\anyproxy-windows-%%a-%VER%\anyproxy-windows-%%a-%VER%.exe ...
        if not exist "dist\anyproxy-windows-%%a-%VER%" mkdir "dist\anyproxy-windows-%%a-%VER%"
        rem -trimpath strips the absolute source path embedded in the binary
        go build -trimpath -o "dist\anyproxy-windows-%%a-%VER%\anyproxy-windows-%%a-%VER%.exe" .
        if errorlevel 1 (
            echo build failed for %%a
            exit /b 1
        )
        rem WinDivert 运行时(需与 exe 同目录, 或用 tun.windows.windivertDir 指定)。
        copy /Y "WinDivert-2.2.2-A\%%b\*" "dist\anyproxy-windows-%%a-%VER%\" >nul
        echo build ok: dist\anyproxy-windows-%%a-%VER%
    )
)
pause
endlocal
