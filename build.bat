@echo off
echo ============================================
echo  Building S.O.W.A Security Software
echo  by C.N.S (Clear Net Sky)
echo ============================================
echo.

:: Set variables (version comes from internal/version/version.go)
set APP_NAME=sowa-security
set BUILD_DIR=build
set LDFLAGS=-s -w

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

:: Build for Windows AMD64 (web UI is embedded into the EXE)
echo [BUILD] Compiling for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="%LDFLAGS%" -o %BUILD_DIR%\%APP_NAME%.exe .\cmd\sowa\

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Build complete!
echo  Output: %BUILD_DIR%\%APP_NAME%.exe
echo  The EXE is fully portable - the web UI is
echo  embedded, no extra files are required.
echo ============================================
echo.
echo To run: %BUILD_DIR%\%APP_NAME%.exe
echo Web UI: http://127.0.0.1:8080
echo.
pause
