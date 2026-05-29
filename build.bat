@echo off
setlocal

:Build-Cpp
    echo Building C++ packet capture...
    set "cppBinDir=cpp\bin"
    if not exist "%cppBinDir%" mkdir "%cppBinDir%"

    where cl >nul 2>nul
    if %errorlevel% equ 0 (
        set "npcapSdk=C:\Program Files\Npcap\sdk"
        set "openSslDir=C:\Program Files\OpenSSL-Win64"
        set "cxxFlags=/EHsc /W3 /O2 /I"%npcapSdk%\Include" /I"%openSslDir%\include""
        set "ldFlags=/link /LIBPATH:"%npcapSdk%\Lib\x64" /LIBPATH:"%openSslDir%\lib" wpcap.lib Packet.lib libssl.lib libcrypto.lib ws2_32.lib"
        cl %cxxFlags% cpp\packet_capture.cpp cpp\protocol_dissectors.cpp /Fe:"%cppBinDir%\packet_capture.exe" %ldFlags%
    ) else (
        g++ -std=c++17 -Wall -Wextra cpp\packet_capture.cpp cpp\protocol_dissectors.cpp -o "%cppBinDir%\packet_capture.exe" -lwpcap -lssl -lcrypto -lws2_32
    )
    goto :EOF

:Build-Rust
    echo Building Rust packet service...
    pushd rust\packet_service
    cargo build --release
    popd

    set "rustBinDir=rust\bin"
    if not exist "%rustBinDir%" mkdir "%rustBinDir%"
    copy rust\packet_service\target\release\packet_service.exe "%rustBinDir%\" >nul
    goto :EOF

:Build-Go
    echo Building Go dashboard...
    set "goBinDir=go\bin"
    if not exist "%goBinDir%" mkdir "%goBinDir%"
    pushd go\dashboard
    go mod tidy
    go build -o "..\bin\dashboard.exe" .
    popd
    goto :EOF

:Generate-Certs
    echo Generating self-signed certificates...
    where openssl >nul 2>nul
    if %errorlevel% equ 0 (
        openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
    ) else (
        echo WARNING: OpenSSL not found in PATH. Certificates will not be generated.
    )
    goto :EOF

:Clean-Artifacts
    echo Cleaning up...
    if exist cpp\bin rmdir /s /q cpp\bin
    if exist rust\bin rmdir /s /q rust\bin
    if exist go\bin rmdir /s /q go\bin
    if exist server.crt del server.crt
    if exist server.key del server.key
    pushd rust\packet_service
    cargo clean
    popd
    echo Clean complete.
    goto :EOF

:Run-All
    call :Build-Cpp
    call :Build-Rust
    call :Build-Go
    call :Generate-Certs

    echo Starting system...
    echo Note: On Windows, for background processes to be easily managed, consider using a more advanced shell like Git Bash or PowerShell.
    echo.

    start "" "rust\bin\packet_service.exe"
    start "" "go\bin\dashboard.exe"

    echo Dashboard initialized at http://localhost:8080
    copy go\dashboard\GeoLite2-City.mmdb go\bin\ >nul 2>nul

    echo Starting C++ packet capture (may require administrator privileges)...
    start "" /wait "cpp\bin\packet_capture.exe"

    echo Cleaning up background processes...
    echo Please manually terminate 'packet_service.exe' and 'dashboard.exe' if they are still running.
    goto :EOF

if "%~1"=="cpp" call :Build-Cpp
if "%~1"=="rust" call :Build-Rust
if "%~1"=="go" call :Build-Go
if "%~1"=="certs" call :Generate-Certs
if "%~1"=="clean" call :Clean-Artifacts
if "%~1"=="run" call :Run-All
if "%~1"=="" call :Run-All
if "%~1" neq "cpp" if "%~1" neq "rust" if "%~1" neq "go" if "%~1" neq "certs" if "%~1" neq "clean" if "%~1" neq "run" if "%~1" neq "" echo Usage: build.bat [cpp|rust|go|certs|clean|run] & echo   No argument defaults to 'run'.

endlocal