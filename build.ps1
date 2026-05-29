function Build-Cpp {
    Write-Host "Building C++ packet capture..."
    $cppBinDir = "cpp/bin"
    if (-not (Test-Path $cppBinDir)) {
        New-Item -ItemType Directory -Force -Path $cppBinDir | Out-Null
    }

    if (Get-Command cl -ErrorAction SilentlyContinue) {
        $npcapSdk = "C:\Program Files\Npcap\sdk"
        $openSslDir = "C:\Program Files\OpenSSL-Win64"
        $cxxFlags = "/EHsc /W3 /O2 /I`"$npcapSdk\Include`" /I`"$openSslDir\include`""
        $ldFlags = "/link /LIBPATH:`"$npcapSdk\Lib\x64`" /LIBPATH:`"$openSslDir\lib`" wpcap.lib Packet.lib libssl.lib libcrypto.lib ws2_32.lib"
        Invoke-Expression "cl $cxxFlags cpp/packet_capture.cpp cpp/protocol_dissectors.cpp /Fe:`"$cppBinDir/packet_capture.exe`" $ldFlags"
    } else {
        g++ -std=c++17 -Wall -Wextra cpp/packet_capture.cpp cpp/protocol_dissectors.cpp -o "$cppBinDir/packet_capture.exe" -lwpcap -lssl -lcrypto -lws2_32
    }
}

function Build-Rust {
    Write-Host "Building Rust packet service..."
    Push-Location rust/packet_service
    cargo build --release
    Pop-Location

    $rustBinDir = "rust/bin"
    if (-not (Test-Path $rustBinDir)) {
        New-Item -ItemType Directory -Force -Path $rustBinDir | Out-Null
    }
    Copy-Item "rust/packet_service/target/release/packet_service.exe" "$rustBinDir\"
}

function Build-Go {
    Write-Host "Building Go dashboard..."
    $goBinDir = "go/bin"
    if (-not (Test-Path $goBinDir)) {
        New-Item -ItemType Directory -Force -Path $goBinDir | Out-Null
    }
    Push-Location go/dashboard
    go mod tidy
    go build -o "../bin/dashboard.exe" .
    Pop-Location
}

function Generate-Certs {
    Write-Host "Generating self-signed certificates..."
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
    } else {
        Write-Warning "OpenSSL not found in PATH. Certificates will not be generated."
    }
}

function Clean-Artifacts {
    Write-Host "Cleaning up..."
    Remove-Item -Recurse -Force cpp/bin, rust/bin, go/bin, server.crt, server.key -ErrorAction SilentlyContinue
    Push-Location rust/packet_service
    cargo clean
    Pop-Location
    Write-Host "Clean complete."
}

function Run-All {
    Build-Cpp
    Build-Rust
    Build-Go
    Generate-Certs

    Write-Host "Starting system..."
    Write-Host "Note: On Windows, use Git Bash for the background processes to work correctly."
    Write-Host ""

    Start-Process -FilePath "rust/bin/packet_service.exe" -NoNewWindow -PassThru | Out-Variable rustProcess
    Start-Process -FilePath "go/bin/dashboard.exe" -NoNewWindow -PassThru | Out-Variable goProcess

    Write-Host "Dashboard initialized at http://localhost:8080"
    Copy-Item "go/dashboard/GeoLite2-City.mmdb" "go/bin/" -ErrorAction SilentlyContinue

    Write-Host "Starting C++ packet capture (may require administrator privileges)..."
    Start-Process -FilePath "cpp/bin/packet_capture.exe" -Verb RunAs -Wait

    Write-Host "Cleaning up background processes..."
    if ($rustProcess) { Stop-Process -Id $rustProcess.Id -Force -ErrorAction SilentlyContinue }
    if ($goProcess) { Stop-Process -Id $goProcess.Id -Force -ErrorAction SilentlyContinue }
}

switch ($args[0]) {
    "cpp" { Build-Cpp }
    "rust" { Build-Rust }
    "go" { Build-Go }
    "certs" { Generate-Certs }
    "clean" { Clean-Artifacts }
    "run" { Run-All }
    default {
        Write-Host "Usage: powershell -File build.ps1 [cpp|rust|go|certs|clean|run]"
        Write-Host "  No argument defaults to 'run'."
        Run-All
    }
}