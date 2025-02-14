#!/bin/bash



# Version
VERSION="1.0.0"

# Build for Linux (AMD64 and ARM64)
echo "[*] Building Linux AMD64..."
GOOS=linux GOARCH=amd64 go build -o goSNMPwn_linux_amd64
echo "[*] Building Linux ARM64..."
GOOS=linux GOARCH=arm64 go build -o goSNMPwn_linux_arm64

# Build for Windows (AMD64 and ARM64)
echo "[*] Building Windows AMD64..."
GOOS=windows GOARCH=amd64 go build -o goSNMPwn_windows_amd64.exe
echo "[*] Building Windows ARM64..."
GOOS=windows GOARCH=arm64 go build -o goSNMPwn_windows_arm64.exe

# Build for macOS (AMD64 and ARM64)
echo "[*] Building macOS AMD64..."
GOOS=darwin GOARCH=amd64 go build -o goSNMPwn_macOS_amd64
echo "[*] Building macOS ARM64..."
GOOS=darwin GOARCH=arm64 go build -o goSNMPwn_macOS_arm64

# Make Linux and macOS binaries executable
chmod +x goSNMPwn_linux_*
chmod +x goSNMPwn_macOS_*

echo "[+] Build complete! Binaries available in  directory:"
ls -l 
