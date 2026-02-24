#!/usr/bin/env pwsh
# DyberVPN Build Script

$ErrorActionPreference = "Stop"

Write-Host "DyberVPN Build Script" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""

# Check Rust
Write-Host "Checking Rust installation..." -ForegroundColor Yellow
$rustVersion = rustc --version
Write-Host "  $rustVersion" -ForegroundColor Green

# Clean build
Write-Host ""
Write-Host "Cleaning previous build..." -ForegroundColor Yellow
cargo clean 2>$null

# Check compilation
Write-Host ""
Write-Host "Checking compilation..." -ForegroundColor Yellow
$checkResult = cargo check --all 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation errors:" -ForegroundColor Red
    Write-Host $checkResult
    exit 1
}
Write-Host "  All crates compile successfully!" -ForegroundColor Green

# Run tests
Write-Host ""
Write-Host "Running tests..." -ForegroundColor Yellow
$testResult = cargo test --all 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Test failures:" -ForegroundColor Red
    Write-Host $testResult
    exit 1
}
Write-Host "  All tests passed!" -ForegroundColor Green

# Build release
Write-Host ""
Write-Host "Building release..." -ForegroundColor Yellow
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Release build complete!" -ForegroundColor Green

# Show binary info
Write-Host ""
Write-Host "Binary info:" -ForegroundColor Yellow
$binary = ".\target\release\dybervpn.exe"
if (Test-Path $binary) {
    $size = (Get-Item $binary).Length / 1MB
    Write-Host "  Path: $binary" -ForegroundColor Green
    Write-Host "  Size: $([math]::Round($size, 2)) MB" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Testing CLI..." -ForegroundColor Yellow
    & $binary version
}

Write-Host ""
Write-Host "Build completed successfully!" -ForegroundColor Cyan
