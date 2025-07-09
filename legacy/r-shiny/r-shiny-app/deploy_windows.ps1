# PowerShell Deployment Script for Academic Legislative Monitor
# This script ensures proper directory and runs deployment

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   ACADEMIC LEGISLATIVE MONITOR - DEPLOYMENT      " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Get the script's directory
$scriptPath = $PSScriptRoot
Write-Host "Script location: $scriptPath" -ForegroundColor Yellow

# Change to script directory
Set-Location $scriptPath
Write-Host "Changed to app directory: $(Get-Location)" -ForegroundColor Green
Write-Host ""

# Check if R is available
$rPath = Get-Command R -ErrorAction SilentlyContinue
if (-not $rPath) {
    Write-Host "ERROR: R is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install R from: https://cran.r-project.org/" -ForegroundColor Yellow
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "✓ R found at: $($rPath.Source)" -ForegroundColor Green
Write-Host ""

# List files to verify we're in the right place
Write-Host "Files in current directory:" -ForegroundColor Cyan
Get-ChildItem | Select-Object -First 10 | ForEach-Object { Write-Host "  - $($_.Name)" }
Write-Host ""

# Check for app.R
if (Test-Path "app.R") {
    Write-Host "✓ app.R found!" -ForegroundColor Green
}
else {
    Write-Host "✗ app.R not found!" -ForegroundColor Red
    Write-Host "Current directory: $(Get-Location)" -ForegroundColor Yellow
    Write-Host "Please ensure you're in the r-shiny-app directory" -ForegroundColor Yellow
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host ""
Write-Host "Starting deployment process..." -ForegroundColor Cyan
Write-Host ""

# Run the simple deployment script
& Rscript deploy_simple.R

Write-Host ""
Write-Host "Deployment script finished." -ForegroundColor Cyan
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")