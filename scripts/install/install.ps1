#!/usr/bin/env pwsh

param(
    [String]$Version = "latest"
)

$ErrorActionPreference = "Stop"

function Write-Error-Message {
    param([String]$Message)
    Write-Output "error: $Message"
}

function Test-Architecture {
    $systemType = (Get-CimInstance Win32_ComputerSystem).SystemType
    return $systemType -match "x64-based"
}

function Get-DownloadUrl {
    param([String]$Version)

    $BaseURL = "https://github.com/spikermint/vet/releases"
    $Target = "vet-windows-x64.exe"

    if ($Version -eq "latest") {
        return "$BaseURL/latest/download/$Target"
    } else {
        return "$BaseURL/download/$Version/$Target"
    }
}

function Get-Binary {
    param([String]$Url, [String]$Dest)

    curl.exe "-#SfLo" "$Dest" "$Url" 2>$null

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "curl.exe failed, trying Invoke-RestMethod..."
        Invoke-RestMethod -Uri $Url -OutFile $Dest
    }
}

function Test-Binary {
    param([String]$Path)

    if (!(Test-Path $Path)) {
        return $false
    }

    $null = & $Path --version 2>&1
    return $LASTEXITCODE -eq 0
}

function Main {
    if (-not (Test-Architecture)) {
        Write-Error-Message "vet is only available for x86 64-bit Windows."
        return 1
    }

    if ($Version -match "^\d+\.\d+\.\d+$") {
        $script:Version = "v$Version"
    }

    $VetRoot = if ($env:VET_INSTALL) { $env:VET_INSTALL } else { "${Home}\.vet" }
    $VetBin = "${VetRoot}\bin"
    $ExePath = "${VetBin}\vet.exe"

    $null = mkdir -Force $VetBin

    try {
        Remove-Item $ExePath -Force -ErrorAction SilentlyContinue
    } catch [System.UnauthorizedAccessException] {
        $running = Get-Process -Name vet -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $ExePath }
        if ($running.Count -gt 0) {
            Write-Error-Message "An existing installation is running. Please close Vet and try again."
            return 1
        }
        Write-Error-Message "Could not remove existing installation: $_"
        return 1
    }

    $DisplayVersion = if ($Version -eq "latest") { "Vet" } else { "Vet $Version" }
    Write-Output "Installing $DisplayVersion..."

    $Url = Get-DownloadUrl -Version $Version
    Get-Binary -Url $Url -Dest $ExePath

    if (-not (Test-Binary -Path $ExePath)) {
        Write-Error-Message "Download failed or binary is corrupted."
        return 1
    }

    $VetVersion = & $ExePath --version 2>&1
    Write-Output "`nInstalled to $ExePath"

    $Path = $env:PATH -split ';'
    if ($Path -notcontains $VetBin) {
        Write-Output "`nAdd to your PATH:"
        Write-Output "  `$env:PATH += `";$VetBin`""
        Write-Output "`nOr add permanently via System Properties > Environment Variables"
    }

    Write-Output "`nRun 'vet --help' to get started"

    return 0
}

$LASTEXITCODE = Main