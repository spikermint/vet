$ErrorActionPreference = "Stop"

Write-Host "==> Version"
$version = vet --version
Write-Host $version
if ($version -notmatch '^vet \d+\.\d+\.\d+') { throw "Invalid version" }

Write-Host "==> Pattern count"
$output = vet patterns
$count = [regex]::Match($output, '^(\d+) patterns', 'Multiline').Groups[1].Value
Write-Host "Patterns: $count"
if ([int]$count -lt 90) { throw "Expected 90+" }

Write-Host "==> Detect Stripe key"
'key = "sk_live_51NzKDwH3JxMvRtYbUcE8q"' | Out-File $env:TEMP\test.txt
$output = vet scan $env:TEMP --format json
if ($output -notmatch 'stripe') { throw "Failed to detect" }
Remove-Item $env:TEMP\test.txt

Write-Host "==> Exit non-zero on findings"
'AKIAIOSFODNN7EXAMPLE' | Out-File $env:TEMP\test.txt
vet scan $env:TEMP >$null 2>&1
if ($LASTEXITCODE -eq 0) { throw "Should exit non-zero" }
Remove-Item $env:TEMP\test.txt

Write-Host "==> Exit zero when clean"
New-Item -ItemType Directory -Path $env:TEMP\clean-test -Force | Out-Null
'# readme' | Out-File $env:TEMP\clean-test\README.md
vet scan $env:TEMP\clean-test
if ($LASTEXITCODE -ne 0) { throw "Should exit zero" }
Remove-Item -Recurse $env:TEMP\clean-test

Write-Host "==> SARIF output"
'sk_live_51NzKDwH3JxMvRtYbUcE8q' | Out-File $env:TEMP\test.txt
$sarif = vet scan $env:TEMP --format sarif 2>$null
if ($sarif -notmatch 'schema') { throw "Invalid SARIF" }
Remove-Item $env:TEMP\test.txt

Write-Host "✓ All checks passed"