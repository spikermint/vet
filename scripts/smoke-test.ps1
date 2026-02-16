$ErrorActionPreference = "Stop"

$testDir = Join-Path $env:TEMP "vet-smoke-test"
New-Item -ItemType Directory -Path $testDir -Force | Out-Null

Write-Host "==> Version"
$version = vet --version
Write-Host $version
if ($version -notmatch '^vet \d+\.\d+\.\d+') { throw "Invalid version" }

Write-Host "==> Pattern count"
$output = vet patterns
$line = $output | Select-String -Pattern '^\d+ patterns' | Select-Object -First 1
$count = [regex]::Match($line, '^(\d+)').Groups[1].Value
Write-Host "Patterns: $count"
if ([int]$count -lt 90) { throw "Expected 90+" }

Write-Host "==> Detect Stripe key"
'key = "sk_live_51NzKDwH3JxMvRtYbUcE8q"' | Out-File "$testDir\secret.txt"
$output = vet scan $testDir --format json 2>&1 | Out-String
if ($output -notmatch 'stripe') { throw "Failed to detect" }
Remove-Item "$testDir\secret.txt"

Write-Host "==> Exit non-zero on findings"
'AKIAIOSFODNN7EXAMPLE' | Out-File "$testDir\secret.txt"
vet scan $testDir >$null 2>&1
if ($LASTEXITCODE -eq 0) { throw "Should exit non-zero" }
Remove-Item "$testDir\secret.txt"

Write-Host "==> Exit zero when clean"
'# readme' | Out-File "$testDir\README.md"
vet scan $testDir
if ($LASTEXITCODE -ne 0) { throw "Should exit zero" }
Remove-Item "$testDir\README.md"

Write-Host "==> SARIF output"
'sk_live_51NzKDwH3JxMvRtYbUcE8q' | Out-File "$testDir\secret.txt"
$sarif = vet scan $testDir --format sarif 2>&1 | Out-String
if ($sarif -notmatch 'schema') { throw "Invalid SARIF" }
Remove-Item "$testDir\secret.txt"

Write-Host "==> Fix command exists"
$fixHelp = vet fix --help 2>&1 | Out-String
if ($fixHelp -notmatch 'dry-run') { throw "Fix help missing dry-run" }
if ($fixHelp -notmatch 'severity') { throw "Fix help missing severity" }

Write-Host "==> Fix reports no secrets when clean"
'fn main() {}' | Out-File "$testDir\clean.rs"
$output = vet fix $testDir 2>&1 | Out-String
if ($output -notmatch 'no secrets') { throw "Fix should report no secrets" }
Remove-Item "$testDir\clean.rs"

Write-Host "==> Fix reports no files when empty"
$emptyDir = Join-Path $testDir "empty"
New-Item -ItemType Directory -Path $emptyDir -Force | Out-Null
$output = vet fix $emptyDir 2>&1 | Out-String
if ($output -notmatch 'no files') { throw "Fix should report no files" }
Remove-Item -Recurse $emptyDir

Remove-Item -Recurse $testDir

Write-Host "✓ All checks passed"
exit 0