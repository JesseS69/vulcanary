param([switch]$PurgeLocalData)
$ErrorActionPreference = "Stop"

& py -3 -m vulcanary stop 2>$null
& py -3 -m pip uninstall --yes vulcanary
if ($LASTEXITCODE -ne 0) { throw "Vulcanary uninstall failed" }

if ($PurgeLocalData) {
    $dataRoot = Join-Path $HOME ".vulcanary"
    if (Test-Path -LiteralPath $dataRoot) {
        Remove-Item -LiteralPath $dataRoot -Recurse -Force
        Write-Host "Removed local Vulcanary configuration and history at $dataRoot."
    }
} else {
    Write-Host "Local configuration and history were preserved in ~/.vulcanary."
}
Write-Host "Vulcanary uninstalled." -ForegroundColor Green
