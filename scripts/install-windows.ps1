param(
    [string]$Repository = "JesseS69/vulcanary",
    [string]$Tag = "latest",
    [switch]$SkipSetup
)
$ErrorActionPreference = "Stop"
$releaseUri = if ($Tag -eq "latest") { "https://api.github.com/repos/$Repository/releases/latest" } else { "https://api.github.com/repos/$Repository/releases/tags/$Tag" }
$release = Invoke-RestMethod -Uri $releaseUri -Headers @{ Accept = "application/vnd.github+json" }
$wheel = $release.assets | Where-Object { $_.name -like "vulcanary-*.whl" } | Select-Object -First 1
$checksums = $release.assets | Where-Object { $_.name -eq "SHA256SUMS.txt" } | Select-Object -First 1
if (-not $wheel -or -not $checksums) { throw "Release does not contain a wheel and SHA256SUMS.txt" }
$installRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("vulcanary-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $installRoot | Out-Null
try {
    $wheelPath = Join-Path $installRoot $wheel.name
    $checksumPath = Join-Path $installRoot $checksums.name
    Invoke-WebRequest -Uri $wheel.browser_download_url -OutFile $wheelPath
    Invoke-WebRequest -Uri $checksums.browser_download_url -OutFile $checksumPath
    $expectedLine = Get-Content -LiteralPath $checksumPath | Where-Object { $_ -match ("\s" + [regex]::Escape($wheel.name) + "$") } | Select-Object -First 1
    if (-not $expectedLine) { throw "Wheel is absent from SHA256SUMS.txt" }
    $expected = ($expectedLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "Wheel checksum verification failed" }
    & py -3 -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11 or newer is required'"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11 or newer is required" }
    & py -3 -m pip install --user --upgrade $wheelPath
    if ($LASTEXITCODE -ne 0) { throw "Vulcanary installation failed" }
    Write-Host "Vulcanary $($release.tag_name) installed and SHA-256 verified." -ForegroundColor Green
    if (-not $SkipSetup) { & py -3 -m vulcanary setup }
} finally {
    if (Test-Path -LiteralPath $installRoot) { Remove-Item -LiteralPath $installRoot -Recurse -Force }
}
