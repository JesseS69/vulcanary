[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, ValueFromRemainingArguments)]
    [string[]] $Repository
)

$failure = $false
foreach ($candidate in $Repository) {
    $resolved = Resolve-Path -LiteralPath $candidate -ErrorAction Stop
    Write-Host "`n==> Scanning $resolved"
    & python -m vulcanary $resolved
    if ($LASTEXITCODE -ne 0) {
        $failure = $true
    }
}

if ($failure) { exit 1 }
