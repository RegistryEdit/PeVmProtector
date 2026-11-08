# Invoked by RunTests.ps1 with $Pevm, $Fixture, $Bin and $Work.
$ScanPath = Join-Path $Work 'named-functions.json'
& $Pevm scan-functions $Fixture $ScanPath *> (Join-Path $Work 'named-functions.log')
if ($LASTEXITCODE -ne 0) { throw 'function symbol scan failed' }
$Scan = Get-Content -LiteralPath $ScanPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not ($Scan.functions | Where-Object { $_.name -eq 'PrintFixtureRva' -and $_.nameSource -eq 'pdb' })) {
    Fail 'PDB scan missed non-exported PrintFixtureRva'
} else { Ok 'matching PDB resolves non-exported function names' }
if (-not ($Scan.functions | Where-Object { $_.name -eq 'LiftTarget' -and $_.nameSource -eq 'export' })) {
    Fail 'PDB scan lost export names'
} else { Ok 'export names preserved alongside PDB names' }
$MismatchPath = Join-Path $Work 'mismatch-functions.json'
& $Pevm scan-functions $Fixture $MismatchPath "--pdb=$(Join-Path $Bin 'DependencyApp.pdb')" *> (Join-Path $Work 'mismatch-functions.log')
if ($LASTEXITCODE -eq 0 -or (Get-Content (Join-Path $Work 'mismatch-functions.log') -Raw) -notmatch 'GUID/age') {
    Fail 'explicit mismatched PDB was not rejected'
} else { Ok 'explicit mismatched PDB rejected' }

# Change only the CodeView GUID in a copy, making the original PDB ineligible.
$Bytes = [IO.File]::ReadAllBytes($Fixture)
$Nt = [BitConverter]::ToUInt32($Bytes, 0x3c)
$SectionCount = [BitConverter]::ToUInt16($Bytes, $Nt + 6)
$SectionTable = $Nt + 24 + [BitConverter]::ToUInt16($Bytes, $Nt + 20)
$DebugRva = [BitConverter]::ToUInt32($Bytes, $Nt + 24 + 112 + 6 * 8)
$DebugSize = [BitConverter]::ToUInt32($Bytes, $Nt + 24 + 116 + 6 * 8)
$DebugRaw = $null
for ($I = 0; $I -lt $SectionCount; ++$I) {
    $At = $SectionTable + 40 * $I
    $Rva = [BitConverter]::ToUInt32($Bytes, $At + 12)
    $RawSize = [BitConverter]::ToUInt32($Bytes, $At + 16)
    if ($DebugRva -ge $Rva -and $DebugRva - $Rva -lt $RawSize) {
        $DebugRaw = [BitConverter]::ToUInt32($Bytes, $At + 20) + $DebugRva - $Rva
    }
}
if ($null -eq $DebugRaw) { throw 'fixture debug directory missing' }
$Patched = $false
for ($I = 0; $I -lt $DebugSize; $I += 28) {
    if ([BitConverter]::ToUInt32($Bytes, $DebugRaw + $I + 12) -ne 2) { continue }
    $Record = [BitConverter]::ToUInt32($Bytes, $DebugRaw + $I + 24)
    if ([BitConverter]::ToUInt32($Bytes, $Record) -ne 0x53445352) { continue }
    $Bytes[$Record + 4] = $Bytes[$Record + 4] -bxor 0xff
    $Patched = $true
}
if (-not $Patched) { throw 'fixture RSDS identity missing' }
$NoSymbols = Join-Path $Work 'UnmatchedSymbols.exe'
[IO.File]::WriteAllBytes($NoSymbols, $Bytes)
& $Pevm scan-functions $NoSymbols $ScanPath *> (Join-Path $Work 'unmatched-functions.log')
if ($LASTEXITCODE -ne 0) { throw 'scan without matching symbols failed' }
$Scan = Get-Content -LiteralPath $ScanPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($Scan.symbolFile -or ($Scan.functions | Where-Object { $_.nameSource -eq 'pdb' }) -or -not $Scan.diagnostics) {
    Fail 'automatic scan attached mismatched symbols'
} elseif (-not ($Scan.functions | Where-Object { $_.name -eq 'LiftTarget' })) {
    Fail 'scan without symbols lost export function names'
} else { Ok 'missing/mismatched PDB falls back to PE names with diagnostics' }
