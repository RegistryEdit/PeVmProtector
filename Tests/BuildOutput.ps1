# Integration checks for the default build transcript, using the real CLI.
$LogWork = Join-Path $Work ('build-output-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $LogWork | Out-Null
$BuildPassword = 'build-log-secret-' + [Guid]::NewGuid().ToString('N')
$Watermark = 'private-watermark-' + [Guid]::NewGuid().ToString('N')
foreach ($Command in @('pack', 'wrap', 'protect-all')) {
    $Extension = if ($Command -eq 'pack') { '.pvm' } else { '.exe' }
    $Artifact = Join-Path $LogWork ($Command + $Extension)
    $OldStaging = "$Artifact.payload.tmp"
    [IO.File]::WriteAllText($OldStaging, 'preserve-unrelated-staging-file')
    $Transcript = Join-Path $LogWork ($Command + '.log')
    $Arguments = @($Command, $Fixture, $Artifact, $BuildPassword)
    if ($Command -ne 'pack') { $Arguments += @('--compress', "--watermark=$Watermark") }
    if ($Command -eq 'protect-all') { $Arguments += @('--mutate', '--anti-disasm') }
    & $Pevm @Arguments *> $Transcript
    if ($LASTEXITCODE -ne 0) { Fail "$Command build transcript fixture failed"; continue }
    if (-not (Test-Path $OldStaging) -or [IO.File]::ReadAllText($OldStaging) -ne 'preserve-unrelated-staging-file') {
        Fail "$Command touched an unrelated payload staging file"
    }
    $Text = Get-Content $Transcript -Raw
    foreach ($Field in @('\[build\]', '\[stage \d+\]', 'input size:', 'section\[0\]:',
                          'entry RVA:', 'plain SHA-256:', 'KDF: scrypt N=16384 r=8 p=1',
                          'cipher: XTEA-CTR', 'compression result:', 'stored/original:',
                          'stage elapsed:', 'output/input:', 'total elapsed:')) {
        if ($Text -notmatch $Field) { Fail "$Command missing build detail: $Field" }
    }
    if (($Text -split '\[complete\]').Count -ne 2 -or $Text -notmatch '\[complete\] output committed\s*$') {
        Fail "$Command must report completion exactly once, after the final artifact"
    }
    if ($Text -match 'output size: (\d+) bytes') {
        if ([uint64]$Matches[1] -ne (Get-Item $Artifact).Length) { Fail "$Command output size does not match disk" }
    } else { Fail "$Command missing output size" }
    if ($Text -match 'output SHA-256: ([0-9a-fA-F]{64})') {
        if ($Matches[1] -ne (Get-FileHash $Artifact -Algorithm SHA256).Hash) { Fail "$Command output hash mismatch" }
    } else { Fail "$Command missing output hash" }
    if ($Text -match 'plain SHA-256: ([0-9a-fA-F]{64})') {
        if ($Matches[1] -ne (Get-FileHash $Fixture -Algorithm SHA256).Hash) { Fail "$Command input hash mismatch" }
    }
    if ($Text.Contains($BuildPassword) -or $Text.Contains($Watermark) -or $Text -match 'key words:|PasswordCheck:') {
        Fail "$Command exposed secret/raw watermark material"
    }
    if ($Command -eq 'pack' -and $Text -notmatch 'stored \(compression disabled\)') { Fail 'pack compression-off result unclear' }
    if ($Command -ne 'pack') {
        foreach ($Field in @('license: off', 'watermark: \d+ bytes embedded', 'runtime section:', 'payload section:', 'build id:')) {
            if ($Text -notmatch $Field) { Fail "$Command missing protection detail: $Field" }
        }
    }
    if ($Command -eq 'protect-all') {
        foreach ($Field in @('candidates:', 'selected:', 'selection rate:', 'skipped:',
                              'function RVA:', 'basic blocks:', 'total VM instructions:', 'VM section:',
                              'VM authentication: HMAC-SHA256', 'VM key separation:', 'VM runtime checks:',
                              'VM code layout:', 'VM decoding:', 'compiled function RVA:',
                              'relocated=', 'link instructions=')) {
            if ($Text -notmatch $Field) { Fail "protect-all missing function detail: $Field" }
        }
    }
    Ok "$Command reports stages, accurate sizes/hashes and sanitized settings"
}

$Invalid = Join-Path $LogWork 'invalid.exe'
[IO.File]::WriteAllText($Invalid, 'not a PE')
$FailedOutput = Join-Path $LogWork 'failed.pvm'
$FailureLog = Join-Path $LogWork 'failed.log'
& $Pevm pack $Invalid $FailedOutput $BuildPassword *> $FailureLog
$ExitCode = $LASTEXITCODE
$Failure = Get-Content $FailureLog -Raw
if ($ExitCode -eq 0 -or (Test-Path $FailedOutput) -or $Failure -match '\[complete\]' -or
    $Failure -notmatch '\[failed\] Read PE payload' -or $Failure -notmatch 'not an MZ') {
    Fail 'invalid PE must report failed stage and preserve nonzero status'
} else { Ok 'invalid PE reports failure without completion' }

$UnwritableOutput = Join-Path $LogWork 'missing-directory\output.pvm'
& $Pevm pack $Fixture $UnwritableOutput $BuildPassword *> $FailureLog
$ExitCode = $LASTEXITCODE
$Failure = Get-Content $FailureLog -Raw
if ($ExitCode -eq 0 -or $Failure -match '\[complete\]' -or $Failure -notmatch '\[failed\] Write container') {
    Fail 'output write failure must identify the failed stage'
} else { Ok 'write failure reports failed stage without completion' }

# Malformed relocation metadata must fail during input preflight, before commit.
$BadReloc = Join-Path $LogWork 'bad-reloc.exe'
$ExistingOutput = Join-Path $LogWork 'preserved.exe'
$Bytes = [IO.File]::ReadAllBytes($Fixture)
$NtAt = [BitConverter]::ToUInt32($Bytes, 0x3c)
$OptionalAt = $NtAt + 24
$RelocRva = [BitConverter]::ToUInt32($Bytes, $OptionalAt + 112 + 5 * 8)
$SectionTableAt = $OptionalAt + [BitConverter]::ToUInt16($Bytes, $NtAt + 20)
$SectionCount = [BitConverter]::ToUInt16($Bytes, $NtAt + 6)
$RelocRaw = $null
for ($Index = 0; $Index -lt $SectionCount; ++$Index) {
    $At = $SectionTableAt + $Index * 40
    $Rva = [BitConverter]::ToUInt32($Bytes, $At + 12)
    $RawSize = [BitConverter]::ToUInt32($Bytes, $At + 16)
    $RawOffset = [BitConverter]::ToUInt32($Bytes, $At + 20)
    if ($RelocRva -ge $Rva -and ($RelocRva - $Rva) -lt $RawSize) {
        $RelocRaw = $RawOffset + $RelocRva - $Rva
        break
    }
}
if ($null -eq $RelocRaw) {
    Fail 'fixture relocation table missing for malformed-input test'
} else {
    [BitConverter]::GetBytes([uint32]9).CopyTo($Bytes, $RelocRaw + 4)
    [IO.File]::WriteAllBytes($BadReloc, $Bytes)
    [IO.File]::WriteAllText($ExistingOutput, 'preserve-existing-output')
    & $Pevm wrap $BadReloc $ExistingOutput $BuildPassword *> $FailureLog
    $ExitCode = $LASTEXITCODE
    $Failure = Get-Content $FailureLog -Raw
    if ($ExitCode -eq 0 -or $Failure -match '\[complete\]' -or
        $Failure -notmatch 'invalid relocation block size' -or
        [IO.File]::ReadAllText($ExistingOutput) -ne 'preserve-existing-output') {
        Fail 'malformed relocation must fail before replacing existing output'
    } else { Ok 'malformed relocation rejected during preflight; existing output preserved' }
}
