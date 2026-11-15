# Real CLI/loader checks, sourced after Invoke-Protected is defined.
$OptionWork = Join-Path $Work ('vm-options-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $OptionWork | Out-Null
$FixtureText = Get-FixtureText
$First = if ($FixtureText -match 'PEVM-FIXTURE-RVA LiftTarget=0x([0-9A-Fa-f]+)') { '0x' + $Matches[1] } else { throw 'LiftTarget missing' }
$Second = if ($FixtureText -match 'PEVM-FIXTURE-RVA LoopTarget=0x([0-9A-Fa-f]+)') { '0x' + $Matches[1] } else { throw 'LoopTarget missing' }
foreach ($Case in @(
    @{Command='protect-function'; Rvas=@($First); Count=1; Complexity=0},
    @{Command='protect-function'; Rvas=@($First); Count=10; Complexity=100},
    @{Command='protect-functions'; Rvas=@($First,$Second); Count=3; Complexity=75},
    @{Command='protect-all'; Rvas=@(); Count=2; Complexity=100}
)) {
    $Output = Join-Path $OptionWork ($Case.Command + '-' + $Case.Count + '.exe')
    $Arguments = @($Case.Command, $Fixture, $Output, 'options-test-key') + $Case.Rvas + @(
        "--vm-instances=$($Case.Count)", "--vm-complexity=$($Case.Complexity)", '--anti-disasm', '--mutate', '--seed=0')
    $Marker = Invoke-Protected $Output $Arguments
    $Inspect = (& $Pevm inspect $Output 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $Inspect -notmatch "\.vmp3 VM instances: $($Case.Count)\b" -or
        $Inspect -notmatch "\.vmp3 VM complexity: $($Case.Complexity)\b") {
        Fail 'VM options missing from serialized wrapper'
    }
    if ($Case.Count -eq 10) {
        $Seen = @([regex]::Matches($Marker, 'index=0 instance=(\d+) instances=10') |
            ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique)
        if (($Seen -join ',') -ne '0,1,2,3,4,5,6,7,8,9') { Fail 'not all ten VM instances executed' }
        else { Ok 'all ten independently compiled instances executed successfully' }
    }
    Ok "$($Case.Command): instances=$($Case.Count), complexity=$($Case.Complexity)"
}

foreach ($Command in @('protect-function', 'protect-functions', 'protect-all')) {
    $Output = Join-Path $OptionWork ($Command + '-disabled.exe')
    $Rvas = @(if ($Command -eq 'protect-function') { $First } elseif ($Command -eq 'protect-functions') { $First; $Second })
    & $Pevm $Command $Fixture $Output options-test-key @Rvas --vm-instances=0 --vm-complexity=100 *> (Join-Path $OptionWork 'disabled.log')
    if ($LASTEXITCODE -ne 0) { throw "zero-instance $Command failed" }
    $Inspect = (& $Pevm inspect $Output 2>&1) -join "`n"
    if ($Inspect -notmatch '\.vmp3: not present') { Fail "$Command created VM code with zero instances" }
    $env:PEVM_TEST_NO_DIALOG = '1'
    try {
        if ((Invoke-Wrapped $Output ($Command + '-disabled')) -ne 0) { Fail 'zero-instance wrapper failed' }
    } finally { Remove-Item env:PEVM_TEST_NO_DIALOG -ErrorAction SilentlyContinue }
    Ok "${Command}: zero instances preserves native execution"
}

$Preserved = Join-Path $OptionWork 'preserved.exe'
[IO.File]::WriteAllText($Preserved, 'keep-existing-output')
foreach ($Option in @('--vm-instances=-1','--vm-instances=11','--vm-instances=1.5','--vm-instances=2junk',
    '--vm-instances=','--vm-instances=4294967296','--vm-complexity=-1','--vm-complexity=101',
    '--vm-complexity=3.5','--vm-complexity=4junk','--vm-complexity=','--vm-complexity=4294967296')) {
    & $Pevm protect-function $Fixture $Preserved options-test-key $First $Option *> (Join-Path $OptionWork 'invalid.log')
    if ($LASTEXITCODE -eq 0 -or [IO.File]::ReadAllText($Preserved) -ne 'keep-existing-output') {
        Fail "invalid VM option accepted or replaced output: $Option"
    }
}
Ok 'invalid option ranges, signs, suffixes and overflows rejected before output commit'

$Seeds = @()
foreach ($Index in 0..1) {
    $Output = Join-Path $OptionWork "automatic-$Index.exe"
    & $Pevm protect-function $Fixture $Output options-test-key $First *> (Join-Path $OptionWork 'automatic.log')
    if ($LASTEXITCODE -ne 0) { throw 'automatic seed build failed' }
    $Inspect = (& $Pevm inspect $Output 2>&1) -join "`n"
    if ($Inspect -match '\.vmp3 seed: (0x[0-9a-f]+)') { $Seeds += $Matches[1] }
}
if ($Seeds.Count -ne 2 -or $Seeds[0] -eq $Seeds[1]) { Fail 'default protection seed is fixed' }
else { Ok 'default protection builds use different seeds' }
