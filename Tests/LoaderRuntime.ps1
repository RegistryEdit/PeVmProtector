$LoaderWork = Join-Path $Work ('loader-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $LoaderWork | Out-Null
$PreviousPluginPath = $env:QT_QPA_PLATFORM_PLUGIN_PATH
$PreviousPlatform = $env:QT_QPA_PLATFORM
$PreviousNoDialog = $env:PEVM_TEST_NO_DIALOG
$PreviousErrorLog = $env:PEVM_TEST_ERROR_LOG
$PreviousBridgeLog = $env:PEVM_TEST_VM_BRIDGE_LOG
try {
    $env:QT_QPA_PLATFORM_PLUGIN_PATH = Join-Path $QtDir 'plugins/platforms'
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:PEVM_TEST_NO_DIALOG = '1'
    $env:PEVM_TEST_ERROR_LOG = '1'
    # Keep the executable beside its DLLs; wrapper startup uses its own directory.
    foreach ($Name in @('LoaderFixture', 'LoaderQtFixture')) {
        $InputExe = Join-Path $Bin "$Name.exe"
        if (-not (Test-Path $InputExe)) { Fail "$Name missing - build the solution first"; continue }
        & $InputExe *> (Join-Path $LoaderWork "$Name.native.log")
        if ($LASTEXITCODE -ne 0) { Fail "$Name native fixture failed: $LASTEXITCODE"; continue }
        foreach ($Command in @('wrap', 'protect-all')) {
            $Output = Join-Path $Bin "$Name.$Command.exe"
            & $Pevm $Command $InputExe $Output loader-regression-key --compress *> (Join-Path $LoaderWork "$Name.$Command.build.log")
            if ($LASTEXITCODE -ne 0) { Fail "$Name $Command build failed"; continue }
            $Proc = Start-Process -FilePath $Output -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput (Join-Path $LoaderWork "$Name.$Command.out.log") `
                -RedirectStandardError (Join-Path $LoaderWork "$Name.$Command.err.log")
            $null = $Proc.Handle # retain the process handle for short-lived GUI executables
            if (-not $Proc.WaitForExit(20000)) {
                Stop-Process -Id $Proc.Id
                Fail "$Name $Command timed out"
            } elseif ($Proc.ExitCode -ne 0) {
                Fail "$Name $Command exited $($Proc.ExitCode); see $LoaderWork"
            } else { Ok "$Name ${Command}: TLS initialization, thread lifetime and runtime startup" }
        }
    }
    # Explicit selection prevents automatic skipping from hiding a regression.
    foreach ($Export in @('LoaderCallWithStack','LoaderSimd','LoaderExceptionFragment','LoaderSehFragment')) {
      & {
        $InputExe = Join-Path $Bin 'LoaderFixture.exe'
        $ScanPath = Join-Path $LoaderWork "$Export.scan.json"
        & $Pevm scan-functions $InputExe $ScanPath *> (Join-Path $LoaderWork "$Export.scan.log")
        if ($LASTEXITCODE -ne 0) { Fail "$Export scan failed"; return }
        $Scan = Get-Content -LiteralPath $ScanPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $Targets = @($Scan.functions | Where-Object { $_.name -eq $Export -or $_.aliases -contains $Export })
        if ($Targets.Count -ne 1) { Fail "$Export expected one export"; return }
        $Output = Join-Path $Bin "LoaderFixture.$Export.exe"
        $BuildLog = Join-Path $LoaderWork "$Export.build.log"
        & $Pevm protect-function $InputExe $Output loader-regression-key $Targets[0].rva --compress --mutate --anti-disasm *> $BuildLog
        if ($LASTEXITCODE -ne 0) { Fail "$Export protection failed"; return }
        if ($Export -like '*Fragment' -and (Get-Content $BuildLog -Raw) -notmatch 'mode=native-EH-fragment') {
            Fail "$Export did not preserve its native exception frame"; return
        }
        $MarkerPath = "$Output.vmbridge-hit"
        if (Test-Path -LiteralPath $MarkerPath) { Remove-Item -LiteralPath $MarkerPath }
        $env:PEVM_TEST_VM_BRIDGE_LOG = '1'
        $OutLog = Join-Path $LoaderWork "$Export.out.log"
        $Proc = Start-Process -FilePath $Output -PassThru -WindowStyle Hidden -RedirectStandardOutput $OutLog `
            -RedirectStandardError (Join-Path $LoaderWork "$Export.err.log")
        $null = $Proc.Handle
        try {
            if (-not $Proc.WaitForExit(20000)) {
                Stop-Process -Id $Proc.Id; Fail "$Export timed out"
            } elseif ($Proc.ExitCode -ne 0) {
                Fail "$Export exited $($Proc.ExitCode); see $LoaderWork"
            } elseif (-not (Test-Path -LiteralPath $MarkerPath)) {
                Fail "$Export VM bridge was not executed"
            } elseif ((Get-Content -LiteralPath $MarkerPath -Raw) -notmatch 'index=0\b') {
                Fail "$Export expected VM entry 0"
            } elseif ((Get-Content -LiteralPath $OutLog -Raw) -notmatch 'PEVM_SIMD_EH_OK') {
                Fail "$Export missing SIMD/EH result verification"
            } else {
                Ok "explicit VM entry: $Export, native result, TLS/thread reentry and exception behavior"
            }
        } finally { $Proc.Dispose() }
      }
    }
    # Automatic protection still produces a runnable encrypted wrapper when
    # every candidate is excluded; it must disclose that no VM was installed.
    $Output = Join-Path $Bin 'LoaderFixture.no-vm.exe'
    $BuildLog = Join-Path $LoaderWork 'no-vm.build.log'
    $NoExports = Join-Path $Bin 'LoaderFixture.noexports.exe'
    $FixtureBytes = [IO.File]::ReadAllBytes((Join-Path $Bin 'LoaderFixture.exe'))
    $NtOffset = [BitConverter]::ToUInt32($FixtureBytes, 0x3c)
    # Exports with unknown size intentionally survive the minimum-size filter.
    # This fixture does not use its own exports, so remove only that directory.
    [Array]::Clear($FixtureBytes, $NtOffset + 24 + 112, 8)
    [IO.File]::WriteAllBytes($NoExports, $FixtureBytes)
    & $Pevm protect-all $NoExports $Output loader-regression-key `
        --min-bytes=4294967295 --compress --mutate --anti-disasm *> $BuildLog
    if ($LASTEXITCODE -ne 0) { Fail 'no eligible VM functions: wrapper build failed' }
    elseif ((Get-Content $BuildLog -Raw) -notmatch '0 functions; no eligible VM entries; encrypted wrapper only') {
        Fail 'no eligible VM functions: result not disclosed'
    } else {
        $Inspection = (& $Pevm inspect $Output) -join "`n"
        if ($Inspection -notmatch '\.vmp3: not present') { Fail 'no eligible VM functions: unexpected VM section' }
        $Proc = Start-Process -FilePath $Output -PassThru -WindowStyle Hidden
        $null = $Proc.Handle
        if (-not $Proc.WaitForExit(20000)) { Stop-Process -Id $Proc.Id; Fail 'no eligible VM functions: wrapper timed out' }
        elseif ($Proc.ExitCode -ne 0) { Fail "no eligible VM functions: wrapper exited $($Proc.ExitCode)" }
        else { Ok 'no eligible VM functions: encrypted wrapper starts, zero VM functions disclosed' }
    }
} finally {
    $env:QT_QPA_PLATFORM_PLUGIN_PATH = $PreviousPluginPath
    $env:QT_QPA_PLATFORM = $PreviousPlatform
    $env:PEVM_TEST_NO_DIALOG = $PreviousNoDialog
    $env:PEVM_TEST_ERROR_LOG = $PreviousErrorLog
    $env:PEVM_TEST_VM_BRIDGE_LOG = $PreviousBridgeLog
}
