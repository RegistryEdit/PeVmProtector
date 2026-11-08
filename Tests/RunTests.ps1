# PeVmProtector test runner (replacement for the retired ctest suite).
# Usage:  powershell -ExecutionPolicy Bypass -File Tests\RunTests.ps1 [-Configuration Release]
param(
    [string]$Configuration = "Release",
    [string]$QtDir = 'D:\Qt\6.7.3\msvc2022_64',
    [string]$BinDirectory = ''
)
$ErrorActionPreference = "Continue"   # native stderr must not become a terminating error; assertions use exit codes

$Root = Split-Path -Parent $PSScriptRoot
$Bin = if ($BinDirectory) { [IO.Path]::GetFullPath($BinDirectory) } else { Join-Path $Root "bin\$Configuration" }
$Pevm = Join-Path $Bin "PeVm.exe"
$Fixture = Join-Path $Bin "LifterFixture.exe"
$Work = Join-Path $Bin "TestArtifacts"
if (-not (Test-Path $Pevm)) { throw "PeVm.exe not found at $Pevm - build the solution first" }
New-Item -ItemType Directory -Force -Path $Work | Out-Null

$Script:Failures = @()
function Fail([string]$Message) { $Script:Failures += $Message; Write-Host "  FAIL: $Message" -ForegroundColor Red }
function Ok([string]$Message) { Write-Host "  ok:  $Message" -ForegroundColor Green }

function Run-Step([string]$Name, [scriptblock]$Body) {
    Write-Host "== $Name" -ForegroundColor Cyan
    & $Body
}

# Runs a wrapper (GUI-subsystem process) and waits for it; returns the exit code.
function Invoke-Wrapped([string]$Exe, [string]$LogName) {
    $OutLog = Join-Path $Work "$LogName.out.log"
    $ErrLog = Join-Path $Work "$LogName.err.log"
    $Proc = Start-Process -FilePath $Exe -PassThru -Wait -WindowStyle Hidden `
            -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog
    return $Proc.ExitCode
}

function Get-FixtureText {
    return ((& $Fixture 2>&1) -join "`n")
}

# ---------------------------------------------------------------------------
Run-Step "pe_architecture_regression" {
    $Regression = Join-Path $Bin "PeRegression.exe"
    if (-not (Test-Path $Regression)) { Fail "PeRegression.exe missing - build the solution first"; return }
    & $Regression
    if ($LASTEXITCODE -ne 0) { Fail "PE architecture regression exited $LASTEXITCODE" }
    else { Ok "PE parsing, snapshot lifting, memory containers and transactional output" }
}

# ---------------------------------------------------------------------------
Run-Step "function_names_and_selection" {
    . (Join-Path $PSScriptRoot 'FunctionSymbols.ps1')
    $Regression = Join-Path $Bin 'FunctionSelection.exe'
    if (-not (Test-Path $Regression)) { Fail 'FunctionSelection.exe missing - build the solution first'; return }
    $PreviousPlatformPath = $env:QT_QPA_PLATFORM_PLUGIN_PATH
    $PreviousStderr = $env:QT_FORCE_STDERR_LOGGING
    $PluginPath = Join-Path $QtDir 'plugins\platforms'
    if (-not (Test-Path (Join-Path $PluginPath 'qoffscreen.dll'))) { Fail 'qoffscreen.dll missing; pass -QtDir'; return }
    try {
        $env:QT_QPA_PLATFORM_PLUGIN_PATH = $PluginPath
        $env:QT_FORCE_STDERR_LOGGING = '1'
        & $Regression -platform offscreen *> (Join-Path $Work 'function-selection.log')
        if ($LASTEXITCODE -ne 0) { Fail 'GUI function selection regression failed; see function-selection.log' }
        else { Ok 'GUI function selection, filtering, exact output and stale scan invalidation' }
    } finally {
        $env:QT_QPA_PLATFORM_PLUGIN_PATH = $PreviousPlatformPath
        $env:QT_FORCE_STDERR_LOGGING = $PreviousStderr
    }
}

Run-Step "gui_all_features" {
    $Regression = Join-Path $Bin 'GuiFeatures.exe'
    if (-not (Test-Path $Regression)) { Fail 'GuiFeatures.exe missing - build the solution first'; return }
    $PreviousPlatformPath = $env:QT_QPA_PLATFORM_PLUGIN_PATH
    $PreviousStderr = $env:QT_FORCE_STDERR_LOGGING
    $PluginPath = Join-Path $QtDir 'plugins\platforms'
    if (-not (Test-Path (Join-Path $PluginPath 'qoffscreen.dll'))) { Fail 'qoffscreen.dll missing; pass -QtDir'; return }
    try {
        $env:QT_QPA_PLATFORM_PLUGIN_PATH = $PluginPath
        $env:QT_FORCE_STDERR_LOGGING = '1'
        & $Regression -platform offscreen *> (Join-Path $Work 'gui-features.log')
        if ($LASTEXITCODE -ne 0) { Fail 'GUI feature regression failed; see gui-features.log' }
        else { Ok 'All CLI commands through GUI, license issuance/verification, protected execution, options and bilingual renders' }
    } finally {
        $env:QT_QPA_PLATFORM_PLUGIN_PATH = $PreviousPlatformPath
        $env:QT_FORCE_STDERR_LOGGING = $PreviousStderr
    }
}

Run-Step "vm_self_test" {
    $Out = & $Pevm self-test 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "self-test exited $LASTEXITCODE" } else { Ok "self-test" }
    $VmOut = & $Pevm vm2-self-test 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "vm2-self-test exited $LASTEXITCODE" }
    elseif (($VmOut -join "`n") -notmatch "VM2 self-test: OK") { Fail "vm2-self-test output invalid" }
    else { Ok "vm2-self-test" }
}

# ---------------------------------------------------------------------------
Run-Step "vm_compiled_and_mutation_regression" {
    $Regression = Join-Path $Bin "VmRegression.exe"
    if (-not (Test-Path $Regression)) { Fail "VmRegression.exe missing - build the solution first"; return }
    & $Regression
    if ($LASTEXITCODE -ne 0) { Fail "VM regression exited $LASTEXITCODE" }
    else { Ok "compiled VM and mutation regression" }
}

# ---------------------------------------------------------------------------
Run-Step "license_regression" {
    $Regression = Join-Path $Bin "LicenseRegression.exe"
    if (-not (Test-Path $Regression)) { Fail "LicenseRegression.exe missing"; return }
    & $Regression $Work
    if ($LASTEXITCODE -ne 0) { Fail "License regression exited $LASTEXITCODE" }
    else { Ok "signed license regression" }
}

# ---------------------------------------------------------------------------
Run-Step "license_runtime" {
    $Regression = Join-Path $Bin "LicenseRuntime.exe"
    if (-not (Test-Path $Regression)) { Fail "LicenseRuntime.exe missing"; return }
    & $Regression $Work *> (Join-Path $Work 'license-runtime.log')
    if ($LASTEXITCODE -ne 0) { Fail "License runtime regression failed; see license-runtime.log" }
    else { Ok "native bilingual dialog, retry/cancel, DPAPI cache, expiry and source fallback" }
}

Run-Step "dependency_fixture" {
    Push-Location $Bin
    try {
        & (Join-Path $Bin "DependencyApp.exe") | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "DependencyApp exited $LASTEXITCODE" } else { Ok "DependencyApp" }
    } finally { Pop-Location }
}

Run-Step "loader_tls_and_qt" {
    . (Join-Path $PSScriptRoot 'LoaderRuntime.ps1')
}

# ---------------------------------------------------------------------------
Run-Step "x64_lift_matrix" {
    $FixtureText = Get-FixtureText
    if ($LASTEXITCODE -ne 0) { throw "LifterFixture failed" }
    $Targets = @{}
    foreach ($Line in ($FixtureText -split "`n")) {
        if ($Line -match "^PEVM-FIXTURE-RVA (\w+)=0x([0-9A-Fa-f]+) rcx=0x([0-9A-Fa-f]+) rdx=0x([0-9A-Fa-f]+) r8=0x([0-9A-Fa-f]+) r9=0x([0-9A-Fa-f]+) rax=0x([0-9A-Fa-f]+)") {
            $Targets[$Matches[1]] = @{
                Rva = "0x" + $Matches[2]; Rcx = "0x" + $Matches[3]; Rdx = "0x" + $Matches[4]
                R8 = "0x" + $Matches[5]; R9 = "0x" + $Matches[6]; Expected = "0x" + $Matches[7]
            }
        }
    }
    if (-not $Targets.ContainsKey("LiftTarget")) { throw "fixture output did not include a LiftTarget RVA" }

    $Negative = @("CpuIdTarget")
    foreach ($Name in $Targets.Keys) {
        $T = $Targets[$Name]
        $Json = Join-Path $Work "lift-matrix-$Name.json"
        $LiftOut = & $Pevm lift-x64 $Fixture $T.Rva $Json "--rcx=$($T.Rcx)" "--rdx=$($T.Rdx)" "--r8=$($T.R8)" "--r9=$($T.R9)" 2>&1
        $Combined = ($LiftOut -join "`n").ToLowerInvariant()
        if ($Name -in $Negative) {
            if ($LASTEXITCODE -eq 0) { Fail "$Name expected lift failure, got success" }
            elseif ($Combined -notmatch "not liftable|unsupported") { Fail "$Name lift failure lacks fail-closed reason" }
            else { Ok "$Name (rejected)" }
        } else {
            if ($LASTEXITCODE -ne 0) { Fail "$Name lift failed: $Combined" }
            elseif ($Combined -notmatch "bridge smoke rax: $($T.Expected.ToLowerInvariant())\b") { Fail "$Name expected RAX $($T.Expected), got: $Combined" }
            else { Ok "$Name" }
        }
    }

    # Hand-assembled code blobs: NAME|HEX|RCX|RDX|EXPECTED
    $RawCases = @(
        "xchg_rcx_rdx|4887D14889D0C3|0x11|0x22|0x11",
        "setae_false|4839D10F93C1480FB6C1C3|0x11|0x22|0x0",
        "setae_true|4839D10F93C1480FB6C1C3|0x33|0x22|0x1",
        "setb_true|4839D10F92C1480FB6C1C3|0x11|0x22|0x1",
        "sete_true|48F7C1110000000F94C1480FB6C1C3|0x22|0x0|0x1",
        "sete_false|48F7C1110000000F94C1480FB6C1C3|0x11|0x0|0x0",
        "setl_true|4839D10F9CC1480FB6C1C3|0xFFFFFFFFFFFFFFFF|0x1|0x1",
        "push_imm32|683412000058C3|0x0|0x0|0x1234",
        "push_imm8_sext|6AFB58C3|0x0|0x0|0xfffffffffffffffb",
        "movsxd_neg|4863CA4889C8C3|0x0|0xFFFFFFFF|0xffffffffffffffff",
        "movsxd_pos|4863CA4889C8C3|0x0|0x7|0x7",
        "neg|48F7D94889C8C3|0x5|0x0|0xfffffffffffffffb",
        "not|48F7D14889C8C3|0x0|0x0|0xffffffffffffffff",
        "movzx_reg8|480FB6C94889C8C3|0x1FF|0x0|0xff",
        "movzx_mem16|480FB701C3|0x40|0x0|0x0",
        "movsx_reg16|480FBFC94889C8C3|0xFFFF|0x0|0xffffffffffffffff",
        "test_imm_sete|48F7C1110000000F94C1480FB6C1C3|0x22|0x0|0x1",
        "test_imm_sete_zero|48F7C1110000000F94C1480FB6C1C3|0x11|0x0|0x0",
        "add_mem_imm|48810134120000488B01C3|0x40|0x0|0x1234",
        "and_mem_imm8|48832105488B01C3|0x40|0x0|0x0",
        "add_mem_reg|480111488B01C3|0x40|0x7B|0x7b",
        "or_mem_reg|480911488B01C3|0x40|0x55|0x55",
        "xor_mem_reg|483111488B01C3|0x40|0x55|0x55",
        "acc_add_imm|480534120000C3|0x0|0x0|0x1234",
        "acc_and_imm|4889C84825FF000000C3|0x1FF|0x0|0xff",
        "acc_xor_imm|4889C8483555000000C3|0x0|0x0|0x55",
        "acc_cmp_sete|4889C8483D110000000F94C1480FB6C1C3|0x11|0x0|0x1",
        "adc_carry_true|48F7D94883D2004889D0C3|0x5|0x0|0x1",
        "adc_carry_false|48F7D94883D2004889D0C3|0x0|0x0|0x0",
        "sbb_borrow|483BD94883D9054889C8C3|0x11|0x22|0xb",
        "rol_imm|4889C848C1C007C3|0x1234|0x0|0x91a00",
        "ror_imm|4889C848C1C803C3|0x1234|0x0|0x8000000000000246",
        "rol_cl|4889D048D3C0C3|0x7|0x1234|0x91a00",
        "bswap|4889C8480FC8C3|0x123456789|0x0|0x8967452301000000"
    )
    foreach ($Case in $RawCases) {
        $Parts = $Case -split "\|"
        $RawOut = & $Pevm lift-raw $Parts[1] 0 "--rcx=$($Parts[2])" "--rdx=$($Parts[3])" 2>&1
        $Raw = ($RawOut -join "`n").ToLowerInvariant()
        if ($LASTEXITCODE -ne 0) { Fail "$($Parts[0]) raw lift failed: $Raw" }
        elseif ($Raw -notmatch "raw bridge rax: $($Parts[4].ToLowerInvariant())\b") { Fail "$($Parts[0]) expected RAX $($Parts[4]), got: $Raw" }
        else { Ok $Parts[0] }
    }
    $Locked = & $Pevm lift-raw F0480111488B01C3 0 --rcx=0x40 --rdx=0x7b 2>&1
    if ($LASTEXITCODE -eq 0 -or ($Locked -join "`n") -notmatch 'LOCK atomic') {
        Fail 'LOCK operation must retain atomicity or be rejected'
    } else { Ok 'LOCK operation rejected without losing atomic semantics' }

    $MultiOut = & $Pevm lift-x64-multi $Fixture (Join-Path $Work "lift-multi.json") $Targets["LiftTarget"].Rva $Targets["LiftTarget"].Rva 2>&1
    if ($LASTEXITCODE -ne 0 -or (($MultiOut -join "`n") -notmatch "multi-function lift: 2 functions")) {
        Fail "multi-function lift failed"
    } else { Ok "lift-x64-multi" }
}

# ---------------------------------------------------------------------------
function Invoke-Protected([string]$Output, [string[]]$ProtectArgs) {
    Remove-Item $Output, "$Output.vmbridge-hit" -ErrorAction SilentlyContinue
    & $Pevm @ProtectArgs *> (Join-Path $Work "protect.log")
    if ($LASTEXITCODE -ne 0) { throw "protect failed: $(Get-Content (Join-Path $Work "protect.log") -Raw)" }
    $env:PEVM_TEST_NO_DIALOG = "1"
    $env:PEVM_TEST_VM_BRIDGE_LOG = "1"
    try {
        $ExitCode = Invoke-Wrapped $Output "protected-run"
        if ($ExitCode -ne 0) { throw "protected fixture failed with exit $ExitCode" }
    } finally {
        Remove-Item env:PEVM_TEST_NO_DIALOG, env:PEVM_TEST_VM_BRIDGE_LOG -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path "$Output.vmbridge-hit")) { throw "protected process ran without VM bridge marker" }
    return (Get-Content "$Output.vmbridge-hit" -Raw)
}

Run-Step "protected_function_vm_bridge" {
    $Rva = if ((Get-FixtureText) -match "PEVM-FIXTURE-RVA LiftTarget=0x([0-9A-Fa-f]+)") { "0x" + $Matches[1] } else { throw "no LiftTarget RVA" }
    $Output = Join-Path $Work "LifterFixture.virtualized.exe"
    $Marker = Invoke-Protected $Output @("protect-function", $Fixture, $Output, "build-key", $Rva, "0x1234")
    if ($Marker -notmatch "VM2 bridge invoked") { Fail "invalid bridge marker" } else { Ok "single function bridged" }
}

# ---------------------------------------------------------------------------
Run-Step "protected_multi_vm_bridge" {
    $FixtureText = Get-FixtureText
    $R1 = if ($FixtureText -match "PEVM-FIXTURE-RVA LiftTarget=0x([0-9A-Fa-f]+)") { "0x" + $Matches[1] } else { throw "no LiftTarget RVA" }
    $R2 = if ($FixtureText -match "PEVM-FIXTURE-RVA LoopTarget=0x([0-9A-Fa-f]+)") { "0x" + $Matches[1] } else { throw "no LoopTarget RVA" }
    $Output = Join-Path $Work "LifterFixture.multi.exe"
    Invoke-Protected $Output @("protect-functions", $Fixture, $Output, "build-key", $R1, $R2, "--seed=0x1234") | Out-Null
    $Inspect = & $Pevm inspect $Output 2>&1
    if (($Inspect -join "`n") -notmatch "\.vmp3 functions: 2") { Fail "inspect does not report two .vmp3 functions" }
    $Marker = Get-Content "$Output.vmbridge-hit" -Raw
    if ($Marker -notmatch "index=0" -or $Marker -notmatch "index=1") { Fail "not both functions were bridged" }
    else { Ok "both functions bridged" }
}

# ---------------------------------------------------------------------------
Run-Step "anti_debug_native_regression" {
    $Regression = Join-Path $Bin 'AntiDebugRegression.exe'
    if (-not (Test-Path $Regression)) { Fail 'AntiDebugRegression.exe missing - build the solution first'; return }
    $Proc = Start-Process -FilePath $Regression -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Work 'anti-debug-native.out.log') `
        -RedirectStandardError (Join-Path $Work 'anti-debug-native.err.log')
    # Retain the process handle before a timed wait; Windows PowerShell 5.1
    # can otherwise lose the exit code for a quickly exiting process.
    $null = $Proc.Handle
    if (-not $Proc.WaitForExit(30000)) {
        $Proc.Kill()
        $Proc.WaitForExit()
        Fail 'anti-debug regression timed out (possible suspended-thread hang)'
    } elseif ($Proc.ExitCode -ne 0) { Fail 'anti-debug regression failed; see anti-debug-native logs' }
    else { Ok 'real hardware breakpoints, disabled slots, Debug/Release policy, resume and handle lifetime' }
    $Proc.Dispose()
}

Run-Step "loader_anti_debug" {
    $Output = Join-Path $Work "LifterFixture.anti.exe"
    Remove-Item $Output, "$Output.loader-error.txt" -ErrorAction SilentlyContinue
    & $Pevm wrap $Fixture $Output anti-debug-key *> (Join-Path $Work "wrap.log")
    if ($LASTEXITCODE -ne 0) { throw "wrap failed: $(Get-Content (Join-Path $Work "wrap.log") -Raw)" }

    $env:PEVM_TEST_FAKE_DEBUGGER = "1"
    $env:PEVM_TEST_ERROR_LOG = "1"
    $env:PEVM_TEST_NO_DIALOG = "1"
    $PreviousAllowDebugger = $env:PEVM_ALLOW_DEBUGGER
    try {
        Remove-Item env:PEVM_ALLOW_DEBUGGER -ErrorAction SilentlyContinue
        $ExitCode = Invoke-Wrapped $Output "fake-debugger-run"
        if ($ExitCode -eq 0) { Fail "loader did not fail closed under simulated debugger" }
        elseif (-not (Test-Path "$Output.loader-error.txt")) { Fail "loader error log missing" }
        else {
            $ErrLog = Get-Content "$Output.loader-error.txt" -Raw
            if ($ErrLog -notmatch "loader integrity check failed") { Fail "unexpected loader error: $ErrLog" }
            else { Ok "simulated debugger rejected" }
        }
        foreach ($Value in @('1', '0', 'true', '01', '11', '1 ', ' 1')) {
            $env:PEVM_ALLOW_DEBUGGER = $Value
            Remove-Item "$Output.loader-error.txt" -ErrorAction SilentlyContinue
            $ExitCode = Invoke-Wrapped $Output ('debugger-policy-' + [Array]::IndexOf(@('1', '0', 'true', '01', '11', '1 ', ' 1'), $Value))
            if ($Configuration -eq 'Debug' -and $Value -ceq '1') {
                if ($ExitCode -ne 0) { Fail 'Debug exact-value opt-out failed' }
                else { Ok 'Debug exact-value opt-out' }
            } elseif ($ExitCode -eq 0) { Fail "$Configuration accepted debugger bypass value '$Value'" }
            elseif (-not (Test-Path "$Output.loader-error.txt")) { Fail 'debugger policy rejection log missing' }
            elseif ((Get-Content "$Output.loader-error.txt" -Raw) -notmatch 'loader integrity check failed') {
                Fail 'debugger policy produced an unrelated failure'
            } else { Ok "$Configuration rejects bypass value '$Value'" }
        }
    } finally {
        $env:PEVM_ALLOW_DEBUGGER = $PreviousAllowDebugger
        Remove-Item env:PEVM_TEST_FAKE_DEBUGGER, env:PEVM_TEST_ERROR_LOG, env:PEVM_TEST_NO_DIALOG -ErrorAction SilentlyContinue
    }

    $env:PEVM_TEST_NO_DIALOG = "1"
    try {
        $ExitCode = Invoke-Wrapped $Output "anti-normal-run"
        if ($ExitCode -ne 0) { Fail "wrapper failed without debugger simulation" } else { Ok "wrapper runs normally" }
    } finally { Remove-Item env:PEVM_TEST_NO_DIALOG -ErrorAction SilentlyContinue }

    # VM program runtime tamper verification.
    $Corrupt = Join-Path $Work "LifterFixture.corrupt.exe"
    $Rva = if ((Get-FixtureText) -match "PEVM-FIXTURE-RVA LiftTarget=0x([0-9A-Fa-f]+)") { "0x" + $Matches[1] } else { throw "no LiftTarget RVA" }
    Remove-Item $Corrupt, "$Corrupt.loader-error.txt" -ErrorAction SilentlyContinue
    & $Pevm protect-function $Fixture $Corrupt anti-debug-key $Rva *> (Join-Path $Work "corrupt-build.log")
    if ($LASTEXITCODE -ne 0) { throw "protect-function failed" }
    $env:PEVM_TEST_CORRUPT_VM = "1"
    $env:PEVM_TEST_ERROR_LOG = "1"
    $env:PEVM_TEST_NO_DIALOG = "1"
    try {
        $ExitCode = Invoke-Wrapped $Corrupt "corrupt-run"
        if ($ExitCode -eq 0) { Fail "corrupted VM program was executed without rejection" }
        else {
            $ErrLog = Get-Content "$Corrupt.loader-error.txt" -Raw
            if ($ErrLog -notmatch "loader integrity check failed") { Fail "unexpected error for corrupted VM: $ErrLog" }
            else { Ok "corrupted VM program rejected" }
        }
    } finally {
        Remove-Item env:PEVM_TEST_CORRUPT_VM, env:PEVM_TEST_ERROR_LOG, env:PEVM_TEST_NO_DIALOG -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
Run-Step "driver_sys_support" {
    # Patch a fixture copy's subsystem to NATIVE (1): structurally a driver
    # image without needing the DDK. Container protection must accept it,
    # runnable wrappers must reject it, and the lifter must still work.
    $SysImage = Join-Path $Work "fixture.sys"
    $Bytes = [IO.File]::ReadAllBytes($Fixture)
    $NtOffset = [BitConverter]::ToUInt32($Bytes, 0x3c)
    $Bytes[$NtOffset + 24 + 68] = 1
    [IO.File]::WriteAllBytes($SysImage, $Bytes)

    $Container = Join-Path $Work "fixture.sys.pvm"
    $Restored = Join-Path $Work "fixture.restored.sys"
    Remove-Item $Container, $Restored -ErrorAction SilentlyContinue
    & $Pevm pack $SysImage $Container driver-pass-1 *> (Join-Path $Work "driver-pack.log")
    if ($LASTEXITCODE -ne 0) { Fail "pack of native image failed" }
    else {
        $PackLog = Get-Content (Join-Path $Work "driver-pack.log") -Raw
        if ($PackLog -notmatch "subsystem=native") { Fail "pack log does not report native subsystem" }
        else { Ok "pack native image" }
    }
    & $Pevm unpack $Container $Restored driver-pass-1 *> (Join-Path $Work "driver-unpack.log")
    if ($LASTEXITCODE -ne 0) { Fail "unpack of native container failed" }
    elseif ((Get-FileHash $SysImage).Hash -ne (Get-FileHash $Restored).Hash) { Fail "native container roundtrip SHA mismatch" }
    else { Ok "native container roundtrip" }

    $Inspect = & $Pevm inspect $Container 2>&1
    if (($Inspect -join "`n") -notmatch "subsystem: native") { Fail "inspect does not report native subsystem" }
    else { Ok "inspect reports native" }

    & $Pevm wrap $SysImage (Join-Path $Work "driver-wrap.exe") driver-pass-1 *> (Join-Path $Work "driver-wrap.log")
    if ($LASTEXITCODE -eq 0) { Fail "wrap accepted a native payload" }
    elseif ((Get-Content (Join-Path $Work "driver-wrap.log") -Raw) -notmatch "native-subsystem") { Fail "wrap rejection lacks the native-subsystem message" }
    else { Ok "wrap rejects native payload" }

    $FixtureText = Get-FixtureText
    $Rva = if ($FixtureText -match "PEVM-FIXTURE-RVA LiftTarget=0x([0-9A-Fa-f]+)") { $Matches[1] } else { throw "no LiftTarget RVA" }
    $LiftOut = & $Pevm lift-x64 $SysImage "0x$Rva" (Join-Path $Work "driver-lift.json") "--rcx=0x11" "--rdx=0x22" "--r8=0x44" "--r9=0x88" 2>&1
    $Combined = ($LiftOut -join "`n").ToLowerInvariant()
    if ($LASTEXITCODE -ne 0) { Fail "lift-x64 failed on native image: $Combined" }
    elseif ($Combined -notmatch "bridge smoke rax: 0xff\b") { Fail "lift-x64 on native image wrong result: $Combined" }
    else { Ok "lift-x64 on native image" }
}

# ---------------------------------------------------------------------------
Run-Step "protect_all_virtualization" {
    # VMP-style full virtualization: discover all functions (.pdata+exports),
    # virtualize everything liftable, keep pointer-using functions native.
    $Output = Join-Path $Work "LifterFixture.all.exe"
    Remove-Item $Output, "$Output.vmbridge-hit" -ErrorAction SilentlyContinue
    & $Pevm protect-all $Fixture $Output build-key 0x1234 --anti-disasm *> (Join-Path $Work "protect-all.log")
    if ($LASTEXITCODE -ne 0) { throw "protect-all failed: $(Get-Content (Join-Path $Work "protect-all.log") -Raw)" }
    $BuildLog = Get-Content (Join-Path $Work "protect-all.log") -Raw
    if ($BuildLog -match "functions: (\d+)") {
        $Virtualized = [int]$Matches[1]
        if ($Virtualized -lt 4) { Fail "protect-all virtualized only $Virtualized functions" }
        else { Ok "protect-all virtualized $Virtualized functions" }
    } else { Fail "protect-all log missing function count" }
    if ($BuildLog -notmatch "skipped: \d+") { Fail "protect-all log missing skip report" }

    $Scan = & $Pevm scan-functions $Fixture (Join-Path $Work "scan.json") 2>&1
    if ($LASTEXITCODE -ne 0 -or (($Scan -join "`n") -notmatch "LiftTarget" -or ($Scan -join "`n") -notmatch "discovered functions: \d+")) {
        Fail "scan-functions failed or missed exports"
    } else { Ok "scan-functions" }

    $env:PEVM_TEST_NO_DIALOG = "1"
    $env:PEVM_TEST_VM_BRIDGE_LOG = "1"
    try {
        $ExitCode = Invoke-Wrapped $Output "protect-all-run"
        if ($ExitCode -ne 0) { throw "protected-all fixture failed with exit $ExitCode" }
    } finally {
        Remove-Item env:PEVM_TEST_NO_DIALOG, env:PEVM_TEST_VM_BRIDGE_LOG -ErrorAction SilentlyContinue
    }
    $Marker = Get-Content "$Output.vmbridge-hit" -Raw
    $Indices = @([regex]::Matches($Marker, 'index=(\d+)') | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique)
    if ($Indices.Count -lt 6) { Fail "expected at least six distinct virtualized functions to execute" }
    elseif (@($Indices | Where-Object { $_ -lt 0 -or $_ -ge $Virtualized }).Count) { Fail "bridge hit with an out-of-range index" }
    else { Ok "all virtualized functions bridged with correct indices" }
}

# ---------------------------------------------------------------------------
Run-Step "mutation_and_watermark" {
    # Mutation pass: the mutated VM program must still compute identical
    # results (fixture main self-validates), and the watermark must survive
    # into the wrapper metadata where inspect decodes it back.
    $Output = Join-Path $Work "LifterFixture.mutated.exe"
    $Rva = if ((Get-FixtureText) -match "PEVM-FIXTURE-RVA LiftTarget=0x([0-9A-Fa-f]+)") { "0x" + $Matches[1] } else { throw "no LiftTarget RVA" }
    Remove-Item $Output, "$Output.vmbridge-hit" -ErrorAction SilentlyContinue
    & $Pevm protect-function $Fixture $Output build-key $Rva --mutate --watermark=customer-x *> (Join-Path $Work "mutate-build.log")
    if ($LASTEXITCODE -ne 0) { throw "protect-function --mutate failed: $(Get-Content (Join-Path $Work "mutate-build.log") -Raw)" }

    $Inspect = & $Pevm inspect $Output 2>&1
    if (($Inspect -join "`n") -notmatch "watermark: customer-x") { Fail "inspect does not decode the watermark" }
    else { Ok "watermark roundtrip" }

    $env:PEVM_TEST_NO_DIALOG = "1"
    $env:PEVM_TEST_VM_BRIDGE_LOG = "1"
    try {
        $ExitCode = Invoke-Wrapped $Output "mutate-run"
        if ($ExitCode -ne 0) { throw "mutated fixture failed with exit $ExitCode" }
    } finally {
        Remove-Item env:PEVM_TEST_NO_DIALOG, env:PEVM_TEST_VM_BRIDGE_LOG -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path "$Output.vmbridge-hit")) { Fail "mutated program did not reach the VM bridge" }
    else { Ok "mutated program computes correctly" }

    # protect-all accepts the same options.
    $AllOutput = Join-Path $Work "LifterFixture.all-mutated.exe"
    & $Pevm protect-all $Fixture $AllOutput build-key 0x1234 --mutate *> (Join-Path $Work "mutate-all.log")
    if ($LASTEXITCODE -ne 0) { Fail "protect-all --mutate failed" } else { Ok "protect-all --mutate" }

    # A wrapper without a watermark reports none.
    $Plain = Join-Path $Work "LifterFixture.nowm.exe"
    & $Pevm wrap $Fixture $Plain anti-debug-key *> (Join-Path $Work "nowm-wrap.log")
    if ($LASTEXITCODE -ne 0) { throw "plain wrap failed" }
    $InspectPlain = & $Pevm inspect $Plain 2>&1
    if (($InspectPlain -join "`n") -match "watermark:") { Fail "plain wrapper unexpectedly reports a watermark" }
    else { Ok "no watermark by default" }
}

# ---------------------------------------------------------------------------
Run-Step "licensing_and_compression" {
    # Compressed container: unpacked bytes must equal the original exactly.
    $Container = Join-Path $Work "compressed.pvm"
    $Restored = Join-Path $Work "compressed.restored.exe"
    Remove-Item $Container, $Restored -ErrorAction SilentlyContinue
    & $Pevm pack $Fixture $Container compress-pass-1 --compress *> (Join-Path $Work "compress-pack.log")
    if ($LASTEXITCODE -ne 0) { Fail "pack --compress failed" }
    else {
        $PackLog = Get-Content (Join-Path $Work "compress-pack.log") -Raw
        if ($PackLog -notmatch "lzss") { Fail "pack log does not report lzss" } else { Ok "pack --compress" }
    }
    & $Pevm unpack $Container $Restored compress-pass-1 *> (Join-Path $Work "compress-unpack.log")
    if ($LASTEXITCODE -ne 0) { Fail "unpack of compressed container failed" }
    elseif ((Get-FileHash $Fixture).Hash -ne (Get-FileHash $Restored).Hash) { Fail "compressed roundtrip SHA mismatch" }
    else { Ok "compressed container roundtrip" }

    . (Join-Path $PSScriptRoot 'LicenseIntegration.ps1')
}

# ---------------------------------------------------------------------------
Run-Step "detailed_build_output" {
    . (Join-Path $PSScriptRoot 'BuildOutput.ps1')
}

Write-Host ""
if ($Script:Failures.Count -gt 0) {
    Write-Host "$($Script:Failures.Count) test failure(s):" -ForegroundColor Red
    $Script:Failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}
Write-Host "All tests passed." -ForegroundColor Green
