param(
    [string]$Configuration = 'Release',
    [string]$QtDir = 'D:\Qt\6.7.3\msvc2022_64',
    [string]$BaselineExe = '',
    [switch]$Mutate,
    [switch]$AntiDisasm,
    [ValidateRange(1,15)][int]$Runs = 3
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Bin = Join-Path $Root "bin/$Configuration"
$Pevm = Join-Path $Bin 'PeVm.exe'
$Fixture = Join-Path $Bin 'LoaderQtFixture.exe'
$Work = Join-Path $Root ('out/qt-performance-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Work | Out-Null
$Previous = @{}
foreach ($Name in @('QT_QPA_PLATFORM','QT_QPA_PLATFORM_PLUGIN_PATH','PEVM_TEST_VM_BRIDGE_LOG','PEVM_TEST_NO_DIALOG')) {
    $Previous[$Name] = [Environment]::GetEnvironmentVariable($Name,'Process')
}
try {
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_QPA_PLATFORM_PLUGIN_PATH = Join-Path $QtDir 'plugins/platforms'
    $env:PEVM_TEST_VM_BRIDGE_LOG = $null
    $env:PEVM_TEST_NO_DIALOG = '1'
    $ScanPath = Join-Path $Work 'scan.json'
    & $Pevm scan-functions $Fixture $ScanPath *> (Join-Path $Work 'scan.log')
    if ($LASTEXITCODE -ne 0) { throw 'Qt fixture scan failed' }
    $Scan = Get-Content -LiteralPath $ScanPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $Targets = @($Scan.functions | Where-Object { $_.name -eq 'LoaderArithmetic' -or $_.aliases -contains 'LoaderArithmetic' })
    if ($Targets.Count -ne 1) { throw 'Expected exactly one LoaderArithmetic export' }
    $Protected = Join-Path $Bin 'LoaderQtFixture.performance.exe'
    $Protection = @('protect-function',$Fixture,$Protected,'qt-performance-key',$Targets[0].rva,'--compress')
    if ($Mutate) { $Protection += '--mutate' }
    if ($AntiDisasm) { $Protection += '--anti-disasm' }
    & $Pevm @Protection *> (Join-Path $Work 'protect.log')
    if ($LASTEXITCODE -ne 0) { throw 'Qt performance protection failed' }
    $Cases = @([pscustomobject]@{Name='native'; Path=$Fixture})
    if ($BaselineExe) { $Cases += [pscustomobject]@{Name='baseline'; Path=(Resolve-Path -LiteralPath $BaselineExe).Path} }
    $Cases += [pscustomobject]@{Name='current'; Path=$Protected}
    $Results = foreach ($Case in $Cases) {
        for ($Run=1; $Run -le $Runs; ++$Run) {
            $Log = Join-Path $Work "$($Case.Name)-$Run.out.log"
            $Proc = Start-Process -FilePath $Case.Path -ArgumentList '--benchmark' -WindowStyle Hidden -PassThru `
                -RedirectStandardOutput $Log -RedirectStandardError (Join-Path $Work "$($Case.Name)-$Run.err.log")
            $null = $Proc.Handle
            try {
                if (!$Proc.WaitForExit(30000)) { throw "$($Case.Name) benchmark timed out" }
                if ($Proc.ExitCode -ne 0) { throw "$($Case.Name) benchmark exited $($Proc.ExitCode)" }
                $Text = Get-Content -LiteralPath $Log -Raw
                if ($Text -notmatch 'PEVM_QT_BENCH median_ns=(\d+) max_ns=(\d+) calls=(\d+) checksum=(\d+)') {
                    throw "$($Case.Name) missing benchmark output"
                }
                $Median=[long]$Matches[1]; $Maximum=[long]$Matches[2]
                if ($Matches[3] -ne '62000' -or $Matches[4] -ne '62270568') { throw 'Qt benchmark result changed' }
                [pscustomobject]@{name=$Case.Name; run=$Run; median_ns=$Median; max_ns=$Maximum;
                    calls=62000; checksum=62270568; path=$Case.Path; sha256=(Get-FileHash -LiteralPath $Case.Path).Hash}
            } finally {
                if (!$Proc.HasExited) { Stop-Process -Id $Proc.Id }
                $Proc.Dispose()
            }
        }
    }
    $OutputPath = Join-Path $Work 'results.json'
    $Results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    $Results | Select-Object name,run,median_ns,max_ns,calls,checksum | Format-Table -AutoSize
    Write-Output "Results: $OutputPath"
    # Timings are observations, not pass/fail speed thresholds on a shared host.
} finally {
    foreach ($Name in $Previous.Keys) { [Environment]::SetEnvironmentVariable($Name,$Previous[$Name],'Process') }
}
