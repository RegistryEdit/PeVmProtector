param(
    [Parameter(Mandatory=$true)][string[]]$Executables,
    [ValidateRange(10,1000)][int]$Samples = 200,
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'out/window-response.json')
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PeVmWindowProbe {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(IntPtr window, uint message,
        UIntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);
}
'@
$PreviousBridge = $env:PEVM_TEST_VM_BRIDGE_LOG
$PreviousDialog = $env:PEVM_TEST_NO_DIALOG
try {
    $env:PEVM_TEST_VM_BRIDGE_LOG = $null
    $env:PEVM_TEST_NO_DIALOG = '1'
    $Results = foreach ($Exe in $Executables) {
        $Path = (Resolve-Path -LiteralPath $Exe).Path
        $Watch = [Diagnostics.Stopwatch]::StartNew()
        $Proc = Start-Process -FilePath $Path -PassThru -WindowStyle Hidden
        $null = $Proc.Handle
        try {
            do {
                $Proc.Refresh()
                if ($Proc.HasExited) { throw "$Path exited before window creation: $($Proc.ExitCode)" }
                if ($Watch.ElapsedMilliseconds -gt 30000) { throw "$Path did not create a window" }
                Start-Sleep -Milliseconds 50
            } while ($Proc.MainWindowHandle -eq [IntPtr]::Zero -or [string]::IsNullOrWhiteSpace($Proc.MainWindowTitle))
            $Startup = $Watch.Elapsed.TotalMilliseconds
            $Handle = $Proc.MainWindowHandle
            $Title = $Proc.MainWindowTitle
            $BeforeCpu = $Proc.TotalProcessorTime.TotalMilliseconds
            $Latencies = @()
            $Timeouts = 0
            for ($I=0; $I -lt $Samples; ++$I) {
                [UIntPtr]$Value=[UIntPtr]::Zero
                $Tick = [Diagnostics.Stopwatch]::StartNew()
                # WM_NULL measures the real GUI thread without sending user input.
                $Result = [PeVmWindowProbe]::SendMessageTimeout($Handle,0,[UIntPtr]::Zero,[IntPtr]::Zero,2,250,[ref]$Value)
                $Latencies += $Tick.Elapsed.TotalMilliseconds
                if ($Result -eq [IntPtr]::Zero) {
                    $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($ErrorCode -ne 0 -and $ErrorCode -ne 1460) {
                        throw "Window probe failed with Win32 error $ErrorCode for $Path"
                    }
                    ++$Timeouts
                }
                Start-Sleep -Milliseconds 15
                $Proc.Refresh()
                if ($Proc.HasExited) { throw "$Path exited while sampling: $($Proc.ExitCode)" }
            }
            $Sorted = @($Latencies | Sort-Object)
            [pscustomobject]@{path=$Path; sha256=(Get-FileHash -LiteralPath $Path).Hash; title=$Title;
                startup_ms=$Startup; samples=$Samples; timeout_ms=250; timeouts=$Timeouts;
                median_ms=$Sorted[[int][math]::Floor($Samples/2)]; p95_ms=$Sorted[[int][math]::Ceiling($Samples*0.95)-1];
                max_ms=$Sorted[-1]; cpu_ms=($Proc.TotalProcessorTime.TotalMilliseconds-$BeforeCpu);
                scope='Login/startup GUI thread WM_NULL; no post-login input or business actions'}
        } finally {
            if (!$Proc.HasExited) {
                $null=$Proc.CloseMainWindow()
                if (!$Proc.WaitForExit(3000)) { Stop-Process -Id $Proc.Id }
            }
            $Proc.Dispose()
        }
    }
    $Results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    $Results | Select-Object path,startup_ms,median_ms,p95_ms,max_ms,timeouts,cpu_ms | Format-List
    Write-Output "Results: $OutputPath"
    if (@($Results | Where-Object timeouts -gt 0).Count) { throw 'GUI response timeouts observed; inspect results' }
} finally {
    $env:PEVM_TEST_VM_BRIDGE_LOG = $PreviousBridge
    $env:PEVM_TEST_NO_DIALOG = $PreviousDialog
}
