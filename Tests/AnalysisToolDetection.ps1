# Sourced by AnalysisResistance.ps1. All tool names/windows below belong to
# disposable fixtures created by this test. Run these cases serially: the
# temporary analysis windows intentionally affect every protected wrapper.
function Stop-AnalysisOwnedProcess($Process) {
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) { $Process.Kill(); $null = $Process.WaitForExit(5000) }
    } finally { $Process.Dispose() }
}

function Start-AnalysisToolFixture([string]$Exe, [string[]]$Arguments, [string]$Ready, [string]$Tag,
                                   [switch]$NoReadyWait) {
    $Quoted = ($Arguments | ForEach-Object { ConvertTo-AnalysisArgument $_ }) -join ' '
    $Process = Start-Process -FilePath $Exe -ArgumentList $Quoted -PassThru -WindowStyle Hidden -ErrorAction Stop `
        -RedirectStandardOutput (Join-Path $SecureWork ($Tag + '-tool.out.log')) `
        -RedirectStandardError (Join-Path $SecureWork ($Tag + '-tool.err.log'))
    try {
        $null = $Process.Handle
        if ($NoReadyWait) { return $Process }
        $Timer = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $Ready)) {
            if ($Process.HasExited) {
                $Detail = if (Test-Path -LiteralPath ($Ready + '.error')) { Get-Content -LiteralPath ($Ready + '.error') -Raw } else { '' }
                throw "analysis tool fixture exited before readiness: $Detail"
            }
            if ($Timer.ElapsedMilliseconds -ge 10000) { throw 'analysis tool fixture readiness timed out' }
            Start-Sleep -Milliseconds 25
        }
        if ($Process.HasExited) { throw 'analysis tool fixture was not resident after readiness' }
        return $Process
    } catch {
        Stop-AnalysisOwnedProcess $Process
        throw
    }
}

function Invoke-AnalysisToolStartupCase($Case, [string]$Template, [string]$Directory) {
    # The native bridge log uses CRT file I/O. Keep nested fixture paths well
    # below MAX_PATH, including the appended .vmbridge-hit suffix.
    $Tag = 'tool-' + $Case.Label + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 16)
    $CaseWork = Join-Path $Directory $Tag
    New-Item -ItemType Directory -Path $CaseWork -ErrorAction Stop | Out-Null
    $ToolPath = Join-Path $CaseWork $Case.Name
    $Wrapper = Join-Path $CaseWork 'protected.exe'
    [IO.File]::Copy($Template, $ToolPath, $false)
    [IO.File]::Copy($SecureOutput, $Wrapper, $false)
    $Ready = Join-Path $CaseWork 'tool.ready'
    $Arguments = if ($Case.Mode -eq 'process') { @('process', $Ready) } else { @('window', $Case.Class, $Case.Title, $Ready) }
    $Tool = $null
    try {
        $Tool = Start-AnalysisToolFixture $ToolPath $Arguments $Ready $Tag
        $Code = Invoke-AnalysisProcess $Wrapper @() ($Tag + '-wrapper')
        $Marker = $Wrapper + '.vmbridge-hit'
        if ($Case.Reject) {
            if ($Code -eq 0) { throw 'analysis fixture was accepted at startup' }
            if (Test-Path -LiteralPath $Marker) { throw 'startup analysis rejection occurred after VM setup/execution' }
            Ok "$($Case.Label): known analysis process/window rejected before VM setup"
        } else {
            if ($Code -ne 0) { throw 'ordinary browser/document window incorrectly rejected' }
            if (-not (Test-Path -LiteralPath $Marker) -or (Get-Item -LiteralPath $Marker).Length -eq 0) {
                throw 'negative analysis case did not execute the protected fixture'
            }
            Ok "$($Case.Label): ordinary browser/document title is allowed and payload executes"
        }
    } finally { Stop-AnalysisOwnedProcess $Tool }
}

function Test-AnalysisToolRuntime([string]$Template, [string]$Directory, [string]$WindowClass = '') {
    $Tag = 'tool-runtime-' + [Guid]::NewGuid().ToString('N').Substring(0, 16)
    $CaseWork = Join-Path $Directory $Tag
    New-Item -ItemType Directory -Path $CaseWork -ErrorAction Stop | Out-Null
    $Wrapper = Join-Path $CaseWork 'protected.exe'
    $ToolName = if ($WindowClass) { 'ordinary-host.exe' } else { 'reclass.exe' }
    $ToolPath = Join-Path $CaseWork $ToolName
    [IO.File]::Copy($SecureOutput, $Wrapper, $false)
    [IO.File]::Copy($Template, $ToolPath, $false)
    $Ready = Join-Path $CaseWork 'tool.ready'
    $Held = [Environment]::GetEnvironmentVariable('PEVM_TEST_HOLD', 'Process')
    $Process = $null
    $Tool = $null
    try {
        $env:PEVM_TEST_HOLD = '1'
        $Process = Start-Process -FilePath $Wrapper -PassThru -WindowStyle Hidden -ErrorAction Stop `
            -RedirectStandardOutput (Join-Path $SecureWork ($Tag + '-wrapper.out.log')) `
            -RedirectStandardError (Join-Path $SecureWork ($Tag + '-wrapper.err.log'))
        $null = $Process.Handle
        $Marker = $Wrapper + '.vmbridge-hit'
        $Timer = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $Marker)) {
            if ($Process.HasExited) { throw 'runtime tool fixture wrapper exited before watchdog readiness' }
            if ($Timer.ElapsedMilliseconds -ge 15000) { throw 'runtime tool fixture wrapper readiness timed out' }
            Start-Sleep -Milliseconds 25
        }
        if ((Get-Item -LiteralPath $Marker).Length -ne 0 -or $Process.HasExited) {
            throw 'runtime tool fixture wrapper did not reach the pre-entry hold'
        }
        # The process appears only after the wrapper watchdog has started. The
        # production two-second inventory schedule must catch it during the hold.
        if ($WindowClass) {
            $Tool = Start-AnalysisToolFixture $ToolPath @('window', $WindowClass, 'IDA - fixture.exe', $Ready) $Ready $Tag
            $Detection = [Diagnostics.Stopwatch]::StartNew()
        } else {
            $Detection = [Diagnostics.Stopwatch]::StartNew()
            $Tool = Start-AnalysisToolFixture $ToolPath @('process', $Ready) $Ready $Tag -NoReadyWait
        }
        if (-not $Process.WaitForExit(5000)) { throw 'periodic tool detection missed a late analysis process/window' }
        $Detection.Stop()
        if ($Process.ExitCode -eq 0) { throw 'runtime analysis process was accepted' }
        if ((Get-Item -LiteralPath $Marker).Length -ne 0) { throw 'runtime analysis process reached payload execution' }
        if ($Detection.ElapsedMilliseconds -ge 6000) { throw 'runtime rejection exceeded the inventory schedule tolerance' }
        # Confirm the created process did stay resident, independently of the
        # detection deadline; CLR startup time cannot lengthen that deadline.
        $ReadyTimer = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $Ready)) {
            if ($Tool.HasExited) { throw 'late analysis process exited before establishing its resident fixture' }
            if ($ReadyTimer.ElapsedMilliseconds -ge 10000) { throw 'late analysis resident fixture readiness timed out' }
            Start-Sleep -Milliseconds 25
        }
        if ($Tool.HasExited) { throw 'late analysis fixture was not resident after wrapper rejection' }
        $Identity = if ($WindowClass) { 'renamed Qt analysis window' } else { 'analysis process' }
        Ok "late $Identity is caught by periodic inventory before the held payload entry ($($Detection.ElapsedMilliseconds) ms)"
    } finally {
        try { Stop-AnalysisOwnedProcess $Tool }
        finally {
            try { Stop-AnalysisOwnedProcess $Process }
            finally { [Environment]::SetEnvironmentVariable('PEVM_TEST_HOLD', $Held, 'Process') }
        }
    }
}

$AnalysisToolDirectory = Join-Path $SecureWork ('tool-fixtures-' + [Guid]::NewGuid().ToString('N').Substring(0, 16))
New-Item -ItemType Directory -Path $AnalysisToolDirectory -ErrorAction Stop | Out-Null
$AnalysisToolTemplate = Join-Path $AnalysisToolDirectory 'fixture.exe'
$AnalysisToolSource = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
namespace PeVmAnalysisToolFixture {
    internal static class Program {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr WindowProcedure(IntPtr window, uint message, UIntPtr wparam, IntPtr lparam);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WindowClass {
            public uint Size, Style;
            public WindowProcedure Procedure;
            public int ClassExtra, WindowExtra;
            public IntPtr Instance, Icon, Cursor, Background;
            public string MenuName, ClassName;
            public IntPtr SmallIcon;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct Message {
            public IntPtr Window;
            public uint Id;
            public UIntPtr WParam;
            public IntPtr LParam;
            public uint Time;
            public int X, Y;
            public uint Private;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string name);
        [DllImport("user32.dll", EntryPoint = "RegisterClassExW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern ushort RegisterClassEx(ref WindowClass value);
        [DllImport("user32.dll", EntryPoint = "CreateWindowExW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowEx(uint extended, string className, string title, uint style,
            int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr parameter);
        [DllImport("user32.dll", EntryPoint = "DefWindowProcW", ExactSpelling = true)]
        private static extern IntPtr DefWindowProc(IntPtr window, uint message, UIntPtr wparam, IntPtr lparam);
        [DllImport("user32.dll", EntryPoint = "GetMessageW", ExactSpelling = true, SetLastError = true)]
        private static extern int GetMessage(out Message message, IntPtr window, uint first, uint last);
        [DllImport("user32.dll")]
        private static extern bool TranslateMessage(ref Message message);
        [DllImport("user32.dll", EntryPoint = "DispatchMessageW", ExactSpelling = true)]
        private static extern IntPtr DispatchMessage(ref Message message);
        private static readonly WindowProcedure Procedure = DefWindowProc;

        [STAThread]
        private static int Main(string[] args) {
            string ready = args.Length == 0 ? null : args[args.Length - 1];
            try {
                if (args.Length == 2 && args[0] == "process") {
                    File.WriteAllText(ready, "resident process");
                    Thread.Sleep(60000);
                    return 0;
                }
                if (args.Length != 4 || args[0] != "window") return 2;
                IntPtr instance = GetModuleHandle(null);
                WindowClass type = new WindowClass();
                type.Size = (uint)Marshal.SizeOf(typeof(WindowClass));
                type.Procedure = Procedure;
                type.Instance = instance;
                type.ClassName = args[1];
                if (RegisterClassEx(ref type) == 0) throw new System.ComponentModel.Win32Exception();
                // A hidden top-level window is sufficient for EnumWindows/FindWindow.
                // No clipboard access, Qt runtime, debugger API or input simulation.
                IntPtr window = CreateWindowEx(0, args[1], args[2], 0x00cf0000, 0, 0, 640, 360,
                                               IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);
                if (window == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
                File.WriteAllText(ready, window.ToInt64().ToString());
                Message message;
                for (;;) {
                    int result = GetMessage(out message, IntPtr.Zero, 0, 0);
                    if (result < 0) throw new System.ComponentModel.Win32Exception();
                    if (result == 0) return 0;
                    TranslateMessage(ref message);
                    DispatchMessage(ref message);
                }
            } catch (Exception error) {
                if (ready != null) File.WriteAllText(ready + ".error", error.ToString());
                return 3;
            }
        }
    }
}
'@
# Keep compiler-generated fixture names unique even if this script is sourced
# again in the same Windows PowerShell process.
$AnalysisToolSource = $AnalysisToolSource.Replace('PeVmAnalysisToolFixture',
    'PeVmAnalysisToolFixture' + [Guid]::NewGuid().ToString('N'))
Add-Type -TypeDefinition $AnalysisToolSource -OutputAssembly $AnalysisToolTemplate -OutputType WindowsApplication -ErrorAction Stop

$AnalysisToolEnvironment = @{}
foreach ($Name in @('PEVM_LICENSE', 'PEVM_TEST_NO_DIALOG', 'PEVM_TEST_HOLD', 'PEVM_TEST_VM_BRIDGE_LOG',
                    'PEVM_TEST_ERROR_LOG', 'PEVM_ALLOW_DEBUGGER')) {
    $AnalysisToolEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
}
try {
    $env:PEVM_LICENSE = $SecureToken
    $env:PEVM_TEST_NO_DIALOG = '1'
    $env:PEVM_TEST_VM_BRIDGE_LOG = '1'
    $env:PEVM_TEST_ERROR_LOG = '1'
    [Environment]::SetEnvironmentVariable('PEVM_TEST_HOLD', $null, 'Process')
    [Environment]::SetEnvironmentVariable('PEVM_ALLOW_DEBUGGER', $null, 'Process')
    foreach ($Case in @(
        @{Label = 'startup-exact-process'; Name = 'reclass.exe'; Mode = 'process'; Reject = $true},
        @{Label = 'renamed-strong-window'; Name = 'ordinary-host.exe'; Mode = 'window'; Class = 'x64dbgClass'; Title = 'fixture'; Reject = $true},
        @{Label = 'renamed-qt-brand'; Name = 'ordinary-host.exe'; Mode = 'window'; Class = 'Qt5QWindowIcon'; Title = 'IDA - fixture.exe'; Reject = $true},
        @{Label = 'browser-document-negative'; Name = 'ordinary-host.exe'; Mode = 'window'; Class = 'Chrome_WidgetWin_1'; Title = 'IDA and Ghidra documentation - Browser'; Reject = $false}
    )) {
        try { Invoke-AnalysisToolStartupCase $Case $AnalysisToolTemplate $AnalysisToolDirectory }
        catch { Fail "$($Case.Label): $($_.Exception.Message)" }
    }
    try { Test-AnalysisToolRuntime $AnalysisToolTemplate $AnalysisToolDirectory }
    catch { Fail "periodic analysis process detection: $($_.Exception.Message)" }
    try { Test-AnalysisToolRuntime $AnalysisToolTemplate $AnalysisToolDirectory 'Qt5152QWindowIcon' }
    catch { Fail "periodic analysis window detection: $($_.Exception.Message)" }
} finally {
    foreach ($Name in $AnalysisToolEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($Name, $AnalysisToolEnvironment[$Name], 'Process')
    }
}
