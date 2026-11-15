# Sourced by LicenseProtection.ps1 after the four licensed wrappers are built.
# This checks shipped symbol disclosure and per-build diversity; public build IDs
# and VM seeds are identifiers, not additional secret encryption keys.
function Assert-AnalysisRange([byte[]]$Bytes, [UInt64]$Offset, [UInt64]$Count) {
    if ($Offset -gt [UInt64]$Bytes.LongLength -or $Count -gt [UInt64]$Bytes.LongLength - $Offset) {
        throw 'analysis regression: truncated binary range'
    }
}

function Get-AnalysisPe([string]$Path) {
    [byte[]]$Bytes = [IO.File]::ReadAllBytes($Path)
    Assert-AnalysisRange $Bytes 0 64
    if ([BitConverter]::ToUInt16($Bytes, 0) -ne 0x5a4d) { throw 'analysis regression: DOS header missing' }
    $Nt = [BitConverter]::ToUInt32($Bytes, 0x3c)
    Assert-AnalysisRange $Bytes $Nt 24
    if ([BitConverter]::ToUInt32($Bytes, [int]$Nt) -ne 0x4550) { throw 'analysis regression: PE header missing' }
    $SectionCount = [BitConverter]::ToUInt16($Bytes, [int]$Nt + 6)
    $OptionalSize = [BitConverter]::ToUInt16($Bytes, [int]$Nt + 20)
    $Optional = [UInt64]$Nt + 24
    Assert-AnalysisRange $Bytes $Optional $OptionalSize
    if ($OptionalSize -lt 112 -or [BitConverter]::ToUInt16($Bytes, [int]$Optional) -ne 0x20b) {
        throw 'analysis regression: full PE32+ header required'
    }
    $DirectoryCount = [BitConverter]::ToUInt32($Bytes, [int]$Optional + 108)
    if ([UInt64]$DirectoryCount * 8 -gt $OptionalSize - 112) { throw 'analysis regression: directory table truncated' }
    $SectionTable = $Optional + $OptionalSize
    Assert-AnalysisRange $Bytes $SectionTable ([UInt64]$SectionCount * 40)
    return [pscustomobject]@{
        Bytes = $Bytes; Nt = [int]$Nt; Optional = [int]$Optional; SectionCount = $SectionCount
        SectionTable = [int]$SectionTable; DirectoryCount = $DirectoryCount
        HeadersSize = [BitConverter]::ToUInt32($Bytes, [int]$Optional + 60)
    }
}

function Get-AnalysisDirectory($Pe, [int]$Index) {
    if ($Index -ge $Pe.DirectoryCount) { return [pscustomobject]@{Rva = 0; Size = 0} }
    $At = $Pe.Optional + 112 + $Index * 8
    return [pscustomobject]@{
        Rva = [BitConverter]::ToUInt32($Pe.Bytes, $At)
        Size = [BitConverter]::ToUInt32($Pe.Bytes, $At + 4)
    }
}

function Resolve-AnalysisRva($Pe, [UInt64]$Rva, [UInt64]$Size) {
    if ($Rva -lt $Pe.HeadersSize -and $Size -le [UInt64]$Pe.HeadersSize - $Rva) {
        Assert-AnalysisRange $Pe.Bytes $Rva $Size
        return [int]$Rva
    }
    $Found = $null
    for ($I = 0; $I -lt $Pe.SectionCount; ++$I) {
        $At = $Pe.SectionTable + 40 * $I
        $Begin = [UInt64][BitConverter]::ToUInt32($Pe.Bytes, $At + 12)
        $RawSize = [UInt64][BitConverter]::ToUInt32($Pe.Bytes, $At + 16)
        if ($Rva -ge $Begin -and $Rva - $Begin -lt $RawSize -and $Size -le $RawSize - ($Rva - $Begin)) {
            if ($null -ne $Found) { throw 'analysis regression: overlapping RVA mappings' }
            $Found = [UInt64][BitConverter]::ToUInt32($Pe.Bytes, $At + 20) + ($Rva - $Begin)
            Assert-AnalysisRange $Pe.Bytes $Found $Size
        }
    }
    if ($null -eq $Found) { throw 'analysis regression: unmapped file RVA' }
    return [int]$Found
}

function Assert-AnalysisSymbols($Pe, $Carrier) {
    if ([BitConverter]::ToUInt32($Pe.Bytes, $Pe.Nt + 12) -ne 0 -or
        [BitConverter]::ToUInt32($Pe.Bytes, $Pe.Nt + 16) -ne 0) {
        throw 'COFF symbol pointer/count survived in shipped wrapper'
    }
    $Debug = Get-AnalysisDirectory $Pe 6
    if (($Debug.Rva -eq 0) -ne ($Debug.Size -eq 0) -or $Debug.Size % 28 -ne 0) {
        throw 'invalid shipped PE debug directory'
    }
    if ($Debug.Size -ne 0) {
        $DebugRaw = Resolve-AnalysisRva $Pe $Debug.Rva $Debug.Size
        for ($I = 0; $I -lt $Debug.Size; $I += 28) {
            $At = $DebugRaw + $I
            $Type = [BitConverter]::ToUInt32($Pe.Bytes, $At + 12)
            $Size = [BitConverter]::ToUInt32($Pe.Bytes, $At + 16)
            $Address = [BitConverter]::ToUInt32($Pe.Bytes, $At + 20)
            $Pointer = [BitConverter]::ToUInt32($Pe.Bytes, $At + 24)
            # Match StripDebugMetadata's explicit removable debug types.
            # Extended DLL characteristics (20), and unfamiliar records that may
            # carry loader requirements, remain legal and receive range checks.
            if ($Type -in @(1, 2, 3, 4, 7, 8, 12, 13, 17, 18, 19) -and ($Size -ne 0 -or $Address -ne 0 -or $Pointer -ne 0)) {
                throw "removable debug record type $Type survived in shipped wrapper"
            }
            if ($Size -ne 0) {
                if ($Pointer -ne 0) { Assert-AnalysisRange $Pe.Bytes $Pointer $Size }
                elseif ($Address -ne 0) { $null = Resolve-AnalysisRva $Pe $Address $Size }
                else { throw 'retained debug record has no data location' }
            }
        }
    }
    $Latin = [Text.Encoding]::GetEncoding(28591).GetString($Pe.Bytes)
    $WideName = [Text.Encoding]::GetEncoding(28591).GetString([Text.Encoding]::Unicode.GetBytes('PeVmStub.pdb'))
    if ($Latin.IndexOf('PeVmStub.pdb', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $Latin.IndexOf($WideName, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw 'carrier PDB filename/path remains searchable in shipped wrapper'
    }
    foreach ($Entry in @(@{Index = 1; Name = 'imports'}, @{Index = 3; Name = 'exceptions'},
                         @{Index = 5; Name = 'base relocations'}, @{Index = 9; Name = 'TLS'})) {
        $Before = Get-AnalysisDirectory $Carrier $Entry.Index
        $After = Get-AnalysisDirectory $Pe $Entry.Index
        if ($Before.Rva -ne $After.Rva -or $Before.Size -ne $After.Size) {
            throw "symbol cleanup changed carrier $($Entry.Name) directory"
        }
        if ($After.Size -ne 0) { $null = Resolve-AnalysisRva $Pe $After.Rva $After.Size }
    }
}

function Get-AnalysisDigest([byte[]]$Bytes, [UInt64]$Offset, [UInt64]$Count) {
    Assert-AnalysisRange $Bytes $Offset $Count
    $Hash = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($Hash.ComputeHash($Bytes, [int]$Offset, [int]$Count)) }
    finally { $Hash.Dispose() }
}

function Get-AnalysisVm($Pe) {
    $Footer = [UInt64]$Pe.Bytes.LongLength - 76
    Assert-AnalysisRange $Pe.Bytes $Footer 76
    if ([Text.Encoding]::ASCII.GetString($Pe.Bytes, [int]$Footer, 8) -cne 'PEVMRUN2') {
        throw 'analysis regression: wrapper footer missing'
    }
    $Metadata = [BitConverter]::ToUInt64($Pe.Bytes, [int]$Footer + 36)
    $MetadataSize = [BitConverter]::ToUInt32($Pe.Bytes, [int]$Footer + 44)
    if ($MetadataSize -ne 272) { throw 'analysis regression: metadata size changed' }
    Assert-AnalysisRange $Pe.Bytes $Metadata $MetadataSize
    if ([Text.Encoding]::ASCII.GetString($Pe.Bytes, [int]$Metadata, 8) -cne 'VMPMETA2') {
        throw 'analysis regression: metadata magic missing'
    }
    $VmAt = [BitConverter]::ToUInt32($Pe.Bytes, [int]$Metadata + 52)
    $VmSize = [BitConverter]::ToUInt32($Pe.Bytes, [int]$Metadata + 56)
    Assert-AnalysisRange $Pe.Bytes $VmAt $VmSize
    if ($VmSize -lt 64 -or [Text.Encoding]::ASCII.GetString($Pe.Bytes, [int]$VmAt, 7) -cne 'PEVMVM3') {
        throw 'analysis regression: VM program missing'
    }
    $Count = [BitConverter]::ToUInt32($Pe.Bytes, [int]$VmAt + 12)
    $Decoys = [BitConverter]::ToUInt32($Pe.Bytes, [int]$VmAt + 24)
    $TableStart = [UInt64]$VmAt + 32 + [UInt64]$Count * 16
    $NonTableBytes = [UInt64]64 + [UInt64]$Count * 16 + $Decoys
    if ($Count -eq 0 -or $NonTableBytes -ge $VmSize) { throw 'analysis regression: VM table size invalid' }
    $TableSize = [UInt64]$VmSize - $NonTableBytes
    if ($TableSize % 20 -ne 0) { throw 'analysis regression: VM instruction table misaligned' }
    return [pscustomobject]@{
        BuildId = [BitConverter]::ToUInt64($Pe.Bytes, [int]$Metadata + 12)
        Profile = Get-AnalysisDigest $Pe.Bytes ($Metadata + 68) 32
        Seed = [BitConverter]::ToUInt64($Pe.Bytes, [int]$VmAt + 16)
        Ciphertext = Get-AnalysisDigest $Pe.Bytes $TableStart $TableSize
    }
}

function ConvertTo-AnalysisArgument([string]$Value) {
    # Win32 argv escaping; quoting is not PowerShell source interpolation.
    $Escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    return '"' + [regex]::Replace($Escaped, '(\\+)$', '$1$1') + '"'
}

function Invoke-AnalysisProcess([string]$Exe, [string[]]$Arguments, [string]$LogName, [int]$Timeout = 30000) {
    $Start = @{
        FilePath = $Exe; PassThru = $true; WindowStyle = 'Hidden'; ErrorAction = 'Stop'
        RedirectStandardOutput = Join-Path $SecureWork ($LogName + '.out.log')
        RedirectStandardError = Join-Path $SecureWork ($LogName + '.err.log')
    }
    if ($Arguments.Count -ne 0) {
        $Start.ArgumentList = ($Arguments | ForEach-Object { ConvertTo-AnalysisArgument $_ }) -join ' '
    }
    $Process = Start-Process @Start
    try {
        $null = $Process.Handle
        if (-not $Process.WaitForExit($Timeout)) {
            $Process.Kill()
            $null = $Process.WaitForExit(5000)
            throw "analysis regression process timed out: $LogName"
        }
        return $Process.ExitCode
    } finally { $Process.Dispose() }
}

function Test-AnalysisRuntimeTamper([string]$Source) {
    if (-not ('PeVmTests.AnalysisMemoryNative' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace PeVmTests {
    public static class AnalysisMemoryNative {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [Out] byte[] buffer,
                                                     UIntPtr size, out UIntPtr read);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(IntPtr process, IntPtr address, byte[] buffer,
                                                      UIntPtr size, out UIntPtr written);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx(IntPtr process, IntPtr address, UIntPtr size,
                                                    uint protection, out uint oldProtection);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushInstructionCache(IntPtr process, IntPtr address, UIntPtr size);
    }
}
'@
    }
    $Pe = Get-AnalysisPe $Source
    $TailRva = $null
    for ($I = 0; $I -lt $Pe.SectionCount; ++$I) {
        $At = $Pe.SectionTable + 40 * $I
        $Name = [Text.Encoding]::ASCII.GetString($Pe.Bytes, $At, 8).Trim([char]0)
        if ($Name -cne '.vmp0') { continue }
        $VirtualSize = [BitConverter]::ToUInt32($Pe.Bytes, $At + 8)
        $Rva = [BitConverter]::ToUInt32($Pe.Bytes, $At + 12)
        $RawSize = [BitConverter]::ToUInt32($Pe.Bytes, $At + 16)
        $RawAt = [BitConverter]::ToUInt32($Pe.Bytes, $At + 20)
        $Flags = [BitConverter]::ToUInt32($Pe.Bytes, $At + 36)
        if ($RawSize -le $VirtualSize -or ($Flags -band 0x20000000) -eq 0) {
            throw 'runtime tamper fixture has no unused executable tail padding'
        }
        Assert-AnalysisRange $Pe.Bytes $RawAt $RawSize
        if ($Pe.Bytes[[int]([UInt64]$RawAt + $RawSize - 1)] -ne 0) {
            throw 'runtime tamper fixture tail padding is not zero on disk'
        }
        $TailRva = [UInt64]$Rva + $RawSize - 1
        for ($J = 0; $J -lt $Pe.SectionCount; ++$J) {
            if ($J -eq $I) { continue }
            $Other = $Pe.SectionTable + 40 * $J
            $OtherRva = [UInt64][BitConverter]::ToUInt32($Pe.Bytes, $Other + 12)
            $OtherSize = [UInt64][Math]::Max([BitConverter]::ToUInt32($Pe.Bytes, $Other + 8),
                                           [BitConverter]::ToUInt32($Pe.Bytes, $Other + 16))
            if ($TailRva -ge $OtherRva -and $TailRva - $OtherRva -lt $OtherSize) {
                throw 'runtime tamper padding overlaps another mapped section'
            }
        }
        break
    }
    if ($null -eq $TailRva) { throw 'runtime tamper fixture .vmp0 section missing' }
    $Tag = 'analysis-live-tamper-' + [Guid]::NewGuid().ToString('N')
    $Output = Join-Path $SecureWork ($Tag + '.exe')
    [IO.File]::Copy($Source, $Output, $false)
    $Saved = @{}
    foreach ($Name in @('PEVM_TEST_HOLD', 'PEVM_TEST_VM_BRIDGE_LOG', 'PEVM_TEST_ERROR_LOG', 'PEVM_ALLOW_DEBUGGER')) {
        $Saved[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
    }
    $Process = $null
    $Handle = [IntPtr]::Zero
    try {
        $env:PEVM_TEST_HOLD = '1'
        $env:PEVM_TEST_VM_BRIDGE_LOG = '1'
        $env:PEVM_TEST_ERROR_LOG = '1'
        [Environment]::SetEnvironmentVariable('PEVM_ALLOW_DEBUGGER', $null, 'Process')
        $Process = Start-Process -FilePath $Output -PassThru -WindowStyle Hidden -ErrorAction Stop `
            -RedirectStandardOutput (Join-Path $SecureWork ($Tag + '.out.log')) `
            -RedirectStandardError (Join-Path $SecureWork ($Tag + '.err.log'))
        $null = $Process.Handle
        $Marker = $Output + '.vmbridge-hit'
        $Startup = [Diagnostics.Stopwatch]::StartNew()
        while (-not (Test-Path -LiteralPath $Marker)) {
            if ($Process.HasExited) { throw 'runtime tamper fixture exited before watchdog readiness marker' }
            if ($Startup.ElapsedMilliseconds -ge 15000) { throw 'runtime tamper watchdog readiness timed out' }
            Start-Sleep -Milliseconds 25
        }
        if ((Get-Item -LiteralPath $Marker).Length -ne 0) { throw 'payload executed before runtime tamper test' }
        $Process.Refresh()
        $Address = [IntPtr]::new($Process.MainModule.BaseAddress.ToInt64() + [long]$TailRva)
        # This is our own ordinary child process; no debugger attachment or
        # production test hook establishes the integrity violation.
        $Handle = [PeVmTests.AnalysisMemoryNative]::OpenProcess(0x0438, $false, [uint32]$Process.Id)
        if ($Handle -eq [IntPtr]::Zero) { throw 'runtime tamper could not open its child process' }
        $One = [UIntPtr]::new(1)
        [byte[]]$Byte = @(0xff)
        $Transferred = [UIntPtr]::Zero
        if (-not [PeVmTests.AnalysisMemoryNative]::ReadProcessMemory($Handle, $Address, $Byte, $One, [ref]$Transferred) -or
            $Transferred.ToUInt64() -ne 1 -or $Byte[0] -ne 0) {
            throw 'runtime tamper target was not the expected zero padding in memory'
        }
        [uint32]$OldProtection = 0
        if (-not [PeVmTests.AnalysisMemoryNative]::VirtualProtectEx($Handle, $Address, $One, 0x40, [ref]$OldProtection)) {
            throw 'runtime tamper could not make its padding byte writable'
        }
        try {
            if (($OldProtection -band 0xff) -ne 0x20) { throw 'runtime tamper original code protection was not RX' }
            [byte[]]$Changed = @(0x5a)
            $Transferred = [UIntPtr]::Zero
            if (-not [PeVmTests.AnalysisMemoryNative]::WriteProcessMemory($Handle, $Address, $Changed, $One, [ref]$Transferred) -or
                $Transferred.ToUInt64() -ne 1) { throw 'runtime tamper byte write failed' }
        } finally {
            [uint32]$IgnoredProtection = 0
            if (-not [PeVmTests.AnalysisMemoryNative]::VirtualProtectEx($Handle, $Address, $One,
                                                                      $OldProtection, [ref]$IgnoredProtection)) {
                throw 'runtime tamper failed to restore the original RX protection'
            }
        }
        if (-not [PeVmTests.AnalysisMemoryNative]::FlushInstructionCache($Handle, $Address, $One)) {
            throw 'runtime tamper could not flush the changed code page'
        }
        # Read only after restoring RX, proving that the child survived the short
        # writable interval and retained a changed byte at its normal protection.
        $Transferred = [UIntPtr]::Zero
        if (-not [PeVmTests.AnalysisMemoryNative]::ReadProcessMemory($Handle, $Address, $Byte, $One, [ref]$Transferred) -or
            $Transferred.ToUInt64() -ne 1 -or $Byte[0] -ne 0x5a) {
            throw 'runtime tamper was not observable after RX protection was restored'
        }
        if (-not $Process.WaitForExit(8000)) { throw 'runtime watchdog missed RX-restored byte tamper within eight seconds' }
        if ($Process.ExitCode -eq 0) { throw 'runtime byte tamper child exited successfully' }
        if ((Get-Item -LiteralPath $Marker).Length -ne 0) { throw 'runtime byte tamper reached protected payload execution' }
        $ErrorLog = $Output + '.loader-error.txt'
        if (Test-Path -LiteralPath $ErrorLog) {
            $Reason = Get-Content -LiteralPath $ErrorLog -Raw
            if ($Reason -notmatch 'runtime|integrity|executable|tamper') { throw "unexpected runtime tamper failure: $Reason" }
        }
        Ok 'live watchdog rejects changed runtime bytes after RX restoration, before the 20-second hold ends'
    } finally {
        try {
            if ($Handle -ne [IntPtr]::Zero) { $null = [PeVmTests.AnalysisMemoryNative]::CloseHandle($Handle) }
            if ($null -ne $Process) {
                try {
                    if (-not $Process.HasExited) { $Process.Kill(); $null = $Process.WaitForExit(5000) }
                } finally { $Process.Dispose() }
            }
        } finally {
            foreach ($Name in $Saved.Keys) { [Environment]::SetEnvironmentVariable($Name, $Saved[$Name], 'Process') }
        }
    }
}

$AnalysisLicense = [Environment]::GetEnvironmentVariable('PEVM_LICENSE', 'Process')
$AnalysisNoDialog = [Environment]::GetEnvironmentVariable('PEVM_TEST_NO_DIALOG', 'Process')
try {
    $env:PEVM_LICENSE = $SecureToken
    $env:PEVM_TEST_NO_DIALOG = '1'
    $Carrier = Get-AnalysisPe (Join-Path (Split-Path -Parent $Pevm) 'PeVmStub.exe')
    foreach ($Command in @('wrap', 'protect-function', 'protect-functions', 'protect-all')) {
        try {
            $Path = Join-Path $SecureWork ($Command + '.exe')
            Assert-AnalysisSymbols (Get-AnalysisPe $Path) $Carrier
            if ((Invoke-AnalysisProcess $Path @() ('analysis-' + $Command)) -ne 0) {
                throw 'valid card did not execute symbol-stripped wrapper'
            }
            Ok "$Command removes carrier symbols and preserves loader directories/execution"
        } catch { Fail "$Command analysis resistance: $($_.Exception.Message)" }
    }
    $Repeats = @()
    foreach ($Index in 0..1) {
        try {
            $Output = Join-Path $SecureWork ("analysis-repeat-$Index.exe")
            $Arguments = @('protect-function', $Fixture, $Output, 'analysis-repeat-build-password', $SecureRva) + $SecureOptions
            if ((Invoke-AnalysisProcess $Pevm $Arguments ("analysis-repeat-$Index-build") 60000) -ne 0) {
                throw 'default-option repeat build failed'
            }
            $Pe = Get-AnalysisPe $Output
            Assert-AnalysisSymbols $Pe $Carrier
            $Repeats += Get-AnalysisVm $Pe
            if ((Invoke-AnalysisProcess $Output @() ("analysis-repeat-$Index-run")) -ne 0) {
                throw 'randomized repeat build failed with valid card'
            }
            Ok "default-option randomized build $Index executes with valid card"
        } catch { Fail "analysis repeat $Index`: $($_.Exception.Message)" }
    }
    if ($Repeats.Count -ne 2) { Fail 'analysis resistance could not compare both repeat builds' }
    else {
        foreach ($Field in @('BuildId', 'Profile', 'Seed', 'Ciphertext')) {
            if ($Repeats[0].$Field -eq $Repeats[1].$Field) { Fail "default-option builds reused $Field" }
            else { Ok "default-option builds vary $Field" }
        }
    }
    try { Test-AnalysisRuntimeTamper $SecureOutput }
    catch { Fail "live runtime code guard: $($_.Exception.Message)" }
    . (Join-Path $PSScriptRoot 'AnalysisToolDetection.ps1')
} finally {
    [Environment]::SetEnvironmentVariable('PEVM_LICENSE', $AnalysisLicense, 'Process')
    [Environment]::SetEnvironmentVariable('PEVM_TEST_NO_DIALOG', $AnalysisNoDialog, 'Process')
}
