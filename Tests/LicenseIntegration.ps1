# Invoked by RunTests.ps1 with its paths and assertion helpers.
$LicenseWork = Join-Path $Work ("licenses-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $LicenseWork | Out-Null
$Private = Join-Path $LicenseWork 'issuer.private'
$Public = Join-Path $LicenseWork 'issuer.pub'
$LicenseFile = Join-Path $LicenseWork 'customer.license'
$Output = Join-Path $LicenseWork 'LifterFixture.licensed.exe'
$Product = 'pevm.regression'
$LicensePrefix = 'PEVM-LICENSE.'
$PublicPrefix = 'PEVM-PUBLIC.'
$PrivatePrefix = 'PEVM-PRIVATE.'
$MachineOutput = & $Pevm license-machine-id 2>&1
if ($LASTEXITCODE -ne 0 -or ($MachineOutput -join "`n") -notmatch '^machine id: ([0-9a-fA-F]{64})$') {
    throw 'license-machine-id did not produce a 64-digit machine id'
}
$Machine = $Matches[1]
& $Pevm license-keygen $Private $Public *> (Join-Path $LicenseWork 'keygen.log')
if ($LASTEXITCODE -ne 0) { throw 'license-keygen failed (requires Windows user DPAPI access)' }
& $Pevm license-issue $Private 30 "--machine=$Machine" "--product=$Product" "--output=$LicenseFile" *> (Join-Path $LicenseWork 'issue.log')
if ($LASTEXITCODE -ne 0) { throw 'license-issue failed' }
$LicenseKey = (Get-Content $LicenseFile -Raw).Trim()
if (-not $LicenseKey.StartsWith($LicensePrefix)) { throw 'license-issue did not produce a signed license' }
& $Pevm license-verify $Public $LicenseFile "--product=$Product" "--machine=$Machine" *> (Join-Path $LicenseWork 'verify.log')
if ($LASTEXITCODE -ne 0) { throw 'license-verify rejected issued license' }
Ok 'CLI key generation, issuance and verification'
$RecoveredPublic = Join-Path $LicenseWork 'recovered.pub'
& $Pevm license-export-public $Private $RecoveredPublic *> (Join-Path $LicenseWork 'export-public.log')
if ($LASTEXITCODE -ne 0 -or (Get-Content $RecoveredPublic -Raw) -ne (Get-Content $Public -Raw)) {
    throw 'license-export-public did not recover the same public key'
}

$Rva = if ((Get-FixtureText) -match 'PEVM-FIXTURE-RVA LiftTarget=0x([0-9A-Fa-f]+)') { '0x' + $Matches[1] } else { throw 'no LiftTarget RVA' }
$LicenseOptions = @('--license', "--license-public-key=$Public", "--license-product=$Product")
& $Pevm protect-function $Fixture $Output build-key $Rva @LicenseOptions *> (Join-Path $LicenseWork 'build.log')
if ($LASTEXITCODE -ne 0) { throw 'licensed protect-function failed' }
$BuildTranscript = Get-Content (Join-Path $LicenseWork 'build.log') -Raw
if ($BuildTranscript -notmatch 'license: required; ECDSA P-256' -or
    $BuildTranscript -notmatch 'license public key fingerprint:' -or
    $BuildTranscript -notmatch 'license product digest:') { Fail 'licensed build omitted public policy details' }
if ($BuildTranscript.Contains($LicenseKey) -or $BuildTranscript -match 'PEVM-PRIVATE\.') { Fail 'licensed build exposed card/private key material' }
& $Pevm inspect $Output *> (Join-Path $LicenseWork 'inspect.log')
if ($LASTEXITCODE -ne 0 -or (Get-Content (Join-Path $LicenseWork 'inspect.log') -Raw) -notmatch 'ECDSA P-256') {
    Fail 'inspect did not recognize signed license policy'
}

# Inspect the real wrapper; the private scalar must never be embedded.
$WrapperBytes = [IO.File]::ReadAllBytes($Output)
$MetadataOffset = [int][BitConverter]::ToUInt64($WrapperBytes, $WrapperBytes.Length - 76 + 36)
$MetadataSize = [BitConverter]::ToUInt32($WrapperBytes, $WrapperBytes.Length - 76 + 44)
if ($MetadataSize -ne 272 -or [BitConverter]::ToUInt32($WrapperBytes, $MetadataOffset + 8) -ne 5) {
    throw 'wrapper metadata version/size mismatch'
}
$PublicText = (Get-Content $Public -Raw).Trim()
if (-not $PublicText.StartsWith($PublicPrefix)) { throw 'unexpected public key prefix' }
$PublicBytes = [Convert]::FromBase64String($PublicText.Substring($PublicPrefix.Length))
$EmbeddedPublic = $WrapperBytes[($MetadataOffset + 168)..($MetadataOffset + 239)]
if ([BitConverter]::ToString($PublicBytes) -ne [BitConverter]::ToString($EmbeddedPublic)) { Fail 'public key not embedded correctly' }
Add-Type -AssemblyName System.Security
$PrivateText = (Get-Content $Private -Raw).Trim()
if (-not $PrivateText.StartsWith($PrivatePrefix)) { throw 'unexpected private key prefix' }
$ProtectedPrivate = [Convert]::FromBase64String($PrivateText.Substring($PrivatePrefix.Length))
$PrivateBytes = [Security.Cryptography.ProtectedData]::Unprotect($ProtectedPrivate, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
try {
    $PrivateScalar = $PrivateBytes[72..103]
    if ([BitConverter]::ToString($WrapperBytes).Contains([BitConverter]::ToString($PrivateScalar))) { Fail 'private signing scalar leaked into wrapper' }
    else { Ok 'wrapper contains public verification key and no private scalar' }
} finally {
    [Array]::Clear($PrivateBytes, 0, $PrivateBytes.Length)
    if ($PrivateScalar) { [Array]::Clear($PrivateScalar, 0, $PrivateScalar.Length) }
}

# Invalid CLI configuration must fail before producing an executable.
$NegativeOptions = @(
    @('--license'),
    @('--license', "--license-public-key=$Public"),
    @('--license', "--license-product=$Product"),
    @("--license-public-key=$Public", "--license-product=$Product"),
    @('--license', '--license-secret=removed'),
    @('--license', "--license-public-key=$Private", "--license-product=$Product")
)
foreach ($Arguments in $NegativeOptions) {
    $RejectedOutput = Join-Path $LicenseWork ('invalid-' + [Guid]::NewGuid().ToString('N') + '.exe')
    & $Pevm wrap $Fixture $RejectedOutput build-key @Arguments *> (Join-Path $LicenseWork 'invalid-cli.log')
    if ($LASTEXITCODE -eq 0 -or (Test-Path $RejectedOutput)) { Fail 'invalid license options produced a wrapper' }
}
foreach ($Days in @('-1', '1x', '36501', '4294967296')) {
    & $Pevm license-issue $Private $Days "--machine=$Machine" "--product=$Product" *> (Join-Path $LicenseWork 'invalid-days.log')
    if ($LASTEXITCODE -eq 0) { Fail "CLI accepted invalid days: $Days" }
}
& $Pevm license-issue $Private 30 "--machine=$Machine" "--product=$Product" "--output=$LicenseFile" *> (Join-Path $LicenseWork 'overwrite.log')
if ($LASTEXITCODE -eq 0 -or (Get-Content $LicenseFile -Raw).Trim() -ne $LicenseKey) { Fail 'issuance overwrote existing license' }
Ok 'required public key/product, legacy flag rejection and strict CLI days checked'

$WrongProductFile = Join-Path $LicenseWork 'wrong-product.license'
$WrongMachineFile = Join-Path $LicenseWork 'wrong-machine.license'
$OtherMachine = if ($Machine.StartsWith('a')) { 'b' + $Machine.Substring(1) } else { 'a' + $Machine.Substring(1) }
& $Pevm license-issue $Private 30 "--machine=$Machine" --product=another.product "--output=$WrongProductFile" *> (Join-Path $LicenseWork 'wrong-product.log')
if ($LASTEXITCODE -ne 0) { throw 'wrong-product fixture signing failed' }
& $Pevm license-issue $Private 30 "--machine=$OtherMachine" "--product=$Product" "--output=$WrongMachineFile" *> (Join-Path $LicenseWork 'wrong-machine.log')
if ($LASTEXITCODE -ne 0) { throw 'wrong-machine fixture signing failed' }
$EncodedPayload = $LicenseKey.Substring($LicensePrefix.Length)
$RawToken = [Convert]::FromBase64String($EncodedPayload)
$RawToken[132] = $RawToken[132] -bxor 1
$BadLicenses = @{
    'legacy' = 'PEVML1.' + $EncodedPayload
    'numbered-prefix' = 'PEVML2.' + $EncodedPayload
    'signature' = $LicensePrefix + [Convert]::ToBase64String($RawToken)
    'product' = (Get-Content $WrongProductFile -Raw).Trim()
    'machine' = (Get-Content $WrongMachineFile -Raw).Trim()
    'oversized' = ('A' * 4097)
}
$SavedEnvironment = @{}
foreach ($Name in @('PEVM_LICENSE', 'PEVM_TEST_ERROR_LOG', 'PEVM_TEST_NO_DIALOG', 'PEVM_TEST_VM_BRIDGE_LOG')) {
    $SavedEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
}
try {
    $env:PEVM_TEST_ERROR_LOG = '1'
    $env:PEVM_TEST_NO_DIALOG = '1'
    $env:PEVM_TEST_VM_BRIDGE_LOG = '1'
    [Environment]::SetEnvironmentVariable('PEVM_LICENSE', $null, 'Process')
    if ((Invoke-Wrapped $Output 'license-missing') -eq 0) { Fail 'missing license accepted' }
    elseif ((Get-Content "$Output.loader-error.txt" -Raw) -notmatch 'license check failed') { Fail 'unexpected missing-license failure' }
    else { Ok 'missing license rejected' }
    $env:PEVM_LICENSE = $LicenseKey
    if ((Invoke-Wrapped $Output 'license-valid') -ne 0 -or -not (Test-Path "$Output.vmbridge-hit")) { Fail 'valid license failed to reach VM bridge' }
    else { Ok 'valid signed license reaches VM bridge' }
    # A valid sidecar must not rescue any invalid environment value.
    [IO.File]::WriteAllText("$Output.license", $LicenseKey + "`n", [Text.Encoding]::ASCII)
    foreach ($Name in $BadLicenses.Keys) {
        $env:PEVM_LICENSE = $BadLicenses[$Name]
        if ((Invoke-Wrapped $Output "license-$Name") -eq 0) { Fail "$Name license accepted" }
        elseif ((Get-Content "$Output.loader-error.txt" -Raw) -notmatch 'license check failed') { Fail "unexpected $Name failure" }
        else { Ok "$Name license rejected with valid sidecar present" }
    }
    [Environment]::SetEnvironmentVariable('PEVM_LICENSE', $null, 'Process')
    if ((Invoke-Wrapped $Output 'license-sidecar') -ne 0) { Fail 'valid sidecar rejected' }
    else { Ok 'sidecar accepted when environment variable absent' }
    $env:PEVM_LICENSE = $LicenseKey
    foreach ($Command in @('wrap', 'protect-all', 'protect-functions')) {
        $AnotherOutput = Join-Path $LicenseWork "$Command.exe"
        $Arguments = @($Command, $Fixture, $AnotherOutput, 'build-key')
        if ($Command -eq 'protect-functions') { $Arguments += $Rva }
        & $Pevm @Arguments @LicenseOptions *> (Join-Path $LicenseWork "$Command-build.log")
        if ($LASTEXITCODE -ne 0) { Fail "licensed $Command build failed"; continue }
        if ((Invoke-Wrapped $AnotherOutput "license-$Command") -ne 0) { Fail "licensed $Command run failed" }
        else { Ok "licensed $Command accepted new format" }
    }
    # Reject old wrapper metadata even when it carries a new, otherwise valid card.
    $OldMetadata = $WrapperBytes.Clone()
    $OldMetadata[$MetadataOffset + 8] = 4
    $OldWrapper = Join-Path $LicenseWork 'old-metadata.exe'
    [IO.File]::WriteAllBytes($OldWrapper, $OldMetadata)
    if ((Invoke-Wrapped $OldWrapper 'license-old-metadata') -eq 0) { Fail 'old metadata accepted' }
    elseif ((Get-Content "$OldWrapper.loader-error.txt" -Raw) -notmatch 'metadata invalid') { Fail 'unexpected old metadata failure' }
    else { Ok 'old wrapper metadata rejected' }
} finally {
    foreach ($Name in $SavedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($Name, $SavedEnvironment[$Name], 'Process') }
}
