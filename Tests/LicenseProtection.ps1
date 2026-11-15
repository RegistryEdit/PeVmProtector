# Invoked by RunTests.ps1; all keys and executables use an isolated test directory.
$SecureWork = Join-Path $Work ('license-protection-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $SecureWork | Out-Null
$SecurePrivate = Join-Path $SecureWork 'issuer.private'
$SecurePublic = Join-Path $SecureWork 'issuer.pub'
$SecureBuildKey = Join-Path $SecureWork 'product.buildkey'
$SecureCard = Join-Path $SecureWork 'customer.license'
$SecureProduct = 'license.protection.test'
$MachineText = (& $Pevm license-machine-id) -join "`n"
if ($LASTEXITCODE -ne 0 -or $MachineText -notmatch 'machine id: ([0-9a-f]{64})') { throw 'machine identity unavailable' }
$SecureMachine = $Matches[1]
& $Pevm license-keygen $SecurePrivate $SecurePublic *> (Join-Path $SecureWork 'keygen.log')
if ($LASTEXITCODE -ne 0) { throw 'secure test key generation failed' }
& $Pevm license-export-build-key $SecurePrivate $SecureBuildKey "--product=$SecureProduct" *> (Join-Path $SecureWork 'build-key.log')
if ($LASTEXITCODE -ne 0) { throw 'product build key export failed' }
& $Pevm license-issue $SecurePrivate 30 "--machine=$SecureMachine" "--product=$SecureProduct" "--output=$SecureCard" *> (Join-Path $SecureWork 'issue.log')
if ($LASTEXITCODE -ne 0) { throw 'secure license issuance failed' }
$SecureToken = (Get-Content -LiteralPath $SecureCard -Raw).Trim()
$CardBytes = [Convert]::FromBase64String($SecureToken.Substring('PEVM-LICENSE.'.Length))
if ($CardBytes.Length -ne 228 -or [BitConverter]::ToUInt32($CardBytes, 0) -ne 3) { throw 'v3 license payload missing' }
$RvaText = Get-FixtureText
if ($RvaText -notmatch 'PEVM-FIXTURE-RVA LiftTarget=0x([0-9a-fA-F]+)') { throw 'fixture RVA missing' }
$SecureRva = '0x' + $Matches[1]
$SecureOptions = @('--license', "--license-public-key=$SecurePublic", "--license-product=$SecureProduct", "--license-build-key=$SecureBuildKey")
$SecureOutput = Join-Path $SecureWork 'licensed.exe'
$OriginalEnvironment = @{}
foreach ($Name in @('PEVM_LICENSE','PEVM_TEST_NO_DIALOG','PEVM_TEST_ERROR_LOG','PEVM_TEST_VM_BRIDGE_LOG')) {
    $OriginalEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
}
try {
    $env:PEVM_TEST_NO_DIALOG = '1'
    $env:PEVM_TEST_ERROR_LOG = '1'
    $env:PEVM_TEST_VM_BRIDGE_LOG = '1'
    foreach ($Command in @('wrap','protect-function','protect-functions','protect-all')) {
        $CommandOutput = Join-Path $SecureWork ($Command + '.exe')
        $Arguments = @($Command,$Fixture,$CommandOutput,'secure-test-build-password')
        if ($Command -in @('protect-function','protect-functions')) { $Arguments += $SecureRva }
        & $Pevm @Arguments @SecureOptions *> (Join-Path $SecureWork ($Command + '-build.log'))
        if ($LASTEXITCODE -ne 0) { Fail "$Command license-held encryption build failed"; continue }
        $env:PEVM_LICENSE = $null
        if ((Invoke-Wrapped $CommandOutput ("secure-$Command-missing")) -eq 0) { Fail "$Command accepted missing license" }
        $env:PEVM_LICENSE = $SecureToken
        if ((Invoke-Wrapped $CommandOutput ("secure-$Command-valid")) -ne 0) { Fail "$Command rejected valid v3 license" }
        elseif ($Command -ne 'wrap' -and -not (Test-Path -LiteralPath "$CommandOutput.vmbridge-hit")) { Fail "$Command did not reach VM bridge" }
        else { Ok "$Command requires v3 card to decrypt payload and run" }
        if ($Command -eq 'protect-function') { $SecureOutput = $CommandOutput }
    }
    $SecureImage = [IO.File]::ReadAllBytes($SecureOutput)
    $FooterOffset = $SecureImage.Length - 76
    if ([BitConverter]::ToUInt32($SecureImage,$FooterOffset+8) -ne 3) { Fail 'strong wrapper footer version missing' }
    $MetadataOffset = [int][BitConverter]::ToUInt64($SecureImage,$FooterOffset+36)
    if ([BitConverter]::ToUInt32($SecureImage,$MetadataOffset+164) -ne 2) { Fail 'strong license policy missing' }
    $BinaryEncoding = [Text.Encoding]::GetEncoding(28591)
    $ImageText = $BinaryEncoding.GetString($SecureImage)
    if ($ImageText.Contains($BinaryEncoding.GetString([byte[]]$CardBytes[132..163])) -or $ImageText.Contains('secure-test-build-password')) {
        Fail 'product unlock key or clear build password embedded in executable'
    } else { Ok 'EXE contains neither product unlock key nor plaintext build password' }
    $Tampered = [byte[]]$SecureImage.Clone()
    $Tampered[$MetadataOffset+100] = $Tampered[$MetadataOffset+100] -bxor 1
    $TamperedPath = Join-Path $SecureWork 'tampered.exe'
    [IO.File]::WriteAllBytes($TamperedPath,$Tampered)
    if ((Invoke-Wrapped $TamperedPath 'secure-metadata-tamper') -eq 0) { Fail 'unauthenticated metadata edit accepted' }
    elseif ((Get-Content -LiteralPath "$TamperedPath.loader-error.txt" -Raw) -notmatch 'licensed wrapper authentication failed') { Fail 'metadata edit did not reach AES-GCM authentication failure' }
    else { Ok 'AES-GCM rejects metadata edits outside legacy region checks' }
    $Downgraded = [byte[]]$SecureImage.Clone()
    $Downgraded[$FooterOffset+8] = 2
    $Downgraded[$MetadataOffset+164] = 1
    $DowngradedPath = Join-Path $SecureWork 'downgraded.exe'
    [IO.File]::WriteAllBytes($DowngradedPath,$Downgraded)
    if ((Invoke-Wrapped $DowngradedPath 'secure-downgrade') -eq 0) { Fail 'downgrading footer and policy recovered payload' }
    else { Ok 'policy/footer downgrade cannot recover encrypted build password' }
    $TamperedCard = [byte[]]$CardBytes.Clone()
    $TamperedCard[132] = $TamperedCard[132] -bxor 1
    $env:PEVM_LICENSE = 'PEVM-LICENSE.' + [Convert]::ToBase64String($TamperedCard)
    if ((Invoke-Wrapped $SecureOutput 'secure-key-tamper') -eq 0) { Fail 'modified signed product key accepted' }
    else { Ok 'product unlock key modification invalidates card signature' }
    $RejectedOutput = Join-Path $SecureWork 'wrong-product.exe'
    & $Pevm wrap $Fixture $RejectedOutput test --license "--license-public-key=$SecurePublic" --license-product=wrong.product "--license-build-key=$SecureBuildKey" *> (Join-Path $SecureWork 'wrong-product.log')
    if ($LASTEXITCODE -eq 0 -or (Test-Path -LiteralPath $RejectedOutput)) { Fail 'mismatched build credential produced output' }
    else { Ok 'build credential is issuer/product bound and checked before output' }
    . (Join-Path $PSScriptRoot 'AnalysisResistance.ps1')
} finally {
    foreach ($Name in $OriginalEnvironment.Keys) { [Environment]::SetEnvironmentVariable($Name,$OriginalEnvironment[$Name],'Process') }
}
