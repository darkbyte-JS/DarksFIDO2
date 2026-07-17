param(
    [string]$Configuration = 'Release',
    [string]$Runtime = 'win-x64',
    [string]$CertificateThumbprint = '',
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$dotnet = if ($env:DOTNET_EXE) { $env:DOTNET_EXE } else { 'dotnet' }
$artifacts = Join-Path $root 'artifacts'
$portable = Join-Path $artifacts 'portable'
$payload = Join-Path $root 'src\DarksFIDO2.Setup\Payload'
$out = Join-Path $artifacts 'release'

Remove-Item $artifacts -Recurse -Force -ErrorAction SilentlyContinue
New-Item $portable, $payload, $out -ItemType Directory -Force | Out-Null

& $dotnet restore (Join-Path $root 'DarksFIDO2.slnx') --locked-mode
if ($LASTEXITCODE -ne 0) { throw 'Locked dependency restore failed.' }

# Keep the GUI self-contained but multi-file. A single-file WPF bundle extracts a full
# runtime on first launch after every upgrade, which made this small UI appear to hang.
& $dotnet publish (Join-Path $root 'src\DarksFIDO2.App\DarksFIDO2.App.csproj') -c $Configuration -r $Runtime --self-contained true --no-restore -p:PublishSingleFile=false -p:PublishReadyToRun=true -p:DebugType=None -o $portable
& $dotnet publish (Join-Path $root 'src\DarksFIDO2.Cli\DarksFIDO2.Cli.csproj') -c $Configuration -r $Runtime --self-contained true --no-restore -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $portable
& $dotnet publish (Join-Path $root 'src\DarksFIDO2.Provider\DarksFIDO2.Provider.csproj') -c $Configuration -r $Runtime --self-contained true --no-restore -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $portable
Copy-Item (Join-Path $root 'src\DarksFIDO2.App\Assets\favicon.ico') (Join-Path $portable 'favicon.ico') -Force
Copy-Item (Join-Path $root 'src\DarksFIDO2.App\Assets\favicon.png') (Join-Path $portable 'favicon.png') -Force
Set-Content (Join-Path $portable 'portable.mode') 'Darks FIDO2 portable data stays beside the executable.' -Encoding ASCII
Copy-Item (Join-Path $root 'README.md') (Join-Path $portable 'README.txt')

if (!$CertificateThumbprint) { throw 'A signing certificate is required for the Windows passkey provider package.' }
$providerPackage = Join-Path $artifacts 'DarksFIDO2.Provider.msix'
$localSdkBin = Join-Path (Split-Path $root -Parent) 'c\bin\10.0.26100.0\x64'
$makeAppx = if ($env:MAKEAPPX_EXE) { $env:MAKEAPPX_EXE } elseif (Test-Path (Join-Path $localSdkBin 'makeappx.exe')) { Join-Path $localSdkBin 'makeappx.exe' } else { '' }
$signTool = if ($env:SIGNTOOL_EXE) { $env:SIGNTOOL_EXE } elseif (Test-Path (Join-Path $localSdkBin 'signtool.exe')) { Join-Path $localSdkBin 'signtool.exe' } else { '' }
if (!(Test-Path $makeAppx) -or !(Test-Path $signTool)) { throw 'Windows SDK makeappx.exe and signtool.exe are required.' }
foreach ($name in 'DarksFIDO2.exe','darksfido-cli.exe','DarksFIDO2.Provider.exe') {
    & $signTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 (Join-Path $portable $name) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Executable signing failed for $name." }
}
& (Join-Path $PSScriptRoot 'build-provider-package.ps1') -ProviderExecutable (Join-Path $portable 'DarksFIDO2.Provider.exe') -OutputPath $providerPackage -CertificateThumbprint $CertificateThumbprint -MakeAppx $makeAppx -SignTool $signTool -TimestampServer $TimestampServer
Copy-Item $providerPackage (Join-Path $portable 'DarksFIDO2.Provider.msix') -Force
Copy-Item $providerPackage (Join-Path $payload 'DarksFIDO2.Provider.msix') -Force
$certificatePath = Join-Path $out 'DarksFIDO2-Signing-Public.cer'
Export-Certificate -Cert ("Cert:\CurrentUser\My\" + $CertificateThumbprint) -FilePath $certificatePath -Force | Out-Null

# The setup executable is signed, and this embedded manifest extends that trust to
# every file extracted from its payload before installation.
$integrity = [ordered]@{}
$portableRoot = (Resolve-Path $portable).Path.TrimEnd('\') + '\'
Get-ChildItem $portable -File -Recurse | Sort-Object FullName | ForEach-Object {
    if (!$_.FullName.StartsWith($portableRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'A payload path escaped the portable root.' }
    $relative = $_.FullName.Substring($portableRoot.Length).Replace('\', '/')
    $integrity[$relative] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
}
$integrityJson = $integrity | ConvertTo-Json
[IO.File]::WriteAllText(
    (Join-Path $portable 'integrity.sha256.json'),
    $integrityJson,
    [Text.UTF8Encoding]::new($false))

$portableZip = Join-Path $out 'DarksFIDO2-Portable.zip'
Compress-Archive -Path (Join-Path $portable '*') -DestinationPath $portableZip -CompressionLevel Optimal
Copy-Item $portableZip (Join-Path $payload 'DarksFIDO2-Portable.zip') -Force

& $dotnet publish (Join-Path $root 'src\DarksFIDO2.Setup\DarksFIDO2.Setup.csproj') -c $Configuration -r $Runtime --self-contained true --no-restore -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o (Join-Path $artifacts 'setup')
$setup = Join-Path $artifacts 'setup\DarksFIDO2-Setup.exe'
& $signTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 $setup | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Setup signing failed.' }
Copy-Item $setup (Join-Path $out 'DarksFIDO2-Setup.exe') -Force
Get-ChildItem $out | Select-Object Name, Length, LastWriteTime
