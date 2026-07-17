param(
    [Parameter(Mandatory=$true)][string]$ProviderExecutable,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [string]$MakeAppx = '',
    [string]$SignTool = '',
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (!$MakeAppx) {
    $MakeAppx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter makeappx.exe -ErrorAction SilentlyContinue |
        Where-Object FullName -Match '\\x64\\makeappx.exe$' | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (!$SignTool) {
    $SignTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object FullName -Match '\\x64\\signtool.exe$' | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (!(Test-Path $MakeAppx) -or !(Test-Path $SignTool)) { throw 'Windows SDK makeappx.exe and signtool.exe are required.' }
$certificate = Get-Item -LiteralPath ("Cert:\CurrentUser\My\" + $CertificateThumbprint) -ErrorAction SilentlyContinue
if (!$certificate) { $certificate = Get-Item -LiteralPath ("Cert:\LocalMachine\My\" + $CertificateThumbprint) -ErrorAction SilentlyContinue }
if (!$certificate -or !$certificate.HasPrivateKey) { throw 'The requested package-signing certificate with a private key was not found.' }
$providerProject = [xml](Get-Content (Join-Path $root 'src\DarksFIDO2.Provider\DarksFIDO2.Provider.csproj') -Raw)
$versionNode = $providerProject.SelectSingleNode('/Project/PropertyGroup/Version')
$versionText = if ($versionNode) { $versionNode.InnerText } else { '' }
if (!$versionText) { throw 'The provider project version is missing.' }
$projectVersion = [version]$versionText
$packageVersion = '{0}.{1}.{2}.0' -f $projectVersion.Major, $projectVersion.Minor, $projectVersion.Build
$publisher = [Security.SecurityElement]::Escape($certificate.Subject)

$stage = Join-Path ([IO.Path]::GetTempPath()) ('DarksFIDO2-Provider-' + [guid]::NewGuid().ToString('N'))
New-Item (Join-Path $stage 'Assets') -ItemType Directory -Force | Out-Null
try {
    Copy-Item $ProviderExecutable (Join-Path $stage 'DarksFIDO2.Provider.exe')
    $manifest = Get-Content (Join-Path $root 'src\DarksFIDO2.Provider\Package.appxmanifest') -Raw
    $manifest = $manifest.Replace('__PUBLISHER__', $publisher).Replace('__VERSION__', $packageVersion)
    if ($manifest.Contains('__')) { throw 'The provider package manifest contains an unresolved template value.' }
    [IO.File]::WriteAllText((Join-Path $stage 'AppxManifest.xml'), $manifest, [Text.UTF8Encoding]::new($false))
    foreach ($name in 'StoreLogo.png','Square150x150Logo.png','Square44x44Logo.png') {
        Copy-Item (Join-Path $root 'src\DarksFIDO2.App\Assets\favicon.png') (Join-Path $stage "Assets\$name")
    }
    & $MakeAppx pack /d $stage /p $OutputPath /o | Out-Null
    & $SignTool sign /sha1 $CertificateThumbprint /fd SHA256 /tr $TimestampServer /td SHA256 $OutputPath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Provider package signing failed.' }
}
finally { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
