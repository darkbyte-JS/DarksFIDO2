param(
    [string]$LogoPath = (Join-Path $PSScriptRoot "..\src\DarksFIDO2.App\Assets\darks-fido2-brand-source.png"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\docs\assets\social-preview.png")
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$logo = [System.Drawing.Image]::FromFile((Resolve-Path $LogoPath))
$bitmap = [System.Drawing.Bitmap]::new(1280, 640, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

try {
    $background = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
        [System.Drawing.Rectangle]::new(0, 0, 1280, 640),
        [System.Drawing.Color]::FromArgb(255, 4, 7, 24),
        [System.Drawing.Color]::FromArgb(255, 15, 9, 43),
        12.0)
    $graphics.FillRectangle($background, 0, 0, 1280, 640)
    $background.Dispose()

    $cyanGlow = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(28, 0, 240, 214))
    $purpleGlow = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(34, 136, 66, 255))
    $graphics.FillEllipse($cyanGlow, -120, 130, 620, 620)
    $graphics.FillEllipse($purpleGlow, 830, -260, 650, 650)
    $cyanGlow.Dispose()
    $purpleGlow.Dispose()

    $logoRectangle = [System.Drawing.Rectangle]::new(70, 80, 480, 480)
    $graphics.DrawImage($logo, $logoRectangle)

    $titleFont = [System.Drawing.Font]::new("Segoe UI", 66, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $subtitleFont = [System.Drawing.Font]::new("Segoe UI", 33, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $labelFont = [System.Drawing.Font]::new("Segoe UI Semibold", 22, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $badgeFont = [System.Drawing.Font]::new("Segoe UI Semibold", 18, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
    $white = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 244, 247, 255))
    $muted = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 190, 200, 229))
    $accent = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 55, 236, 220))
    $badge = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 88, 55, 183))

    $graphics.DrawString("Darks FIDO2", $titleFont, $white, 560, 150)
    $graphics.DrawString("TPM-backed passkeys for Windows 11", $subtitleFont, $muted, 566, 250)
    $graphics.DrawString("FIDO2  |  WebAuthn  |  TOTP", $labelFont, $accent, 568, 330)
    $graphics.FillRectangle($badge, 568, 405, 210, 47)
    $graphics.DrawString("EXPERIMENTAL BETA", $badgeFont, $white, 584, 415)
    $graphics.DrawString("Open source  |  Local-first  |  Apache-2.0", $labelFont, $muted, 568, 485)

    $titleFont.Dispose()
    $subtitleFont.Dispose()
    $labelFont.Dispose()
    $badgeFont.Dispose()
    $white.Dispose()
    $muted.Dispose()
    $accent.Dispose()
    $badge.Dispose()

    $outputDirectory = Split-Path -Parent $OutputPath
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
    $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
}
finally {
    $graphics.Dispose()
    $bitmap.Dispose()
    $logo.Dispose()
}

$image = [System.Drawing.Image]::FromFile((Resolve-Path $OutputPath))
try {
    if ($image.Width -ne 1280 -or $image.Height -ne 640) {
        throw "Generated social preview has an unexpected size."
    }
}
finally {
    $image.Dispose()
}
