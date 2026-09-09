using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Windows.Media.Imaging;
using ZXing;
using ZXing.Common;
using Drawing = System.Drawing;
using DrawingImaging = System.Drawing.Imaging;

namespace DarksFIDO2.App.Services;

public interface IQrCaptureService
{
    string? ScanScreens();
    string? DecodeFile(string filePath);
}

public sealed class QrCaptureService : IQrCaptureService
{
    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int nIndex);

    private const int SM_XVIRTUALSCREEN = 76;
    private const int SM_YVIRTUALSCREEN = 77;
    private const int SM_CXVIRTUALSCREEN = 78;
    private const int SM_CYVIRTUALSCREEN = 79;

    public string? ScanScreens()
    {
        int left = GetSystemMetrics(SM_XVIRTUALSCREEN);
        int top = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

        if (width <= 0 || height <= 0) return null;
        ValidateDimensions(width, height);

        using var bitmap = new Drawing.Bitmap(width, height, DrawingImaging.PixelFormat.Format32bppArgb);
        using (Drawing.Graphics graphics = Drawing.Graphics.FromImage(bitmap))
        {
            graphics.CopyFromScreen(left, top, 0, 0, new Drawing.Size(width, height), Drawing.CopyPixelOperation.SourceCopy);
        }

        Drawing.Rectangle area = new(0, 0, bitmap.Width, bitmap.Height);
        DrawingImaging.BitmapData data = bitmap.LockBits(area, DrawingImaging.ImageLockMode.ReadOnly, DrawingImaging.PixelFormat.Format32bppArgb);
        try
        {
            int length = Math.Abs(data.Stride) * data.Height;
            byte[] pixels = new byte[length];
            Marshal.Copy(data.Scan0, pixels, 0, length);
            try
            {
                var source = new RGBLuminanceSource(pixels, bitmap.Width, bitmap.Height, RGBLuminanceSource.BitmapFormat.BGRA32);
                var reader = new BarcodeReaderGeneric
                {
                    AutoRotate = true,
                    Options = new DecodingOptions
                    {
                        TryHarder = true,
                        PossibleFormats = [BarcodeFormat.QR_CODE]
                    }
                };
                Result? result = reader.Decode(source);
                if (result?.Text.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase) == true)
                {
                    return result.Text;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pixels);
            }
        }
        finally
        {
            bitmap.UnlockBits(data);
        }

        return null;
    }

    public string? DecodeFile(string filePath)
    {
        if (!File.Exists(filePath)) return null;

        var uri = new Uri(Path.GetFullPath(filePath));
        var image = new BitmapImage();
        image.BeginInit();
        image.UriSource = uri;
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.EndInit();

        ValidateDimensions(image.PixelWidth, image.PixelHeight);

        var converted = new FormatConvertedBitmap(image, System.Windows.Media.PixelFormats.Bgra32, null, 0);
        int stride = checked(converted.PixelWidth * 4);
        byte[] pixels = new byte[checked(stride * converted.PixelHeight)];
        converted.CopyPixels(pixels, stride, 0);

        try
        {
            var luminance = new RGBLuminanceSource(pixels, converted.PixelWidth, converted.PixelHeight, RGBLuminanceSource.BitmapFormat.BGRA32);
            var reader = new BarcodeReaderGeneric
            {
                AutoRotate = true,
                Options = new DecodingOptions
                {
                    TryHarder = true,
                    PossibleFormats = [BarcodeFormat.QR_CODE]
                }
            };
            Result? result = reader.Decode(luminance);
            return result?.Text;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pixels);
        }
    }

    private static void ValidateDimensions(int width, int height)
    {
        if (width is < 1 or > 16_384 || height is < 1 or > 16_384 || (long)width * height > 40_000_000)
        {
            throw new System.FormatException("Image dimensions exceed the safety limit.");
        }
    }
}
