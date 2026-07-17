using System.Windows;
using System.Windows.Media;
using DarksFIDO2.Core;

namespace DarksFIDO2.App;

internal static class ThemeManager
{
    public static void Apply(AppTheme theme)
    {
        ThemePalette palette = theme switch
        {
            AppTheme.Light => new(
                Window: "#F4F7FB", Panel: "#FFFFFFFF", PanelAlt: "#FFF0F4FA", Elevated: "#FFFFFFFF",
                CardHover: "#FFE8EEF8", Side: "#FFF8FAFD", Header: "#FAFFFFFF",
                Text: "#17233B", Muted: "#53647E", Subtle: "#71809A",
                Accent: "#067A99", AccentStrong: "#4F46E5", AccentHover: "#4338CA", AccentSurface: "#FFE7F7FB",
                OnAccent: "#FFFFFF", Border: "#CCD7E5",
                Input: "#FFFFFFFF", InputText: "#17233B", InputHover: "#FFF5F8FC",
                Success: "#087A55", SuccessSurface: "#FFE8F8F1",
                Warning: "#945700", WarningSurface: "#FFFFF5DC",
                Danger: "#B92F4B", DangerSurface: "#FFFDEBF0"),
            AppTheme.Dark => new(
                Window: "#080B12", Panel: "#F2131823", PanelAlt: "#FF1B2230", Elevated: "#FF202938",
                CardHover: "#FF263142", Side: "#F50A0E16", Header: "#F20D121C",
                Text: "#F5F7FB", Muted: "#A9B2C3", Subtle: "#7E899D",
                Accent: "#7DD3FC", AccentStrong: "#5865E8", AccentHover: "#6D78F2", AccentSurface: "#26385573",
                OnAccent: "#FFFFFF", Border: "#354154",
                Input: "#FF151C28", InputText: "#F5F7FB", InputHover: "#FF202B3A",
                Success: "#64DDB0", SuccessSurface: "#2034A47B",
                Warning: "#F6C85F", WarningSurface: "#263B3018",
                Danger: "#FF8198", DangerSurface: "#263C1924"),
            _ => new(
                Window: "#070B18", Panel: "#F20E1730", PanelAlt: "#FF15213F", Elevated: "#FF192746",
                CardHover: "#FF1D2D50", Side: "#F7070D1D", Header: "#F20A1125",
                Text: "#F8FAFF", Muted: "#AEBBD4", Subtle: "#8290AE",
                Accent: "#56E4FF", AccentStrong: "#6857F5", AccentHover: "#7C6BFF", AccentSurface: "#263C52A0",
                OnAccent: "#FFFFFF", Border: "#3B4B70",
                Input: "#FF101A31", InputText: "#F8FAFF", InputHover: "#FF1A2948",
                Success: "#5EE6B1", SuccessSurface: "#2032B585",
                Warning: "#FFD166", WarningSurface: "#263D3218",
                Danger: "#FF7A91", DangerSurface: "#263E1725")
        };

        ResourceDictionary resources = Application.Current.Resources;
        Set(resources, "WindowBrush", palette.Window);
        Set(resources, "PanelBrush", palette.Panel);
        Set(resources, "PanelAltBrush", palette.PanelAlt);
        Set(resources, "SurfaceElevatedBrush", palette.Elevated);
        Set(resources, "CardHoverBrush", palette.CardHover);
        Set(resources, "SidePanelBrush", palette.Side);
        Set(resources, "HeaderBrush", palette.Header);
        Set(resources, "TextBrush", palette.Text);
        Set(resources, "MutedBrush", palette.Muted);
        Set(resources, "SubtleTextBrush", palette.Subtle);
        Set(resources, "AccentBrush", palette.Accent);
        Set(resources, "AccentStrongBrush", palette.AccentStrong);
        Set(resources, "AccentHoverBrush", palette.AccentHover);
        Set(resources, "AccentSurfaceBrush", palette.AccentSurface);
        Set(resources, "OnAccentTextBrush", palette.OnAccent);
        Set(resources, "BorderBrush", palette.Border);
        Set(resources, "InputBrush", palette.Input);
        Set(resources, "InputTextBrush", palette.InputText);
        Set(resources, "InputHoverBrush", palette.InputHover);
        Set(resources, "SuccessBrush", palette.Success);
        Set(resources, "SuccessSurfaceBrush", palette.SuccessSurface);
        Set(resources, "WarningBrush", palette.Warning);
        Set(resources, "WarningSurfaceBrush", palette.WarningSurface);
        Set(resources, "DangerBrush", palette.Danger);
        Set(resources, "DangerSurfaceBrush", palette.DangerSurface);
    }

    private static void Set(ResourceDictionary resources, string key, string color) => resources[key] = Brush(color);

    private static SolidColorBrush Brush(string value)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        brush.Freeze();
        return brush;
    }

    private sealed record ThemePalette(
        string Window, string Panel, string PanelAlt, string Elevated, string CardHover, string Side, string Header,
        string Text, string Muted, string Subtle, string Accent, string AccentStrong, string AccentHover, string AccentSurface,
        string OnAccent, string Border, string Input, string InputText, string InputHover,
        string Success, string SuccessSurface, string Warning, string WarningSurface, string Danger, string DangerSurface);
}
