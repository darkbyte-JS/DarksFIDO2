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
                Window: "#E2E8F0", Panel: "#E8EEF6", PanelAlt: "#EDF3FA", Elevated: "#F2F7FD",
                CardHover: "#F8FBFF", Side: "#DAE1EB", Header: "#DEE5EF",
                Text: "#1E293B", Muted: "#64748B", Subtle: "#94A3B8",
                Accent: "#0284C7", AccentStrong: "#4F46E5", AccentHover: "#4338CA", AccentSurface: "#E0F2FE",
                OnAccent: "#FFFFFF", Border: "#CBD5E1", BorderHighlight: "#FFFFFF", BorderShadow: "#BAC5D5",
                Input: "#D9E1ED", InputText: "#0F172A", InputHover: "#D2DAE7",
                Success: "#059669", SuccessSurface: "#D1FAE5",
                Warning: "#D97706", WarningSurface: "#FEF3C7",
                Danger: "#E11D48", DangerSurface: "#FFE4E6",
                CardGradStart: "#EEF4FB", CardGradEnd: "#E2E8F1"),
            AppTheme.Dark => new(
                Window: "#181B22", Panel: "#1F242E", PanelAlt: "#252B37", Elevated: "#282F3D",
                CardHover: "#2E3545", Side: "#15181F", Header: "#1A1D25",
                Text: "#F3F4F6", Muted: "#9CA3AF", Subtle: "#6B7280",
                Accent: "#38BDF8", AccentStrong: "#6366F1", AccentHover: "#4F46E5", AccentSurface: "#2638BDF8",
                OnAccent: "#FFFFFF", Border: "#2C3342", BorderHighlight: "#3B4457", BorderShadow: "#101217",
                Input: "#14161D", InputText: "#F3F4F6", InputHover: "#181A22",
                Success: "#34D399", SuccessSurface: "#2634D399",
                Warning: "#FBBF24", WarningSurface: "#26FBBF24",
                Danger: "#F43F5E", DangerSurface: "#26F43F5E",
                CardGradStart: "#242936", CardGradEnd: "#1C202A"),
            _ => new(
                Window: "#0F121C", Panel: "#191E2C", PanelAlt: "#202638", Elevated: "#262E44",
                CardHover: "#2D364F", Side: "#0D1018", Header: "#111520",
                Text: "#F8FAFF", Muted: "#A5B4CD", Subtle: "#73839E",
                Accent: "#56E4FF", AccentStrong: "#7C3AED", AccentHover: "#8B5CF6", AccentSurface: "#2656E4FF",
                OnAccent: "#FFFFFF", Border: "#2D374E", BorderHighlight: "#435070", BorderShadow: "#080A10",
                Input: "#0F121B", InputText: "#F8FAFF", InputHover: "#131722",
                Success: "#5EE6B1", SuccessSurface: "#265EE6B1",
                Warning: "#FFD166", WarningSurface: "#26FFD166",
                Danger: "#FF7A91", DangerSurface: "#26FF7A91",
                CardGradStart: "#21283B", CardGradEnd: "#171B28")
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
        Set(resources, "BorderHighlightBrush", palette.BorderHighlight);
        Set(resources, "BorderShadowBrush", palette.BorderShadow);
        Set(resources, "InputBrush", palette.Input);
        Set(resources, "InputTextBrush", palette.InputText);
        Set(resources, "InputHoverBrush", palette.InputHover);
        Set(resources, "SuccessBrush", palette.Success);
        Set(resources, "SuccessSurfaceBrush", palette.SuccessSurface);
        Set(resources, "WarningBrush", palette.Warning);
        Set(resources, "WarningSurfaceBrush", palette.WarningSurface);
        Set(resources, "DangerBrush", palette.Danger);
        Set(resources, "DangerSurfaceBrush", palette.DangerSurface);
        Set(resources, "CardGradientStartBrush", palette.CardGradStart);
        Set(resources, "CardGradientEndBrush", palette.CardGradEnd);
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
        string OnAccent, string Border, string BorderHighlight, string BorderShadow, string Input, string InputText, string InputHover,
        string Success, string SuccessSurface, string Warning, string WarningSurface, string Danger, string DangerSurface,
        string CardGradStart, string CardGradEnd);
}
