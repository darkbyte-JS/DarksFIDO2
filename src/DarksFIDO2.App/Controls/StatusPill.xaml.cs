using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace DarksFIDO2.App.Controls;

public enum PillVariant
{
    Success,
    Warning,
    Danger,
    Info,
    Neutral
}

public partial class StatusPill : UserControl
{
    public static readonly DependencyProperty TextProperty =
        DependencyProperty.Register(nameof(Text), typeof(string), typeof(StatusPill),
            new PropertyMetadata(string.Empty, OnTextOrVariantChanged));

    public static readonly DependencyProperty VariantProperty =
        DependencyProperty.Register(nameof(Variant), typeof(PillVariant), typeof(StatusPill),
            new PropertyMetadata(PillVariant.Neutral, OnTextOrVariantChanged));

    public StatusPill()
    {
        InitializeComponent();
        UpdateAppearance();
    }

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public PillVariant Variant
    {
        get => (PillVariant)GetValue(VariantProperty);
        set => SetValue(VariantProperty, value);
    }

    private static void OnTextOrVariantChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusPill pill) pill.UpdateAppearance();
    }

    private void UpdateAppearance()
    {
        if (PillText == null || PillBorder == null || PillDot == null) return;

        PillText.Text = Text;

        switch (Variant)
        {
            case PillVariant.Success:
                PillBorder.Background = (Brush)Application.Current.FindResource("StatusSuccessBgBrush");
                PillBorder.BorderBrush = (Brush)Application.Current.FindResource("StatusSuccessBrush");
                PillText.Foreground = (Brush)Application.Current.FindResource("StatusSuccessTextBrush");
                PillDot.Fill = (Brush)Application.Current.FindResource("StatusSuccessTextBrush");
                break;
            case PillVariant.Warning:
                PillBorder.Background = (Brush)Application.Current.FindResource("StatusWarningBgBrush");
                PillBorder.BorderBrush = (Brush)Application.Current.FindResource("StatusWarningBrush");
                PillText.Foreground = (Brush)Application.Current.FindResource("StatusWarningTextBrush");
                PillDot.Fill = (Brush)Application.Current.FindResource("StatusWarningTextBrush");
                break;
            case PillVariant.Danger:
                PillBorder.Background = (Brush)Application.Current.FindResource("StatusDangerBgBrush");
                PillBorder.BorderBrush = (Brush)Application.Current.FindResource("StatusDangerBrush");
                PillText.Foreground = (Brush)Application.Current.FindResource("StatusDangerTextBrush");
                PillDot.Fill = (Brush)Application.Current.FindResource("StatusDangerTextBrush");
                break;
            case PillVariant.Info:
                PillBorder.Background = (Brush)Application.Current.FindResource("StatusInfoBgBrush");
                PillBorder.BorderBrush = (Brush)Application.Current.FindResource("StatusInfoBrush");
                PillText.Foreground = (Brush)Application.Current.FindResource("StatusInfoTextBrush");
                PillDot.Fill = (Brush)Application.Current.FindResource("StatusInfoTextBrush");
                break;
            default:
                PillBorder.Background = (Brush)Application.Current.FindResource("SurfaceBackgroundBrush");
                PillBorder.BorderBrush = (Brush)Application.Current.FindResource("BorderStrongBrush");
                PillText.Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush");
                PillDot.Fill = (Brush)Application.Current.FindResource("TextSecondaryBrush");
                break;
        }
    }
}
