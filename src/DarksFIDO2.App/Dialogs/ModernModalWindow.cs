using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;

namespace DarksFIDO2.App.Dialogs;

public class ModernModalWindow : Window
{
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowDisplayAffinity(IntPtr hWnd, uint dwAffinity);
    private const uint WDA_EXCLUDEFROMCAPTURE = 0x00000011;

    protected readonly Border RootBorder;
    protected readonly StackPanel HeaderPanel;
    protected readonly Grid ContentGrid;
    protected readonly StackPanel ActionsPanel;

    public ModernModalWindow(Window? owner, string title, string? subtitle = null, double width = 480)
    {
        Owner = owner ?? Application.Current.MainWindow;
        Width = width;
        SizeToContent = SizeToContent.Height;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        FontFamily = (FontFamily)Application.Current.FindResource("FontPrimary");
        FontSize = 13;
        ShowInTaskbar = false;
        TextElement.SetForeground(this, (Brush)Application.Current.FindResource("TextPrimaryBrush"));

        Color shadowColor = Colors.Black;
        if (Application.Current.TryFindResource("ShadowAmbientColor") is Color sc)
        {
            shadowColor = sc;
        }

        RootBorder = new Border
        {
            Background = (Brush)Application.Current.FindResource("PanelBackgroundBrush"),
            BorderBrush = (Brush)Application.Current.FindResource("BorderHighlightBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(14),
            Margin = new Thickness(16),
            Effect = new DropShadowEffect
            {
                BlurRadius = 32,
                ShadowDepth = 8,
                Direction = 315,
                Color = shadowColor,
                Opacity = 0.55
            }
        };

        var mainLayout = new Grid();
        mainLayout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Header
        mainLayout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Content
        mainLayout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Actions

        // Header
        var headerBorder = new Border
        {
            Background = (Brush)Application.Current.FindResource("WellBackgroundBrush"),
            BorderBrush = (Brush)Application.Current.FindResource("BorderSubtleBrush"),
            BorderThickness = new Thickness(0, 0, 0, 1),
            CornerRadius = new CornerRadius(14, 14, 0, 0)
        };

        var headerGrid = new Grid();
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        HeaderPanel = new StackPanel { Margin = new Thickness(20, 16, 20, 16) };
        var titleBlock = new TextBlock
        {
            Text = title,
            FontFamily = (FontFamily)Application.Current.FindResource("FontPrimary"),
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush")
        };
        HeaderPanel.Children.Add(titleBlock);

        if (!string.IsNullOrWhiteSpace(subtitle))
        {
            var subBlock = new TextBlock
            {
                Text = subtitle,
                FontFamily = (FontFamily)Application.Current.FindResource("FontPrimary"),
                FontSize = 12,
                Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush"),
                Margin = new Thickness(0, 4, 0, 0),
                TextWrapping = TextWrapping.Wrap
            };
            HeaderPanel.Children.Add(subBlock);
        }

        headerGrid.Children.Add(HeaderPanel);

        // Close button
        var closeBtn = new Button
        {
            Width = 32,
            Height = 32,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            Margin = new Thickness(0, 12, 14, 0),
            VerticalAlignment = VerticalAlignment.Top
        };
        var closePath = new Path
        {
            Data = (Geometry)Application.Current.FindResource("IconClose"),
            Fill = (Brush)Application.Current.FindResource("TextSecondaryBrush"),
            Width = 12,
            Height = 12,
            Stretch = Stretch.Uniform
        };
        closeBtn.Content = closePath;
        closeBtn.Click += (s, e) => { DialogResult = false; Close(); };
        Grid.SetColumn(closeBtn, 1);
        headerGrid.Children.Add(closeBtn);

        // Header dragging
        headerBorder.MouseLeftButtonDown += (s, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed) DragMove();
        };

        headerBorder.Child = headerGrid;
        mainLayout.Children.Add(headerBorder);

        // Content
        ContentGrid = new Grid { Margin = new Thickness(24, 20, 24, 20) };
        Grid.SetRow(ContentGrid, 1);
        mainLayout.Children.Add(ContentGrid);

        // Actions
        ActionsPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(24, 0, 24, 20)
        };
        Grid.SetRow(ActionsPanel, 2);
        mainLayout.Children.Add(ActionsPanel);

        RootBorder.Child = mainLayout;
        Content = RootBorder;

        // Hotkeys
        KeyDown += (s, e) =>
        {
            if (e.Key == Key.Escape)
            {
                DialogResult = false;
                Close();
            }
        };

        SourceInitialized += (s, e) =>
        {
            var helper = new System.Windows.Interop.WindowInteropHelper(this);
            SetWindowDisplayAffinity(helper.Handle, WDA_EXCLUDEFROMCAPTURE);
        };
    }

    public void SetContent(UIElement element)
    {
        ContentGrid.Children.Clear();
        ContentGrid.Children.Add(element);
    }

    public void AddAction(Button button)
    {
        button.Margin = new Thickness(10, 0, 0, 0);
        ActionsPanel.Children.Add(button);
    }
}
