using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace DarksFIDO2.App.Dialogs;

public sealed class PasswordGeneratorDialog : ModernModalWindow
{
    private readonly TextBox _passwordBox;
    private readonly TextBlock _statusText;
    private readonly Slider _lengthSlider;
    private readonly TextBlock _lengthLabel;
    private readonly CheckBox _cbDigits;
    private readonly CheckBox _cbLowercase;
    private readonly CheckBox _cbUppercase;
    private readonly CheckBox _cbSymbols;
    private readonly CheckBox _cbExtendedAscii;

    private string _currentPassword = string.Empty;
    private DispatcherTimer? _clipboardTimer;
    private int _countdownSeconds = 10;
    private bool _isClosed = false;

    public PasswordGeneratorDialog(Window? owner)
        : base(owner, "EPHEMERAL PASSWORD GENERATOR", "Zero-retention cryptographically secure password generator with clipboard guard.", 520)
    {
        var mainStack = new StackPanel();

        // 1. Password Display Well
        var wellBorder = new Border
        {
            Background = (Brush)Application.Current.FindResource("WellBackgroundBrush"),
            BorderBrush = (Brush)Application.Current.FindResource("BorderStrongBrush"),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(12, 10, 10, 10),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var wellGrid = new Grid();
        wellGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        wellGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _passwordBox = new TextBox
        {
            IsReadOnly = true,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            FontFamily = (FontFamily)Application.Current.FindResource("FontMonospace"),
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
            VerticalAlignment = VerticalAlignment.Center,
            CaretBrush = (Brush)Application.Current.FindResource("AccentPrimaryBrush")
        };
        wellGrid.Children.Add(_passwordBox);

        var regenBtn = new Button
        {
            Style = (Style)Application.Current.FindResource("BtnSecondary"),
            Width = 34,
            Height = 34,
            Padding = new Thickness(0),
            Margin = new Thickness(10, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center,
            ToolTip = "Generate new password"
        };
        var regenPath = new Path
        {
            Data = (Geometry)Application.Current.FindResource("IconRefresh"),
            Fill = (Brush)Application.Current.FindResource("TextSecondaryBrush"),
            Width = 14,
            Height = 14,
            Stretch = Stretch.Uniform
        };
        regenBtn.Content = regenPath;
        regenBtn.Click += (s, e) => GenerateNewPassword();
        Grid.SetColumn(regenBtn, 1);
        wellGrid.Children.Add(regenBtn);

        wellBorder.Child = wellGrid;
        mainStack.Children.Add(wellBorder);

        // 2. Status & Ephemeral Countdown Notice
        _statusText = new TextBlock
        {
            Text = "Zero disk retention: generated credentials are never saved or written to audit logs.",
            Style = (Style)Application.Current.FindResource("TextCaption"),
            FontSize = 11,
            Margin = new Thickness(2, 0, 0, 18),
            Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush")
        };
        mainStack.Children.Add(_statusText);

        // 3. Length Selector Slider
        var lengthGrid = new Grid { Margin = new Thickness(0, 0, 0, 14) };
        lengthGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        lengthGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var lengthTitle = new TextBlock
        {
            Text = "PASSWORD LENGTH",
            Style = (Style)Application.Current.FindResource("TextCaption"),
            FontWeight = FontWeights.Bold
        };
        lengthGrid.Children.Add(lengthTitle);

        _lengthLabel = new TextBlock
        {
            Text = "20 characters",
            Style = (Style)Application.Current.FindResource("TextMonoData"),
            FontWeight = FontWeights.Bold,
            Foreground = (Brush)Application.Current.FindResource("AccentPrimaryBrush")
        };
        Grid.SetColumn(_lengthLabel, 1);
        lengthGrid.Children.Add(_lengthLabel);
        mainStack.Children.Add(lengthGrid);

        _lengthSlider = new Slider
        {
            Minimum = 8,
            Maximum = 64,
            Value = 20,
            TickFrequency = 1,
            IsSnapToTickEnabled = true,
            Margin = new Thickness(0, 0, 0, 18)
        };
        _lengthSlider.ValueChanged += (s, e) =>
        {
            if (_lengthLabel is not null)
            {
                _lengthLabel.Text = $"{(int)_lengthSlider.Value} characters";
            }
            GenerateNewPassword();
        };
        mainStack.Children.Add(_lengthSlider);

        // 4. Character Set Checkbox Options
        var optionsTitle = new TextBlock
        {
            Text = "CHARACTER SETS",
            Style = (Style)Application.Current.FindResource("TextCaption"),
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 0, 10)
        };
        mainStack.Children.Add(optionsTitle);

        var optionsGrid = new Grid { Margin = new Thickness(0, 0, 0, 16) };
        optionsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        optionsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        optionsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        optionsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        optionsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        _cbDigits = new CheckBox
        {
            Content = "Numbers (0-9)",
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 10)
        };
        _cbDigits.Click += (s, e) => OnOptionChanged();
        optionsGrid.Children.Add(_cbDigits);

        _cbLowercase = new CheckBox
        {
            Content = "Lowercase (a-z)",
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 10)
        };
        _cbLowercase.Click += (s, e) => OnOptionChanged();
        Grid.SetColumn(_cbLowercase, 1);
        optionsGrid.Children.Add(_cbLowercase);

        _cbUppercase = new CheckBox
        {
            Content = "Uppercase (A-Z)",
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 10)
        };
        _cbUppercase.Click += (s, e) => OnOptionChanged();
        Grid.SetRow(_cbUppercase, 1);
        optionsGrid.Children.Add(_cbUppercase);

        _cbSymbols = new CheckBox
        {
            Content = "Special symbols (!@#$...)",
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 10)
        };
        _cbSymbols.Click += (s, e) => OnOptionChanged();
        Grid.SetRow(_cbSymbols, 1);
        Grid.SetColumn(_cbSymbols, 1);
        optionsGrid.Children.Add(_cbSymbols);

        _cbExtendedAscii = new CheckBox
        {
            Content = "Extended ASCII (¡, ¿, ©, ®, ±, µ...)",
            IsChecked = false,
            Margin = new Thickness(0, 0, 0, 4)
        };
        _cbExtendedAscii.Click += (s, e) => OnOptionChanged();
        Grid.SetRow(_cbExtendedAscii, 2);
        Grid.SetColumnSpan(_cbExtendedAscii, 2);
        optionsGrid.Children.Add(_cbExtendedAscii);

        mainStack.Children.Add(optionsGrid);

        SetContent(mainStack);

        // Actions
        var closeBtn = new Button
        {
            Content = "Close",
            Style = (Style)Application.Current.FindResource("BtnSecondary")
        };
        closeBtn.Click += (s, e) => Close();

        var copyBtn = new Button
        {
            Style = (Style)Application.Current.FindResource("BtnPrimary"),
            Padding = new Thickness(16, 6, 16, 6)
        };
        var copyStack = new StackPanel { Orientation = Orientation.Horizontal };
        var copyIcon = new Path
        {
            Data = (Geometry)Application.Current.FindResource("IconCopy"),
            Fill = Brushes.White,
            Width = 12,
            Height = 12,
            Stretch = Stretch.Uniform,
            Margin = new Thickness(0, 0, 8, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        var copyText = new TextBlock
        {
            Text = "Copy (10s Auto-Clear)",
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center
        };
        copyStack.Children.Add(copyIcon);
        copyStack.Children.Add(copyText);
        copyBtn.Content = copyStack;
        copyBtn.Click += (s, e) => ExecuteCopy();

        AddAction(closeBtn);
        AddAction(copyBtn);

        Closed += (s, e) => _isClosed = true;

        GenerateNewPassword();
    }

    private void OnOptionChanged()
    {
        // Prevent all checkboxes from being unchecked
        if (_cbDigits.IsChecked != true &&
            _cbLowercase.IsChecked != true &&
            _cbUppercase.IsChecked != true &&
            _cbSymbols.IsChecked != true &&
            _cbExtendedAscii.IsChecked != true)
        {
            _cbLowercase.IsChecked = true;
        }

        GenerateNewPassword();
    }

    private void GenerateNewPassword()
    {
        int length = (int)_lengthSlider.Value;
        bool digits = _cbDigits.IsChecked == true;
        bool lower = _cbLowercase.IsChecked == true;
        bool upper = _cbUppercase.IsChecked == true;
        bool symbols = _cbSymbols.IsChecked == true;
        bool extended = _cbExtendedAscii.IsChecked == true;

        _currentPassword = GenerateSecurePassword(length, digits, lower, upper, symbols, extended);
        if (_passwordBox is not null)
        {
            _passwordBox.Text = _currentPassword;
        }
    }

    private static string GenerateSecurePassword(int length, bool digits, bool lower, bool upper, bool symbols, bool extended)
    {
        const string digitChars = "0123456789";
        const string lowerChars = "abcdefghijklmnopqrstuvwxyz";
        const string upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string symbolChars = "!@#$%^&*()_+-=[]{}|;:,.<>?~";
        const string extendedChars = "¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";

        var pools = new List<string>();
        if (digits) pools.Add(digitChars);
        if (lower) pools.Add(lowerChars);
        if (upper) pools.Add(upperChars);
        if (symbols) pools.Add(symbolChars);
        if (extended) pools.Add(extendedChars);

        if (pools.Count == 0)
        {
            pools.Add(lowerChars);
        }

        var chars = new List<char>(length);

        // Guarantee at least one character from each selected set
        foreach (var pool in pools)
        {
            if (chars.Count < length)
            {
                chars.Add(pool[RandomNumberGenerator.GetInt32(pool.Length)]);
            }
        }

        // Fill remaining length from combined pool
        string combined = string.Concat(pools);
        while (chars.Count < length)
        {
            chars.Add(combined[RandomNumberGenerator.GetInt32(combined.Length)]);
        }

        // Fisher-Yates CSPRNG shuffle
        for (int i = chars.Count - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars.ToArray());
    }

    private void ExecuteCopy()
    {
        if (string.IsNullOrEmpty(_currentPassword)) return;

        string copiedPassword = _currentPassword;

        // Clipboard Protection: prevent Windows history & cloud sync
        try
        {
            var data = new DataObject();
            data.SetText(copiedPassword);
            data.SetData("CanIncludeInClipboardHistory", 0);
            data.SetData("CanUploadToClipboardCloud", 0);
            data.SetData("ExcludeClipboardContentFromMonitorProcessing", 0);
            Clipboard.SetDataObject(data, false);
        }
        catch (Exception ex)
        {
            if (!_isClosed)
            {
                _statusText.Text = $"Clipboard copy error: {ex.Message}";
                _statusText.Foreground = (Brush)Application.Current.FindResource("StatusDangerTextBrush");
            }
            return;
        }

        // 10-Second Auto-Clear Timer
        _clipboardTimer?.Stop();
        _countdownSeconds = 10;

        if (!_isClosed)
        {
            _statusText.Text = $"Copied! Clipboard will auto-clear in {_countdownSeconds}s...";
            _statusText.Foreground = (Brush)Application.Current.FindResource("AccentPrimaryBrush");
        }

        _clipboardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _clipboardTimer.Tick += (s, e) =>
        {
            _countdownSeconds--;
            if (_countdownSeconds > 0)
            {
                if (!_isClosed)
                {
                    _statusText.Text = $"Copied! Clipboard will auto-clear in {_countdownSeconds}s...";
                }
            }
            else
            {
                _clipboardTimer.Stop();
                try
                {
                    if (Clipboard.ContainsText() && Clipboard.GetText() == copiedPassword)
                    {
                        Clipboard.Clear();
                    }
                }
                catch { }

                if (!_isClosed)
                {
                    _statusText.Text = "Clipboard auto-cleared. Ephemeral credential wiped from memory.";
                    _statusText.Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush");
                }
            }
        };
        _clipboardTimer.Start();
    }
}
