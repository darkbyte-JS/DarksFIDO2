using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace DarksFIDO2.App.Controls;

public partial class PinBox : UserControl
{
    private bool _isRevealed = false;

    public event Action? PasswordChanged;
    public event KeyEventHandler? PinKeyDown;

    public PinBox()
    {
        InitializeComponent();

        MaskedBox.PasswordChanged += (s, e) =>
        {
            if (!_isRevealed) PasswordChanged?.Invoke();
        };

        PlainBox.TextChanged += (s, e) =>
        {
            if (_isRevealed) PasswordChanged?.Invoke();
        };

        ToggleBtn.Click += OnToggleClick;

        MaskedBox.KeyDown += (s, e) => PinKeyDown?.Invoke(s, e);
        PlainBox.KeyDown += (s, e) => PinKeyDown?.Invoke(s, e);
    }

    public string Password
    {
        get => _isRevealed ? PlainBox.Text : MaskedBox.Password;
        set
        {
            MaskedBox.Password = value;
            PlainBox.Text = value;
        }
    }

    public void FocusInput()
    {
        if (_isRevealed) PlainBox.Focus();
        else MaskedBox.Focus();
    }

    public void Clear()
    {
        MaskedBox.Password = string.Empty;
        PlainBox.Text = string.Empty;
    }

    private void OnToggleClick(object sender, RoutedEventArgs e)
    {
        _isRevealed = !_isRevealed;

        if (_isRevealed)
        {
            PlainBox.Text = MaskedBox.Password;
            MaskedBox.Visibility = Visibility.Collapsed;
            PlainBox.Visibility = Visibility.Visible;
            ToggleIcon.Data = (Geometry)Application.Current.FindResource("IconEyeOff");
            PlainBox.Focus();
            PlainBox.CaretIndex = PlainBox.Text.Length;
        }
        else
        {
            MaskedBox.Password = PlainBox.Text;
            PlainBox.Visibility = Visibility.Collapsed;
            MaskedBox.Visibility = Visibility.Visible;
            ToggleIcon.Data = (Geometry)Application.Current.FindResource("IconEye");
            MaskedBox.Focus();
        }
    }
}
