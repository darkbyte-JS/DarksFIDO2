using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using DarksFIDO2.Core;

namespace DarksFIDO2.App;

internal sealed class ProfileSetupWindow : Window
{
    private readonly TextBox _name = new() { Text = "Personal" };
    private readonly PasswordBox _pin = new();
    private readonly PasswordBox _confirm = new();
    private readonly CheckBox _keyfile = new() { Content = "Require a generated master keyfile (PIN + file)", Margin = new Thickness(0, 10, 0, 6) };

    public ProfileSetupWindow(Window owner)
    {
        Owner = owner;
        Title = "Create encrypted profile";
        Width = 570;
        Height = 650;
        MinWidth = 520;
        MinHeight = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResize;
        Background = (Brush)Application.Current.Resources["WindowBrush"];
        Foreground = (Brush)Application.Current.Resources["TextBrush"];
        var panel = new StackPanel { Margin = new Thickness(30) };
        panel.Children.Add(new TextBlock { Text = "Create an isolated vault", FontSize = 28, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock { Text = "Each profile gets its own encryption key, credentials, TOTP entries, settings, and audit log.", TextWrapping = TextWrapping.Wrap, Foreground = (Brush)Application.Current.Resources["MutedBrush"], Margin = new Thickness(0, 8, 0, 24) });
        AddField(panel, "Profile name", _name);
        AddField(panel, "Master PIN or passphrase (minimum 10 characters)", _pin);
        AddField(panel, "Confirm PIN or passphrase", _confirm);
        panel.Children.Add(_keyfile);
        panel.Children.Add(new TextBlock
        {
            Text = "If enabled, you must choose a save location. Losing both the keyfile and recovery code permanently locks this vault.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.Resources["MutedBrush"],
            FontSize = 12,
            Margin = new Thickness(0, 0, 0, 22)
        });
        var buttons = new WrapPanel();
        var create = new Button { Content = "Create profile", Style = (Style)Application.Current.Resources["PrimaryButton"] };
        create.Click += (_, _) =>
        {
            if (_name.Text.Trim().Length == 0) { MessageBox.Show(this, "Enter a profile name."); return; }
            if (_pin.Password.Length < 10) { MessageBox.Show(this, "Use at least 10 characters for the PIN/passphrase."); return; }
            if (_pin.Password != _confirm.Password) { MessageBox.Show(this, "The PIN/passphrase values do not match."); return; }
            DialogResult = true;
        };
        var cancel = new Button { Content = "Cancel" };
        cancel.Click += (_, _) => DialogResult = false;
        buttons.Children.Add(create); buttons.Children.Add(cancel); panel.Children.Add(buttons);
        Dialogs.AttachSurface(this, panel);
    }

    public string ProfileName => _name.Text.Trim();
    public string Pin => _pin.Password;
    public bool UseKeyfile => _keyfile.IsChecked == true;

    private static void AddField(Panel panel, string label, Control input)
    {
        panel.Children.Add(new TextBlock { Text = label, Foreground = (Brush)Application.Current.Resources["MutedBrush"], Margin = new Thickness(0, 0, 0, 6) });
        input.Margin = new Thickness(0, 0, 0, 16);
        panel.Children.Add(input);
    }
}

internal static class Dialogs
{
    public static bool? ChooseFidoRegistration(Window owner, bool platformAvailable)
    {
        var window = Base(owner, "Register a passkey", 640, 430);
        bool? selection = null;
        var panel = new StackPanel { Margin = new Thickness(30) };
        panel.Children.Add(new TextBlock { Text = "Choose an authenticator", FontSize = 27, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock
        {
            Text = "Windows Hello is the secure built-in option when you do not own a USB key. It is a real platform FIDO2 authenticator, not a simulated USB device.",
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.Resources["MutedBrush"],
            Margin = new Thickness(0, 8, 0, 22)
        });
        var hello = new Button
        {
            Content = platformAvailable ? "Windows Hello  —  built-in passkey" : "Windows Hello  —  not configured",
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(18, 15, 18, 15),
            IsEnabled = platformAvailable
        };
        hello.Click += (_, _) => { selection = true; window.DialogResult = true; };
        var external = new Button
        {
            Content = "External security key  —  USB / NFC / BLE",
            HorizontalContentAlignment = HorizontalAlignment.Left,
            Padding = new Thickness(18, 15, 18, 15)
        };
        external.Click += (_, _) => { selection = false; window.DialogResult = true; };
        var cancel = new Button { Content = "Cancel", Margin = new Thickness(0, 14, 0, 0), HorizontalAlignment = HorizontalAlignment.Left };
        cancel.Click += (_, _) => window.DialogResult = false;
        panel.Children.Add(hello);
        panel.Children.Add(external);
        panel.Children.Add(new TextBlock
        {
            Text = "Darks FIDO2 can also be enabled as a Windows virtual passkey provider from the Passkeys & FIDO2 page. It is activated on demand by browser WebAuthn requests; no screen monitoring or virtual USB driver is used.",
            TextWrapping = TextWrapping.Wrap,
            FontSize = 12,
            Foreground = (Brush)Application.Current.Resources["MutedBrush"],
            Margin = new Thickness(0, 12, 0, 0)
        });
        panel.Children.Add(cancel);
        AttachSurface(window, panel);
        return window.ShowDialog() == true ? selection : null;
    }

    public static TotpEntry? AddTotpManual(Window owner)
    {
        var window = Base(owner, "Add TOTP account", 560, 640);
        var issuer = new TextBox();
        var account = new TextBox();
        var secret = new PasswordBox();
        var period = new ComboBox { IsEditable = true, ItemsSource = new[] { 15, 30, 60, 90, 120 }, Text = "30" };
        var digits = new ComboBox { ItemsSource = new[] { 6, 8 }, SelectedItem = 6 };
        var algorithm = new ComboBox { ItemsSource = new[] { "SHA1", "SHA256", "SHA512" }, SelectedItem = "SHA1" };
        var panel = new StackPanel { Margin = new Thickness(30) };
        panel.Children.Add(new TextBlock { Text = "Manual authenticator setup", FontSize = 27, FontWeight = FontWeights.SemiBold });
        panel.Children.Add(new TextBlock { Text = "Enter the Base32 secret and generator settings shown by the service, like KeePassXC.", TextWrapping = TextWrapping.Wrap, Foreground = (Brush)Application.Current.Resources["MutedBrush"], Margin = new Thickness(0, 8, 0, 22) });
        AddField(panel, "Issuer / service", issuer);
        AddField(panel, "Account name", account);
        AddField(panel, "Secret key (Base32)", secret);
        var settings = new Grid { Margin = new Thickness(0, 0, 0, 18) };
        settings.ColumnDefinitions.Add(new ColumnDefinition()); settings.ColumnDefinitions.Add(new ColumnDefinition()); settings.ColumnDefinitions.Add(new ColumnDefinition());
        AddCompact(settings, "Digits", digits, 0); AddCompact(settings, "Interval (seconds)", period, 1); AddCompact(settings, "Algorithm", algorithm, 2);
        panel.Children.Add(settings);
        var buttons = new WrapPanel();
        var save = new Button { Content = "Add account", Style = (Style)Application.Current.Resources["PrimaryButton"] };
        save.Click += (_, _) =>
        {
            try
            {
                if (string.IsNullOrWhiteSpace(account.Text)) throw new InvalidOperationException("Enter an account name.");
                if (account.Text.Trim().Length > 512 || issuer.Text.Trim().Length > 256) throw new InvalidOperationException("The issuer or account name is too long.");
                byte[] decoded = TotpService.DecodeBase32(secret.Password);
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(decoded);
                if (!int.TryParse(period.Text, out int seconds) || seconds is < 5 or > 300) throw new InvalidOperationException("Interval must be between 5 and 300 seconds.");
                window.Tag = new TotpEntry
                {
                    Issuer = issuer.Text.Trim(),
                    Account = account.Text.Trim(),
                    SecretBase32 = new string(secret.Password.Where(c => !char.IsWhiteSpace(c) && c != '-' && c != '=').Select(char.ToUpperInvariant).ToArray()),
                    Digits = (int)(digits.SelectedItem ?? 6),
                    Period = seconds,
                    Algorithm = Convert.ToString(algorithm.SelectedItem) ?? "SHA1"
                };
                window.DialogResult = true;
            }
            catch (Exception ex) { MessageBox.Show(window, ex.Message, "Invalid TOTP settings", MessageBoxButton.OK, MessageBoxImage.Warning); }
        };
        var cancel = new Button { Content = "Cancel" }; cancel.Click += (_, _) => window.DialogResult = false;
        buttons.Children.Add(save); buttons.Children.Add(cancel); panel.Children.Add(buttons); AttachSurface(window, panel);
        return window.ShowDialog() == true ? window.Tag as TotpEntry : null;
    }

    public static string? Prompt(Window owner, string title, string label, string initial = "", bool secret = false)
    {
        var window = Base(owner, title, 460, 240);
        var panel = new StackPanel { Margin = new Thickness(28) };
        panel.Children.Add(new TextBlock { Text = label, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });
        Control input;
        if (secret) input = new PasswordBox(); else input = new TextBox { Text = initial };
        input.Margin = new Thickness(0, 0, 0, 18);
        panel.Children.Add(input);
        var buttons = new WrapPanel();
        var ok = new Button { Content = "Continue", Style = (Style)Application.Current.Resources["PrimaryButton"] };
        ok.Click += (_, _) => window.DialogResult = true;
        var cancel = new Button { Content = "Cancel" };
        cancel.Click += (_, _) => window.DialogResult = false;
        buttons.Children.Add(ok); buttons.Children.Add(cancel); panel.Children.Add(buttons);
        AttachSurface(window, panel);
        if (window.ShowDialog() != true) return null;
        return input is PasswordBox password ? password.Password : ((TextBox)input).Text;
    }

    public static bool Confirm(Window owner, string title, string message) => MessageBox.Show(owner, message, title, MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;

    private static void AddField(Panel panel, string label, Control input)
    {
        panel.Children.Add(new TextBlock { Text = label.ToUpperInvariant(), Foreground = (Brush)Application.Current.Resources["SubtleTextBrush"], FontWeight = FontWeights.SemiBold, FontSize = 11, Margin = new Thickness(0, 0, 0, 7) });
        input.Margin = new Thickness(0, 0, 0, 14);
        panel.Children.Add(input);
    }

    private static void AddCompact(Grid grid, string label, Control input, int column)
    {
        var panel = new StackPanel { Margin = new Thickness(0, 0, column < 2 ? 10 : 0, 0) };
        panel.Children.Add(new TextBlock { Text = label.ToUpperInvariant(), Foreground = (Brush)Application.Current.Resources["SubtleTextBrush"], Margin = new Thickness(0, 0, 0, 7), FontWeight = FontWeights.SemiBold, FontSize = 10 });
        panel.Children.Add(input);
        Grid.SetColumn(panel, column);
        grid.Children.Add(panel);
    }

    internal static void AttachSurface(Window window, UIElement content)
    {
        var scroll = new ScrollViewer
        {
            Content = content,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
        };
        window.Content = new Border
        {
            Style = (Style)Application.Current.Resources["CardStyle"],
            Margin = new Thickness(16),
            Padding = new Thickness(0),
            Child = scroll
        };
    }

    private static Window Base(Window owner, string title, double width, double height) => new()
    {
        Owner = owner,
        Title = title,
        Width = width,
        Height = height,
        MinWidth = Math.Min(width, 440),
        MinHeight = Math.Min(height, 220),
        WindowStartupLocation = WindowStartupLocation.CenterOwner,
        ResizeMode = ResizeMode.CanResize,
        ShowInTaskbar = false,
        UseLayoutRounding = true,
        Background = (Brush)Application.Current.Resources["WindowBrush"],
        Foreground = (Brush)Application.Current.Resources["TextBrush"]
    };
}
