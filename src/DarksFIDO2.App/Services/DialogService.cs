using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using DarksFIDO2.App.Dialogs;
using DarksFIDO2.Core;

namespace DarksFIDO2.App.Services;

public interface IDialogService
{
    void ShowAlert(string message, string title = "Information");
    void ShowError(string message, string title = "Error");
    bool ShowConfirm(string message, string title = "Confirmation", string confirmText = "Confirm", bool isDestructive = false);
    string? ShowPrompt(string message, string title = "Input Required", string defaultValue = "");
    string? ShowPromptSecret(string message, string title = "Master PIN Required");
    ProfileCreationRequest? ShowCreateProfileDialog();
    TotpEntry? ShowAddTotpManual();
    (string RpId, string UserName, string DisplayName, bool UsePlatform)? ShowCreatePasskeyDialog();
    void ShowPasswordGenerator();
}

public sealed class DialogService : IDialogService
{
    public void ShowAlert(string message, string title = "Information")
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, title, null, 420);
        var text = new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            FontSize = 13,
            LineHeight = 20
        };
        win.SetContent(text);

        var okBtn = new Button { Content = "OK", Style = (Style)Application.Current.FindResource("BtnPrimary") };
        okBtn.Click += (s, e) => { win.DialogResult = true; win.Close(); };
        win.AddAction(okBtn);
        win.ShowDialog();
    }

    public void ShowError(string message, string title = "Error")
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, title, "An error occurred during operation", 440);
        var panel = new StackPanel();

        var text = new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.FindResource("StatusDangerTextBrush"),
            FontSize = 13,
            LineHeight = 20
        };
        panel.Children.Add(text);
        win.SetContent(panel);

        var okBtn = new Button { Content = "Dismiss", Style = (Style)Application.Current.FindResource("BtnSecondary") };
        okBtn.Click += (s, e) => { win.DialogResult = true; win.Close(); };
        win.AddAction(okBtn);
        win.ShowDialog();
    }

    public bool ShowConfirm(string message, string title = "Confirmation", string confirmText = "Confirm", bool isDestructive = false)
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, title, null, 440);
        var text = new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            FontSize = 13,
            LineHeight = 20
        };
        win.SetContent(text);

        var cancelBtn = new Button { Content = "Cancel", Style = (Style)Application.Current.FindResource("BtnSecondary") };
        cancelBtn.Click += (s, e) => { win.DialogResult = false; win.Close(); };

        var confirmBtn = new Button
        {
            Content = confirmText,
            Style = (Style)Application.Current.FindResource(isDestructive ? "BtnDanger" : "BtnPrimary")
        };
        confirmBtn.Click += (s, e) => { win.DialogResult = true; win.Close(); };

        win.AddAction(cancelBtn);
        win.AddAction(confirmBtn);

        return win.ShowDialog() == true;
    }

    public string? ShowPrompt(string message, string title = "Input Required", string defaultValue = "")
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, title, null, 440);
        var panel = new StackPanel();

        var label = new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 10)
        };
        panel.Children.Add(label);

        var input = new TextBox
        {
            Text = defaultValue,
            Style = (Style)Application.Current.FindResource("StandardTextBox")
        };
        panel.Children.Add(input);
        win.SetContent(panel);

        var cancelBtn = new Button { Content = "Cancel", Style = (Style)Application.Current.FindResource("BtnSecondary") };
        cancelBtn.Click += (s, e) => { win.DialogResult = false; win.Close(); };

        var submitBtn = new Button { Content = "Continue", Style = (Style)Application.Current.FindResource("BtnPrimary") };
        submitBtn.Click += (s, e) => { win.DialogResult = true; win.Close(); };

        input.KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) { win.DialogResult = true; win.Close(); }
        };

        win.AddAction(cancelBtn);
        win.AddAction(submitBtn);

        input.Focus();
        input.SelectAll();

        return win.ShowDialog() == true ? input.Text.Trim() : null;
    }

    public string? ShowPromptSecret(string message, string title = "Master PIN Required")
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, title, null, 440);
        var panel = new StackPanel();

        var label = new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 10)
        };
        panel.Children.Add(label);

        var pinBox = new PasswordBox
        {
            Height = 32,
            Background = (Brush)Application.Current.FindResource("AppBackgroundBrush"),
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            BorderBrush = (Brush)Application.Current.FindResource("BorderStrongBrush"),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4)
        };
        panel.Children.Add(pinBox);
        win.SetContent(panel);

        var cancelBtn = new Button { Content = "Cancel", Style = (Style)Application.Current.FindResource("BtnSecondary") };
        cancelBtn.Click += (s, e) => { win.DialogResult = false; win.Close(); };

        var submitBtn = new Button { Content = "Unlock", Style = (Style)Application.Current.FindResource("BtnPrimary") };
        submitBtn.Click += (s, e) => { win.DialogResult = true; win.Close(); };

        pinBox.KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) { win.DialogResult = true; win.Close(); }
        };

        win.AddAction(cancelBtn);
        win.AddAction(submitBtn);

        pinBox.Focus();

        return win.ShowDialog() == true ? pinBox.Password : null;
    }

    public ProfileCreationRequest? ShowCreateProfileDialog()
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, "Create Encrypted Profile", "Isolate passkeys and credentials under a new master secret.", 480);
        var form = new StackPanel();

        form.Children.Add(CreateFieldLabel("PROFILE NAME"));
        var nameInput = new TextBox { Text = "Personal", Style = (Style)Application.Current.FindResource("StandardTextBox"), Margin = new Thickness(0, 0, 0, 12) };
        form.Children.Add(nameInput);

        form.Children.Add(CreateFieldLabel("MASTER PIN / PASSPHRASE (MIN 6 CHARACTERS)"));
        var pinInput = new PasswordBox
        {
            Height = 32,
            Background = (Brush)Application.Current.FindResource("AppBackgroundBrush"),
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            BorderBrush = (Brush)Application.Current.FindResource("BorderStrongBrush"),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            Margin = new Thickness(0, 0, 0, 12)
        };
        form.Children.Add(pinInput);

        form.Children.Add(CreateFieldLabel("CONFIRM MASTER PIN"));
        var confirmPinInput = new PasswordBox
        {
            Height = 32,
            Background = (Brush)Application.Current.FindResource("AppBackgroundBrush"),
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            BorderBrush = (Brush)Application.Current.FindResource("BorderStrongBrush"),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(8, 4, 8, 4),
            Margin = new Thickness(0, 0, 0, 14)
        };
        form.Children.Add(confirmPinInput);

        var keyfileCheck = new CheckBox
        {
            Content = "Generate companion keyfile (.dfkey) for Dual-Factor authorization",
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            Margin = new Thickness(0, 0, 0, 16)
        };
        form.Children.Add(keyfileCheck);

        win.SetContent(form);

        var cancelBtn = new Button { Content = "Cancel", Style = (Style)Application.Current.FindResource("BtnSecondary") };
        cancelBtn.Click += (s, e) => { win.DialogResult = false; win.Close(); };

        ProfileCreationRequest? result = null;

        var createBtn = new Button { Content = "Create Vault", Style = (Style)Application.Current.FindResource("BtnPrimary") };
        createBtn.Click += (s, e) =>
        {
            string name = nameInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(name))
            {
                ShowAlert("Profile name cannot be empty.", "Validation Error");
                return;
            }
            if (pinInput.Password.Length < 6)
            {
                ShowAlert("Master PIN must be at least 6 characters long.", "Validation Error");
                return;
            }
            if (pinInput.Password != confirmPinInput.Password)
            {
                ShowAlert("The confirmation PIN does not match.", "Validation Error");
                return;
            }

            byte[]? keyfile = keyfileCheck.IsChecked == true ? RandomNumberGenerator.GetBytes(64) : null;
            result = new ProfileCreationRequest(name, pinInput.Password, keyfile);
            win.DialogResult = true;
            win.Close();
        };

        win.AddAction(cancelBtn);
        win.AddAction(createBtn);

        return win.ShowDialog() == true ? result : null;
    }

    public TotpEntry? ShowAddTotpManual()
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, "Add TOTP Account", "Manually configure a time-based one-time password authenticator.", 480);
        var form = new StackPanel();

        form.Children.Add(CreateFieldLabel("ISSUER / SERVICE (E.G. GITHUB, GOOGLE)"));
        var issuerInput = new TextBox { Style = (Style)Application.Current.FindResource("StandardTextBox"), Margin = new Thickness(0, 0, 0, 12) };
        form.Children.Add(issuerInput);

        form.Children.Add(CreateFieldLabel("ACCOUNT NAME (E.G. USER@EXAMPLE.COM)"));
        var accountInput = new TextBox { Style = (Style)Application.Current.FindResource("StandardTextBox"), Margin = new Thickness(0, 0, 0, 12) };
        form.Children.Add(accountInput);

        form.Children.Add(CreateFieldLabel("SECRET KEY (BASE32)"));
        var secretInput = new TextBox { Style = (Style)Application.Current.FindResource("StandardTextBox"), Margin = new Thickness(0, 0, 0, 14) };
        form.Children.Add(secretInput);

        win.SetContent(form);

        var cancelBtn = new Button { Content = "Cancel", Style = (Style)Application.Current.FindResource("BtnSecondary") };
        cancelBtn.Click += (s, e) => { win.DialogResult = false; win.Close(); };

        TotpEntry? result = null;

        var addBtn = new Button { Content = "Add Account", Style = (Style)Application.Current.FindResource("BtnPrimary") };
        addBtn.Click += (s, e) =>
        {
            string secret = secretInput.Text.Trim().Replace(" ", "").ToUpperInvariant();
            if (string.IsNullOrWhiteSpace(secret))
            {
                ShowAlert("Base32 secret key cannot be empty.", "Validation Error");
                return;
            }

            string account = string.IsNullOrWhiteSpace(accountInput.Text) ? "Account" : accountInput.Text.Trim();
            string issuer = issuerInput.Text.Trim();

            try
            {
                var entry = new TotpEntry
                {
                    Issuer = issuer,
                    Account = account,
                    SecretBase32 = secret,
                    Digits = 6,
                    Period = 30,
                    Algorithm = "SHA1"
                };
                _ = TotpService.GetCode(entry);
                result = entry;
                win.DialogResult = true;
                win.Close();
            }
            catch (Exception ex)
            {
                ShowAlert($"Invalid Base32 secret key: {ex.Message}", "Invalid Secret");
            }
        };

        win.AddAction(cancelBtn);
        win.AddAction(addBtn);

        return win.ShowDialog() == true ? result : null;
    }

    public (string RpId, string UserName, string DisplayName, bool UsePlatform)? ShowCreatePasskeyDialog()
    {
        var win = new ModernModalWindow(Application.Current.MainWindow, "Register WebAuthn Passkey", "Register a passkey using Windows Hello or software cryptography.", 500);
        var form = new StackPanel();

        form.Children.Add(CreateFieldLabel("RELYING PARTY DOMAIN (RP ID)"));
        var rpInput = new TextBox { Text = "darksfido2.local", Style = (Style)Application.Current.FindResource("StandardTextBox"), Margin = new Thickness(0, 0, 0, 12) };
        form.Children.Add(rpInput);

        form.Children.Add(CreateFieldLabel("USER NAME"));
        var userInput = new TextBox { Text = Environment.UserName, Style = (Style)Application.Current.FindResource("StandardTextBox"), Margin = new Thickness(0, 0, 0, 12) };
        form.Children.Add(userInput);

        form.Children.Add(CreateFieldLabel("DISPLAY NAME"));
        var displayInput = new TextBox { Text = $"{Environment.UserName} Passkey", Style = (Style)Application.Current.FindResource("StandardTextBox"), Margin = new Thickness(0, 0, 0, 14) };
        form.Children.Add(displayInput);

        var platformRadio = new RadioButton
        {
            Content = "Windows Hello Platform Authenticator (TPM-backed biometric/PIN)",
            IsChecked = true,
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            Margin = new Thickness(0, 0, 0, 8)
        };
        var softwareRadio = new RadioButton
        {
            Content = "Software Passkey (Encrypted inside active profile vault)",
            Foreground = (Brush)Application.Current.FindResource("TextPrimaryBrush"),
            Margin = new Thickness(0, 0, 0, 16)
        };
        form.Children.Add(platformRadio);
        form.Children.Add(softwareRadio);

        win.SetContent(form);

        var cancelBtn = new Button { Content = "Cancel", Style = (Style)Application.Current.FindResource("BtnSecondary") };
        cancelBtn.Click += (s, e) => { win.DialogResult = false; win.Close(); };

        (string RpId, string UserName, string DisplayName, bool UsePlatform)? result = null;

        var regBtn = new Button { Content = "Begin Registration", Style = (Style)Application.Current.FindResource("BtnPrimary") };
        regBtn.Click += (s, e) =>
        {
            string rp = rpInput.Text.Trim();
            if (string.IsNullOrWhiteSpace(rp))
            {
                ShowAlert("Relying party ID cannot be empty.", "Validation Error");
                return;
            }
            result = (rp, userInput.Text.Trim(), displayInput.Text.Trim(), platformRadio.IsChecked == true);
            win.DialogResult = true;
            win.Close();
        };

        win.AddAction(cancelBtn);
        win.AddAction(regBtn);

        return win.ShowDialog() == true ? result : null;
    }

    public void ShowPasswordGenerator()
    {
        var win = new PasswordGeneratorDialog(Application.Current.MainWindow);
        win.ShowDialog();
    }

    private static TextBlock CreateFieldLabel(string text)
    {
        return new TextBlock
        {
            Text = text,
            FontFamily = (FontFamily)Application.Current.FindResource("FontPrimary"),
            FontSize = 11,
            FontWeight = FontWeights.SemiBold,
            Foreground = (Brush)Application.Current.FindResource("TextSecondaryBrush"),
            Margin = new Thickness(0, 0, 0, 4)
        };
    }
}
