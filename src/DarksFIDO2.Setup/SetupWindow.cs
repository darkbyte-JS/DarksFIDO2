using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using IOPath = System.IO.Path;

namespace DarksFIDO2.Setup;

public class SetupWindow : Window
{
    // Neumorphic Color Palette
    private static readonly Color BgColor = Color.FromRgb(0x13, 0x16, 0x22);          // Deep matte canvas
    private static readonly Color CardBgStart = Color.FromRgb(0x1B, 0x1F, 0x2E);      // Extruded card top
    private static readonly Color CardBgEnd = Color.FromRgb(0x15, 0x18, 0x26);        // Extruded card bottom
    private static readonly Color WellBg = Color.FromRgb(0x0C, 0x0E, 0x15);           // Sunken track well
    private static readonly Color HighlightBorder = Color.FromRgb(0x2D, 0x36, 0x4D);  // Top-left light reflection
    private static readonly Color ShadowBorder = Color.FromRgb(0x0A, 0x0C, 0x12);     // Bottom-right shadow edge
    private static readonly Color AccentCyan = Color.FromRgb(0x00, 0xD2, 0xFF);       // Neon cyan accent
    private static readonly Color AccentPurple = Color.FromRgb(0x7C, 0x3A, 0xED);     // Indigo accent
    private static readonly Color TextWhite = Color.FromRgb(0xF3, 0xF6, 0xFC);        // High-contrast text
    private static readonly Color TextMuted = Color.FromRgb(0x94, 0xA3, 0xB8);        // Subtle secondary text
    private static readonly Color SuccessGreen = Color.FromRgb(0x10, 0xB9, 0x81);     // Active status green
    private static readonly Color DangerRed = Color.FromRgb(0xF4, 0x3F, 0x5E);        // Error red

    // Wizard Stages
    private readonly Grid _optionsPage;
    private readonly Grid _progressPage;
    private readonly Grid _completePage;
    private readonly Grid _errorPage;

    // Wizard Step Pills
    private readonly Border _step1Pill;
    private readonly Border _step2Pill;
    private readonly Border _step3Pill;

    // Controls - Options Page
    private readonly TextBox _pathBox;
    private readonly TextBlock _spaceText;
    private readonly CheckBox _desktopShortcutCheck;
    private readonly CheckBox _startMenuShortcutCheck;
    private readonly CheckBox _trustCertCheck;
    private readonly CheckBox _launchCheck;

    // Controls - Progress Page
    private readonly TextBlock _progressStatus;
    private readonly ProgressBar _progressBar;
    private readonly TextBlock _percentText;
    private readonly TextBox _logBox;

    // Controls - Error Page
    private readonly TextBox _errorDetails;

    // Footer Buttons
    private readonly Button _cancelButton;
    private readonly Button _installButton;
    private readonly Button _finishButton;
    private readonly Button _retryButton;

    public string SelectedInstallDirectory { get; private set; }
    public bool LaunchAfterInstall { get; private set; } = true;

    public SetupWindow(string defaultInstallDirectory)
    {
        SelectedInstallDirectory = defaultInstallDirectory;

        // Window Chrome & Styling
        Title = "Darks FIDO2 Setup";
        Width = 640;
        Height = 540;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        WindowStyle = WindowStyle.None;
        AllowsTransparency = true;
        Background = Brushes.Transparent;
        FontFamily = new FontFamily("Segoe UI Variable Text, Segoe UI, sans-serif");
        FontSize = 13;

        // Outer Root Window with Neumorphic Drop Shadow
        var outerBorder = new Border
        {
            CornerRadius = new CornerRadius(20),
            Background = new SolidColorBrush(BgColor),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1.2),
            Margin = new Thickness(16),
            Effect = new DropShadowEffect
            {
                Color = Colors.Black,
                BlurRadius = 26,
                Direction = 315,
                ShadowDepth = 8,
                Opacity = 0.65
            }
        };

        var mainLayout = new Grid();
        mainLayout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(68, GridUnitType.Pixel) }); // Header / TitleBar
        mainLayout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(42, GridUnitType.Pixel) }); // Step Pills
        mainLayout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });   // Body Content
        mainLayout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(64, GridUnitType.Pixel) }); // Footer Actions

        // ==========================================
        // 1. DRAGGABLE TITLE BAR & BRAND HEADER
        // ==========================================
        var titleBar = new Border
        {
            Background = Brushes.Transparent,
            Padding = new Thickness(24, 16, 20, 0),
            CornerRadius = new CornerRadius(20, 20, 0, 0)
        };
        titleBar.MouseLeftButtonDown += (_, e) =>
        {
            if (e.ButtonState == MouseButtonState.Pressed) DragMove();
        };

        var titleGrid = new Grid();
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        titleGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        // Brand Icon Plate (Sculpted Neumorphic Tile)
        var iconPlate = new Border
        {
            Width = 38,
            Height = 38,
            CornerRadius = new CornerRadius(11),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1),
            Effect = CreateNeumorphicShadow(4, 2, 0.4)
        };
        var shieldPath = CreateVectorIcon(
            "M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z",
            new SolidColorBrush(AccentCyan), 18, 18);
        iconPlate.Child = shieldPath;
        Grid.SetColumn(iconPlate, 0);
        titleGrid.Children.Add(iconPlate);

        // App Titles
        var titleStack = new StackPanel
        {
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(14, 0, 0, 0)
        };
        var appTitle = new TextBlock
        {
            Text = "Darks FIDO2",
            FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI"),
            FontWeight = FontWeights.SemiBold,
            FontSize = 17,
            Foreground = new SolidColorBrush(TextWhite)
        };
        var appSub = new TextBlock
        {
            Text = "PASSKEY & HARDWARE VAULT SETUP · v0.6.4",
            FontWeight = FontWeights.Bold,
            FontSize = 10,
            Foreground = new SolidColorBrush(AccentCyan),
            Margin = new Thickness(0, 2, 0, 0)
        };
        titleStack.Children.Add(appTitle);
        titleStack.Children.Add(appSub);
        Grid.SetColumn(titleStack, 1);
        titleGrid.Children.Add(titleStack);

        // Close Window Button
        var closeBtn = CreateIconButton(
            "M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z",
            () => Close());
        Grid.SetColumn(closeBtn, 2);
        titleGrid.Children.Add(closeBtn);

        titleBar.Child = titleGrid;
        Grid.SetRow(titleBar, 0);
        mainLayout.Children.Add(titleBar);

        // ==========================================
        // 2. STEP INDICATOR PILLS
        // ==========================================
        var stepRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Margin = new Thickness(24, 6, 24, 0)
        };
        _step1Pill = CreateStepPill("1. Destination & Options", isActive: true);
        _step2Pill = CreateStepPill("2. Installation", isActive: false);
        _step3Pill = CreateStepPill("3. Finished", isActive: false);
        stepRow.Children.Add(_step1Pill);
        stepRow.Children.Add(_step2Pill);
        stepRow.Children.Add(_step3Pill);
        Grid.SetRow(stepRow, 1);
        mainLayout.Children.Add(stepRow);

        // ==========================================
        // 3. BODY STAGE CONTAINER
        // ==========================================
        var bodyContainer = new Grid { Margin = new Thickness(24, 10, 24, 10) };
        Grid.SetRow(bodyContainer, 2);
        mainLayout.Children.Add(bodyContainer);

        // ---------------- PAGE 1: OPTIONS ----------------
        _optionsPage = new Grid();
        var optStack = new StackPanel();

        // Installation Path Group in a Sunken Well
        var pathGroup = new Border
        {
            CornerRadius = new CornerRadius(14),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(18, 14, 18, 14),
            Margin = new Thickness(0, 0, 0, 14),
            Effect = CreateNeumorphicShadow(10, 3, 0.3)
        };
        var pathLayout = new StackPanel();
        var pathHeader = new TextBlock
        {
            Text = "INSTALLATION DIRECTORY",
            FontSize = 10.5,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(TextMuted),
            Margin = new Thickness(0, 0, 0, 8)
        };
        pathLayout.Children.Add(pathHeader);

        // Sunken Track for Path Input
        var sunkenTrack = new Border
        {
            CornerRadius = new CornerRadius(10),
            Background = new SolidColorBrush(WellBg),
            BorderBrush = new SolidColorBrush(ShadowBorder),
            BorderThickness = new Thickness(1.2),
            Padding = new Thickness(12, 4, 6, 4)
        };
        var pathRow = new Grid();
        pathRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        pathRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _pathBox = new TextBox
        {
            Text = defaultInstallDirectory,
            Foreground = new SolidColorBrush(TextWhite),
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            FontSize = 12.5,
            VerticalAlignment = VerticalAlignment.Center
        };
        _pathBox.TextChanged += (_, _) => UpdateSpace();
        Grid.SetColumn(_pathBox, 0);
        pathRow.Children.Add(_pathBox);

        var browseButton = CreateNeumorphicButton("Browse…", OnBrowseClicked, width: 85, height: 32);
        browseButton.Margin = new Thickness(6, 0, 0, 0);
        Grid.SetColumn(browseButton, 1);
        pathRow.Children.Add(browseButton);

        sunkenTrack.Child = pathRow;
        pathLayout.Children.Add(sunkenTrack);

        _spaceText = new TextBlock
        {
            Text = "At least 350 MB required. " + GetSpace(defaultInstallDirectory),
            FontSize = 11,
            Foreground = new SolidColorBrush(SuccessGreen),
            Margin = new Thickness(2, 8, 0, 0)
        };
        pathLayout.Children.Add(_spaceText);
        pathGroup.Child = pathLayout;
        optStack.Children.Add(pathGroup);

        // Configuration Checkbox Card
        var configCard = new Border
        {
            CornerRadius = new CornerRadius(14),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(18, 14, 18, 14),
            Effect = CreateNeumorphicShadow(10, 3, 0.3)
        };
        var checkStack = new StackPanel();

        var checkHeader = new TextBlock
        {
            Text = "DEPLOYMENT PREFERENCES",
            FontSize = 10.5,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(TextMuted),
            Margin = new Thickness(0, 0, 0, 10)
        };
        checkStack.Children.Add(checkHeader);

        _desktopShortcutCheck = CreateNeumorphicCheckBox("Create desktop shortcut icon", isChecked: true);
        checkStack.Children.Add(_desktopShortcutCheck);

        _startMenuShortcutCheck = CreateNeumorphicCheckBox("Create Start Menu folder and shortcut", isChecked: true);
        checkStack.Children.Add(_startMenuShortcutCheck);

        _trustCertCheck = CreateNeumorphicCheckBox("Register certificate into Trusted People (optional, for test/dev builds)", isChecked: false);
        checkStack.Children.Add(_trustCertCheck);

        _launchCheck = CreateNeumorphicCheckBox("Launch Darks FIDO2 immediately after installation", isChecked: true);
        checkStack.Children.Add(_launchCheck);

        configCard.Child = checkStack;
        optStack.Children.Add(configCard);

        _optionsPage.Children.Add(optStack);
        bodyContainer.Children.Add(_optionsPage);

        // ---------------- PAGE 2: PROGRESS ----------------
        _progressPage = new Grid { Visibility = Visibility.Collapsed };
        var progStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };

        var progressCard = new Border
        {
            CornerRadius = new CornerRadius(16),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(22),
            Effect = CreateNeumorphicShadow(12, 4, 0.4)
        };
        var progInner = new StackPanel();

        var progHeaderRow = new Grid { Margin = new Thickness(0, 0, 0, 12) };
        progHeaderRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        progHeaderRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        _progressStatus = new TextBlock
        {
            Text = "Preparing installation package…",
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(TextWhite)
        };
        Grid.SetColumn(_progressStatus, 0);
        progHeaderRow.Children.Add(_progressStatus);

        _percentText = new TextBlock
        {
            Text = "0%",
            FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI"),
            FontSize = 16,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(AccentCyan)
        };
        Grid.SetColumn(_percentText, 1);
        progHeaderRow.Children.Add(_percentText);
        progInner.Children.Add(progHeaderRow);

        // Sunken Progress Well
        var progressTrack = new Border
        {
            Height = 10,
            CornerRadius = new CornerRadius(99),
            Background = new SolidColorBrush(WellBg),
            BorderBrush = new SolidColorBrush(ShadowBorder),
            BorderThickness = new Thickness(1),
            Margin = new Thickness(0, 0, 0, 16),
            ClipToBounds = true
        };
        _progressBar = new ProgressBar
        {
            Height = 10,
            Minimum = 0,
            Maximum = 100,
            Value = 0,
            Foreground = new SolidColorBrush(AccentCyan),
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0)
        };
        progressTrack.Child = _progressBar;
        progInner.Children.Add(progressTrack);

        // Sunken Terminal Log
        var logBorder = new Border
        {
            Height = 160,
            CornerRadius = new CornerRadius(10),
            Background = new SolidColorBrush(WellBg),
            BorderBrush = new SolidColorBrush(ShadowBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(10)
        };
        _logBox = new TextBox
        {
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush(Color.FromRgb(0x4A, 0xDE, 0x80)), // Terminal green
            BorderThickness = new Thickness(0),
            IsReadOnly = true,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            FontFamily = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize = 11
        };
        logBorder.Child = _logBox;
        progInner.Children.Add(logBorder);

        progressCard.Child = progInner;
        progStack.Children.Add(progressCard);
        _progressPage.Children.Add(progStack);
        bodyContainer.Children.Add(_progressPage);

        // ---------------- PAGE 3: COMPLETE ----------------
        _completePage = new Grid { Visibility = Visibility.Collapsed };
        var compStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };

        var compCard = new Border
        {
            CornerRadius = new CornerRadius(16),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(28),
            Effect = CreateNeumorphicShadow(12, 4, 0.4)
        };
        var compInner = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };

        var checkIconBorder = new Border
        {
            Width = 56,
            Height = 56,
            CornerRadius = new CornerRadius(18),
            Background = new SolidColorBrush(Color.FromArgb(0x28, 0x10, 0xB9, 0x81)),
            BorderBrush = new SolidColorBrush(SuccessGreen),
            BorderThickness = new Thickness(1.5),
            Margin = new Thickness(0, 0, 0, 16)
        };
        checkIconBorder.Child = CreateVectorIcon(
            "M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z",
            new SolidColorBrush(SuccessGreen), 26, 26);
        compInner.Children.Add(checkIconBorder);

        var compTitle = new TextBlock
        {
            Text = "Installation Complete",
            FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI"),
            FontSize = 22,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(TextWhite),
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 0, 0, 6)
        };
        compInner.Children.Add(compTitle);

        var compDesc = new TextBlock
        {
            Text = "Darks FIDO2 has been installed successfully.\nThe virtual passkey provider companion is registered and ready for Windows WebAuthn.",
            Foreground = new SolidColorBrush(TextMuted),
            FontSize = 13,
            TextAlignment = TextAlignment.Center,
            LineHeight = 20,
            Margin = new Thickness(0, 0, 0, 16)
        };
        compInner.Children.Add(compDesc);

        compCard.Child = compInner;
        compStack.Children.Add(compCard);
        _completePage.Children.Add(compStack);
        bodyContainer.Children.Add(_completePage);

        // ---------------- PAGE 4: ERROR ----------------
        _errorPage = new Grid { Visibility = Visibility.Collapsed };
        var errStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };

        var errCard = new Border
        {
            CornerRadius = new CornerRadius(16),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(DangerRed),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(22),
            Effect = CreateNeumorphicShadow(12, 4, 0.4)
        };
        var errInner = new StackPanel();

        var errHeaderRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
        var errIcon = CreateVectorIcon(
            "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z",
            new SolidColorBrush(DangerRed), 22, 22);
        errHeaderRow.Children.Add(errIcon);

        var errTitle = new TextBlock
        {
            Text = "Installation Stopped",
            FontFamily = new FontFamily("Segoe UI Variable Display, Segoe UI"),
            FontSize = 16,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(DangerRed),
            Margin = new Thickness(10, 0, 0, 0),
            VerticalAlignment = VerticalAlignment.Center
        };
        errHeaderRow.Children.Add(errTitle);
        errInner.Children.Add(errHeaderRow);

        var errSunken = new Border
        {
            Height = 160,
            CornerRadius = new CornerRadius(10),
            Background = new SolidColorBrush(WellBg),
            BorderBrush = new SolidColorBrush(ShadowBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(10)
        };
        _errorDetails = new TextBox
        {
            Background = Brushes.Transparent,
            Foreground = new SolidColorBrush(TextWhite),
            BorderThickness = new Thickness(0),
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            FontFamily = new FontFamily("Consolas, monospace"),
            FontSize = 11.5
        };
        errSunken.Child = _errorDetails;
        errInner.Children.Add(errSunken);

        errCard.Child = errInner;
        errStack.Children.Add(errCard);
        _errorPage.Children.Add(errStack);
        bodyContainer.Children.Add(_errorPage);

        // ==========================================
        // 4. FOOTER CONTROLS
        // ==========================================
        var footerBorder = new Border
        {
            Padding = new Thickness(24, 0, 24, 18),
            Background = Brushes.Transparent
        };
        var footerStack = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            VerticalAlignment = VerticalAlignment.Center
        };

        _cancelButton = CreateNeumorphicButton("Cancel", () => Close(), width: 95, height: 38);
        _cancelButton.Margin = new Thickness(0, 0, 10, 0);
        footerStack.Children.Add(_cancelButton);

        _retryButton = CreateNeumorphicButton("Retry", () => OnInstallClicked(this, new RoutedEventArgs()), width: 95, height: 38);
        _retryButton.Margin = new Thickness(0, 0, 10, 0);
        _retryButton.Visibility = Visibility.Collapsed;
        footerStack.Children.Add(_retryButton);

        _installButton = CreatePrimaryButton("Install Now", (s, e) => OnInstallClicked(s, e), width: 130, height: 38);
        footerStack.Children.Add(_installButton);

        _finishButton = CreatePrimaryButton("Finish", (_, _) =>
        {
            DialogResult = true;
            Close();
        }, width: 130, height: 38);
        _finishButton.Visibility = Visibility.Collapsed;
        footerStack.Children.Add(_finishButton);

        footerBorder.Child = footerStack;
        Grid.SetRow(footerBorder, 3);
        mainLayout.Children.Add(footerBorder);

        outerBorder.Child = mainLayout;
        Content = outerBorder;
    }

    private void UpdateSpace()
    {
        try { _spaceText.Text = "At least 350 MB required. " + GetSpace(_pathBox.Text); } catch { }
    }

    private static string GetSpace(string path)
    {
        try
        {
            string root = IOPath.GetPathRoot(IOPath.GetFullPath(path)) ?? "C:\\";
            var drive = new DriveInfo(root);
            double gb = (double)drive.AvailableFreeSpace / (1024 * 1024 * 1024);
            return $"{gb:0.0} GB free on ({root.TrimEnd('\\')})";
        }
        catch { return ""; }
    }

    private void OnBrowseClicked(object sender, RoutedEventArgs e)
    {
        try
        {
            var dlg = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Destination Location",
                InitialDirectory = Directory.Exists(_pathBox.Text) ? _pathBox.Text : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
            };
            if (dlg.ShowDialog(this) == true)
            {
                _pathBox.Text = IOPath.Combine(dlg.FolderName, "DarksFIDO2");
            }
        }
        catch { }
    }

    private async void OnInstallClicked(object sender, RoutedEventArgs e)
    {
        string targetDir = _pathBox.Text.Trim();
        bool createDesktop = _desktopShortcutCheck.IsChecked == true;
        bool createStartMenu = _startMenuShortcutCheck.IsChecked == true;
        bool trustCert = _trustCertCheck.IsChecked == true;
        bool launchOnFinish = _launchCheck.IsChecked == true;

        if (string.IsNullOrWhiteSpace(targetDir))
        {
            MessageBox.Show(this, "Please enter a destination path.", "Setup", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SelectedInstallDirectory = targetDir;
        LaunchAfterInstall = launchOnFinish;

        // Switch to Step 2
        UpdatePill(_step1Pill, false);
        UpdatePill(_step2Pill, true);
        _optionsPage.Visibility = Visibility.Collapsed;
        _errorPage.Visibility = Visibility.Collapsed;
        _progressPage.Visibility = Visibility.Visible;
        _installButton.Visibility = Visibility.Collapsed;
        _retryButton.Visibility = Visibility.Collapsed;
        _cancelButton.IsEnabled = false;

        void Report(int pct, string msg)
        {
            Dispatcher.Invoke(() =>
            {
                _progressBar.Value = pct;
                _percentText.Text = $"{pct}%";
                _progressStatus.Text = msg;
                _logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\r\n");
                _logBox.ScrollToEnd();
            });
        }

        try
        {
            Report(0, "Preparing setup…");
            await Task.Run(() => Program.PerformInstall(targetDir, createDesktop, createStartMenu, trustCert, Report));

            Report(100, "Installation complete!");
            UpdatePill(_step2Pill, false);
            UpdatePill(_step3Pill, true);
            _progressPage.Visibility = Visibility.Collapsed;
            _completePage.Visibility = Visibility.Visible;
            _cancelButton.Visibility = Visibility.Collapsed;
            _finishButton.Visibility = Visibility.Visible;
        }
        catch (Exception ex)
        {
            _progressPage.Visibility = Visibility.Collapsed;
            _errorPage.Visibility = Visibility.Visible;
            _errorDetails.Text = ex.Message;
            _cancelButton.IsEnabled = true;
            _retryButton.Visibility = Visibility.Visible;
        }
    }

    // ==========================================
    // NEUMORPHIC UI COMPONENT BUILDERS
    // ==========================================
    private static Border CreateStepPill(string label, bool isActive)
    {
        var border = new Border
        {
            CornerRadius = new CornerRadius(99),
            Background = isActive ? new SolidColorBrush(Color.FromArgb(0x30, 0x00, 0xD2, 0xFF)) : new SolidColorBrush(WellBg),
            BorderBrush = isActive ? new SolidColorBrush(AccentCyan) : new SolidColorBrush(ShadowBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(12, 4, 12, 4),
            Margin = new Thickness(0, 0, 8, 0)
        };
        var text = new TextBlock
        {
            Text = label,
            FontSize = 11,
            FontWeight = isActive ? FontWeights.SemiBold : FontWeights.Normal,
            Foreground = isActive ? new SolidColorBrush(AccentCyan) : new SolidColorBrush(TextMuted)
        };
        border.Child = text;
        return border;
    }

    private static void UpdatePill(Border pill, bool isActive)
    {
        pill.Background = isActive ? new SolidColorBrush(Color.FromArgb(0x30, 0x00, 0xD2, 0xFF)) : new SolidColorBrush(WellBg);
        pill.BorderBrush = isActive ? new SolidColorBrush(AccentCyan) : new SolidColorBrush(ShadowBorder);
        if (pill.Child is TextBlock tb)
        {
            tb.FontWeight = isActive ? FontWeights.SemiBold : FontWeights.Normal;
            tb.Foreground = isActive ? new SolidColorBrush(AccentCyan) : new SolidColorBrush(TextMuted);
        }
    }

    private static CheckBox CreateNeumorphicCheckBox(string text, bool isChecked)
    {
        return new CheckBox
        {
            Content = text,
            IsChecked = isChecked,
            Foreground = new SolidColorBrush(TextWhite),
            FontSize = 12.5,
            Margin = new Thickness(0, 0, 0, 8),
            Cursor = Cursors.Hand
        };
    }

    private static Button CreateNeumorphicButton(string text, Action action, double width = 80, double height = 32)
    {
        var btn = new Button
        {
            Content = text,
            Width = width,
            Height = height,
            Foreground = new SolidColorBrush(TextWhite),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand,
            FontSize = 12
        };
        btn.Click += (_, _) => action();
        return btn;
    }

    private static Button CreateNeumorphicButton(string text, RoutedEventHandler handler, double width = 80, double height = 32)
    {
        var btn = new Button
        {
            Content = text,
            Width = width,
            Height = height,
            Foreground = new SolidColorBrush(TextWhite),
            Background = CreateBrush(CardBgStart, CardBgEnd),
            BorderBrush = new SolidColorBrush(HighlightBorder),
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand,
            FontSize = 12
        };
        btn.Click += handler;
        return btn;
    }

    private static Button CreatePrimaryButton(string text, RoutedEventHandler handler, double width = 120, double height = 36)
    {
        var btn = new Button
        {
            Content = text,
            Width = width,
            Height = height,
            FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.White,
            Background = new LinearGradientBrush(AccentCyan, AccentPurple, 45),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x7D, 0xEE, 0xFF)),
            BorderThickness = new Thickness(1),
            Cursor = Cursors.Hand,
            FontSize = 13,
            Effect = new DropShadowEffect
            {
                Color = AccentCyan,
                BlurRadius = 14,
                Direction = 315,
                ShadowDepth = 2,
                Opacity = 0.4
            }
        };
        btn.Click += handler;
        return btn;
    }

    private static Button CreateIconButton(string pathData, Action onClick)
    {
        var btn = new Button
        {
            Width = 32,
            Height = 32,
            Background = Brushes.Transparent,
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            Content = CreateVectorIcon(pathData, new SolidColorBrush(TextMuted), 14, 14)
        };
        btn.MouseEnter += (_, _) =>
        {
            if (btn.Content is System.Windows.Shapes.Path p) p.Fill = new SolidColorBrush(TextWhite);
        };
        btn.MouseLeave += (_, _) =>
        {
            if (btn.Content is System.Windows.Shapes.Path p) p.Fill = new SolidColorBrush(TextMuted);
        };
        btn.Click += (_, _) => onClick();
        return btn;
    }

    private static System.Windows.Shapes.Path CreateVectorIcon(string pathData, Brush fill, double w, double h)
    {
        return new System.Windows.Shapes.Path
        {
            Data = Geometry.Parse(pathData),
            Fill = fill,
            Width = w,
            Height = h,
            Stretch = Stretch.Uniform,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center
        };
    }

    private static LinearGradientBrush CreateBrush(Color c1, Color c2)
    {
        return new LinearGradientBrush(c1, c2, new Point(0, 0), new Point(1, 1));
    }

    private static DropShadowEffect CreateNeumorphicShadow(double blur, double depth, double opacity)
    {
        return new DropShadowEffect
        {
            Color = Colors.Black,
            BlurRadius = blur,
            Direction = 315,
            ShadowDepth = depth,
            Opacity = opacity
        };
    }
}
