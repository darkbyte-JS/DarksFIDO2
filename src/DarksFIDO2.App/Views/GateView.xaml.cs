using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using DarksFIDO2.App.ViewModels;

namespace DarksFIDO2.App.Views;

public partial class GateView : UserControl
{
    public GateView()
    {
        InitializeComponent();

        Loaded += (s, e) =>
        {
            MasterPinBox.Clear();
            MasterPinBox.FocusInput();
        };

        MasterPinBox.PinKeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter)
            {
                TriggerUnlock();
            }
        };
    }

    private void UnlockBtn_Click(object sender, RoutedEventArgs e)
    {
        TriggerUnlock();
    }

    private void TriggerUnlock()
    {
        if (DataContext is GateViewModel vm)
        {
            string pin = MasterPinBox.Password;
            vm.AttemptUnlock(pin);
            MasterPinBox.Clear();
        }
    }
}
