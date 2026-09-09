using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Windows.Data;
using System.Windows.Input;
using DarksFIDO2.App.Dialogs;
using DarksFIDO2.App.Services;
using DarksFIDO2.Core;

namespace DarksFIDO2.App.ViewModels;

public enum AuditFilterType
{
    All,
    Auth,
    Vault,
    Errors
}

public sealed class AuditViewModel : ViewModelBase
{
    private readonly IVaultSession _session;
    private readonly IDialogService _dialogs;

    private readonly ObservableCollection<AuditEvent> _allEvents = [];
    private readonly ICollectionView _eventsView;

    private AuditFilterType _activeFilter = AuditFilterType.All;
    private string _searchQuery = string.Empty;
    private AuditEvent? _selectedEvent;

    public AuditViewModel(IVaultSession session, IDialogService dialogs)
    {
        _session = session;
        _dialogs = dialogs;

        _eventsView = CollectionViewSource.GetDefaultView(_allEvents);
        _eventsView.Filter = FilterEvent;

        LoadEvents();

        FilterAllCommand = new RelayCommand(() => SetFilter(AuditFilterType.All));
        FilterAuthCommand = new RelayCommand(() => SetFilter(AuditFilterType.Auth));
        FilterVaultCommand = new RelayCommand(() => SetFilter(AuditFilterType.Vault));
        FilterErrorsCommand = new RelayCommand(() => SetFilter(AuditFilterType.Errors));

        ExportSignedCsvCommand = new RelayCommand(ExecuteExportSignedCsv);
        RefreshCommand = new RelayCommand(LoadEvents);
    }

    public ICollectionView Events => _eventsView;

    public AuditEvent? SelectedEvent
    {
        get => _selectedEvent;
        set => SetProperty(ref _selectedEvent, value);
    }

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                _eventsView.Refresh();
            }
        }
    }

    public AuditFilterType ActiveFilter
    {
        get => _activeFilter;
        private set => SetProperty(ref _activeFilter, value);
    }

    public int TotalEvents => _allEvents.Count;

    public ICommand FilterAllCommand { get; }
    public ICommand FilterAuthCommand { get; }
    public ICommand FilterVaultCommand { get; }
    public ICommand FilterErrorsCommand { get; }
    public ICommand ExportSignedCsvCommand { get; }
    public ICommand RefreshCommand { get; }

    public void LoadEvents()
    {
        _allEvents.Clear();
        if (_session.CurrentProfile is null) return;

        foreach (AuditEvent ev in _session.CurrentProfile.Data.AuditLog.OrderByDescending(x => x.TimestampUtc))
        {
            _allEvents.Add(ev);
        }

        SelectedEvent = _allEvents.FirstOrDefault();
        OnPropertyChanged(nameof(TotalEvents));
    }

    private void SetFilter(AuditFilterType filter)
    {
        ActiveFilter = filter;
        _eventsView.Refresh();
    }

    private bool FilterEvent(object obj)
    {
        if (obj is not AuditEvent ev) return false;

        // Filter by category
        switch (ActiveFilter)
        {
            case AuditFilterType.Auth:
                if (!ev.Type.Contains("Auth", StringComparison.OrdinalIgnoreCase) &&
                    !ev.Type.Contains("WebAuthn", StringComparison.OrdinalIgnoreCase) &&
                    !ev.Type.Contains("Totp", StringComparison.OrdinalIgnoreCase))
                    return false;
                break;
            case AuditFilterType.Vault:
                if (!ev.Type.Contains("Vault", StringComparison.OrdinalIgnoreCase) &&
                    !ev.Type.Contains("Profile", StringComparison.OrdinalIgnoreCase))
                    return false;
                break;
            case AuditFilterType.Errors:
                if (!ev.Outcome.Contains("Fail", StringComparison.OrdinalIgnoreCase) &&
                    !ev.Outcome.Contains("Error", StringComparison.OrdinalIgnoreCase))
                    return false;
                break;
        }

        // Filter by search query
        if (!string.IsNullOrWhiteSpace(SearchQuery))
        {
            string q = SearchQuery.Trim();
            if (!ev.Message.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !ev.Type.Contains(q, StringComparison.OrdinalIgnoreCase) &&
                !ev.Outcome.Contains(q, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    private void ExecuteExportSignedCsv()
    {
        if (_session.CurrentProfile is null) return;

        var sfd = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Export Cryptographically Signed Audit Log",
            Filter = "CSV Spreadsheet (*.csv)|*.csv|All Files (*.*)|*.*",
            FileName = $"{_session.CurrentProfile.Metadata.Name}-Audit-{DateTime.UtcNow:yyyyMMdd-HHmm}.csv"
        };

        if (sfd.ShowDialog() != true) return;

        try
        {
            SignedAuditExport export = _session.AuditExport.ExportSignedCsv(_session.CurrentProfile.Data, sfd.FileName);
            _session.AddAuditEvent("Audit", "Success", $"Exported signed audit log: {sfd.FileName}");
            LoadEvents();

            _dialogs.ShowAlert(
                $"Audit log exported successfully with ECDSA P-256 digital signature!\n\n" +
                $"Data File: {export.CsvPath}\n" +
                $"Signature: {export.SignaturePath}\n" +
                $"Public Key: {export.PublicKeyPath}\n\n" +
                "Any tampering with the CSV file will invalidate the cryptographic signature.",
                "Export Signed Audit");
        }
        catch (Exception ex)
        {
            _dialogs.ShowError($"Audit export failed: {ex.Message}");
        }
    }
}
