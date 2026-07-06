using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.USB.Services;

public class UsbDeviceMonitor : IDisposable
{
    private const string WmiInsertQuery = @"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_DiskDrive' AND TargetInstance.InterfaceType = 'USB'";
    private const string WmiRemoveQuery = @"SELECT * FROM __InstanceDeletionEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_DiskDrive' AND TargetInstance.InterfaceType = 'USB'";

    private ManagementEventWatcher _insertWatcher;
    private ManagementEventWatcher _removeWatcher;
    private bool _isRunning;

    public event Action<UsbDeviceInfo> OnDeviceInserted;
    public event Action<UsbDeviceInfo> OnDeviceRemoved;

    public void Start()
    {
        if (_isRunning) return;
        _isRunning = true;

        EnumerateExistingDevices();

        _insertWatcher = new ManagementEventWatcher(new WqlEventQuery(WmiInsertQuery));
        _insertWatcher.EventArrived += OnUsbDiskInserted;
        _insertWatcher.Start();

        _removeWatcher = new ManagementEventWatcher(new WqlEventQuery(WmiRemoveQuery));
        _removeWatcher.EventArrived += OnUsbDiskRemoved;
        _removeWatcher.Start();
    }

    public void Stop()
    {
        _isRunning = false;
        _insertWatcher?.Stop(); _insertWatcher?.Dispose();
        _removeWatcher?.Stop(); _removeWatcher?.Dispose();
    }

    private void OnUsbDiskInserted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var targetInstance = e.NewEvent["TargetInstance"] as ManagementBaseObject;
            if (targetInstance == null) return;
            var deviceInfo = ExtractDeviceInfo(targetInstance);
            OnDeviceInserted?.Invoke(deviceInfo);
        }
        catch { }
    }

    private void OnUsbDiskRemoved(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var targetInstance = e.NewEvent["TargetInstance"] as ManagementBaseObject;
            if (targetInstance == null) return;
            var deviceInfo = ExtractDeviceInfo(targetInstance);
            OnDeviceRemoved?.Invoke(deviceInfo);
        }
        catch { }
    }

    private void EnumerateExistingDevices()
    {
        using var searcher = new ManagementObjectSearcher(@"SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
        foreach (ManagementObject disk in searcher.Get())
        {
            try { var deviceInfo = ExtractDeviceInfo(disk); OnDeviceInserted?.Invoke(deviceInfo); } catch { }
        }
    }

    private UsbDeviceInfo ExtractDeviceInfo(ManagementBaseObject disk)
    {
        string pnpDeviceID = disk["PNPDeviceID"]?.ToString() ?? "";
        string model = disk["Model"]?.ToString() ?? "Unknown";
        string serialNumber = (disk["SerialNumber"]?.ToString() ?? "").Trim().TrimEnd('\0', ' ');
        ulong size = Convert.ToUInt64(disk["Size"] ?? 0);
        var (vid, pid) = ParseVidPid(pnpDeviceID);
        return new UsbDeviceInfo
        {
            PnpDeviceID = pnpDeviceID,
            Model = model,
            SerialNumber = serialNumber,
            VID = vid,
            PID = pid,
            SizeBytes = size,
            DeviceType = UsbDeviceType.MassStorage,
            DetectedAt = DateTime.UtcNow
        };
    }

    private (string vid, string pid) ParseVidPid(string pnpDeviceID)
    {
        string vid = "0000", pid = "0000";
        try
        {
            string upper = pnpDeviceID.ToUpperInvariant();
            int vidIdx = upper.IndexOf("VID_");
            int pidIdx = upper.IndexOf("PID_");
            if (vidIdx >= 0 && vidIdx + 8 <= upper.Length) vid = upper.Substring(vidIdx + 4, 4);
            if (pidIdx >= 0 && pidIdx + 8 <= upper.Length) pid = upper.Substring(pidIdx + 4, 4);
        }
        catch { }
        return (vid, pid);
    }

    public void Dispose() => Stop();
}
