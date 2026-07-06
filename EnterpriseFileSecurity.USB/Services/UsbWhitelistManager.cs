using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.USB.Services;

public class UsbWhitelistManager
{
    private List<WhitelistEntry> _whitelist;
    private readonly ReaderWriterLockSlim _lock = new();

    public UsbWhitelistManager()
    {
        _whitelist = new List<WhitelistEntry>();
    }

    public class WhitelistEntry
    {
        public string EntryID { get; set; } = Guid.NewGuid().ToString("N");
        public string SerialNumber { get; set; }
        public string VID { get; set; }
        public string PID { get; set; }
        public string Model { get; set; }
        public string DeviceFingerprint { get; set; }
        public string OwnerUserID { get; set; }
        public string OwnerName { get; set; }
        public string Description { get; set; }
        public string AuthorizedBy { get; set; }
        public DateTime AuthorizedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public bool IsActive { get; set; } = true;
    }

    public bool IsDeviceAuthorized(UsbDeviceInfo device)
    {
        _lock.EnterReadLock();
        try
        {
            if (string.IsNullOrEmpty(device.SerialNumber)) return false;
            string fingerprint = device.ComputeFingerprint();
            foreach (var entry in _whitelist)
            {
                if (!entry.IsActive) continue;
                if (!string.IsNullOrEmpty(entry.DeviceFingerprint) && entry.DeviceFingerprint == fingerprint)
                    { if (!IsEntryExpired(entry)) return true; }
                if (string.Equals(entry.SerialNumber, device.SerialNumber, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(entry.VID, device.VID, StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(entry.PID, device.PID, StringComparison.OrdinalIgnoreCase))
                    { if (!IsEntryExpired(entry)) return true; }
                if (string.Equals(entry.SerialNumber, device.SerialNumber, StringComparison.OrdinalIgnoreCase))
                    { if (!IsEntryExpired(entry)) return true; }
            }
            return false;
        }
        finally { _lock.ExitReadLock(); }
    }

    public bool AddDevice(UsbDeviceInfo deviceInfo, string ownerUserID, string ownerName, string authorizedBy, string description = null)
    {
        if (_whitelist.Any(e => e.SerialNumber == deviceInfo.SerialNumber && e.IsActive)) return false;
        var entry = new WhitelistEntry
        {
            SerialNumber = deviceInfo.SerialNumber, VID = deviceInfo.VID, PID = deviceInfo.PID,
            Model = deviceInfo.Model, DeviceFingerprint = deviceInfo.ComputeFingerprint(),
            OwnerUserID = ownerUserID, OwnerName = ownerName,
            Description = description ?? $"{deviceInfo.Model} ({deviceInfo.SerialNumber})",
            AuthorizedBy = authorizedBy, AuthorizedAt = DateTime.UtcNow, IsActive = true
        };
        _whitelist.Add(entry);
        return true;
    }

    public bool RemoveDevice(string serialNumber)
    {
        var entry = _whitelist.FirstOrDefault(e => e.SerialNumber == serialNumber && e.IsActive);
        if (entry == null) return false;
        entry.IsActive = false;
        return true;
    }

    public List<WhitelistEntry> GetAllEntries()
    {
        _lock.EnterReadLock();
        try { return _whitelist.Where(e => e.IsActive).ToList(); }
        finally { _lock.ExitReadLock(); }
    }

    private bool IsEntryExpired(WhitelistEntry entry)
    {
        return entry.ExpiresAt.HasValue && entry.ExpiresAt.Value < DateTime.UtcNow;
    }
}
