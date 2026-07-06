using System;

namespace EnterpriseFileSecurity.Common;

public class UsbAlertEntry
{
    public string AlertID { get; set; } = Guid.NewGuid().ToString("N");
    public UsbAlertType AlertType { get; set; }
    public string AlertTypeName => AlertType.ToString();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string PnpDeviceID { get; set; }
    public string DeviceModel { get; set; }
    public string SerialNumber { get; set; }
    public string VID { get; set; }
    public string PID { get; set; }
    public string DeviceFingerprint { get; set; }
    public string DriveLetter { get; set; }
    public ulong DeviceSizeMB => DeviceSizeBytes / (1024 * 1024);
    public ulong DeviceSizeBytes { get; set; }
    public string Severity { get; set; }
    public string Description { get; set; }
    public string Action { get; set; }
    public string Recommendation { get; set; }
    public string CurrentUser { get; set; }
    public string MachineName { get; set; } = Environment.MachineName;
    public string ProcessName { get; set; }
}
