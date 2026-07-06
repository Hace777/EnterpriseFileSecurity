using System;
using System.Security.Cryptography;
using System.Text;

namespace EnterpriseFileSecurity.Common;

public class UsbDeviceInfo
{
    public string PnpDeviceID { get; set; }
    public string Model { get; set; }
    public string SerialNumber { get; set; }
    public string VID { get; set; }
    public string PID { get; set; }
    public ulong SizeBytes { get; set; }
    public string DriveLetter { get; set; }
    public string VolumeName { get; set; }
    public UsbDeviceType DeviceType { get; set; }
    public DateTime DetectedAt { get; set; }
    public string DeviceFingerprint { get; set; }

    public string ComputeFingerprint()
    {
        string raw = $"{VID ?? ""}|{PID ?? ""}|{SerialNumber ?? ""}|{Model ?? ""}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        DeviceFingerprint = Convert.ToHexString(hash).ToLowerInvariant();
        return DeviceFingerprint;
    }
}
