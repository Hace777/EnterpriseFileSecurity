using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.USB.Services;

public class UsbBlockEngine
{
    public bool BlockDevice(UsbDeviceInfo deviceInfo, BlockReason reason)
    {
        Console.WriteLine($"[UsbBlock] 正在阻止设备: {deviceInfo.Model} (原因: {reason})");
        UnmountVolume(deviceInfo.PnpDeviceID);
        SetDiskOffline(deviceInfo.PnpDeviceID);
        return true;
    }

    private bool UnmountVolume(string pnpDeviceID)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"ASSOCIATORS OF {{Win32_DiskDrive.DeviceID=\"{pnpDeviceID}\"}} WHERE AssocClass=Win32_DiskDriveToDiskPartition");
            foreach (ManagementObject partition in searcher.Get())
            {
                string partitionID = partition["DeviceID"]?.ToString();
                using var logicalSearcher = new ManagementObjectSearcher(
                    $"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID=\"{partitionID}\"}} WHERE AssocClass=Win32_LogicalDiskToPartition");
                foreach (ManagementObject logicalDisk in logicalSearcher.Get())
                {
                    string driveLetter = logicalDisk["DeviceID"]?.ToString();
                    if (!string.IsNullOrEmpty(driveLetter))
                    {
                        try
                        {
                            using var volumeSearcher = new ManagementObjectSearcher(
                                $"SELECT * FROM Win32_Volume WHERE DriveLetter='{driveLetter}'");
                            foreach (ManagementObject volume in volumeSearcher.Get())
                                volume.InvokeMethod("Dismount", new object[] { true, false });
                        }
                        catch { }
                    }
                }
            }
            return true;
        }
        catch { return false; }
    }

    private bool SetDiskOffline(string pnpDeviceID)
    {
        try
        {
            int diskIndex = GetDiskIndex(pnpDeviceID);
            if (diskIndex < 0) return false;
            string scriptPath = Path.GetTempFileName() + ".txt";
            File.WriteAllLines(scriptPath, new[] { $"select disk {diskIndex}", "offline disk" });
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "diskpart.exe", Arguments = $"/s \"{scriptPath}\"",
                    UseShellExecute = false, RedirectStandardOutput = true,
                    CreateNoWindow = true, Verb = "runas"
                }
            };
            process.Start();
            process.WaitForExit(8000);
            File.Delete(scriptPath);
            return process.ExitCode == 0;
        }
        catch { return false; }
    }

    private int GetDiskIndex(string pnpDeviceID)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                $"SELECT Index FROM Win32_DiskDrive WHERE PNPDeviceID='{pnpDeviceID}'");
            foreach (ManagementObject disk in searcher.Get())
                return Convert.ToInt32(disk["Index"]);
        }
        catch { }
        return -1;
    }
}
