using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.USB.Services;

public class MaliciousUsbScanner
{
    public bool ScanDevice(UsbDeviceInfo deviceInfo)
    {
        bool isMalicious = false;
        string rootPath = null;
        if (!string.IsNullOrEmpty(deviceInfo.DriveLetter))
            rootPath = deviceInfo.DriveLetter;

        if (!string.IsNullOrEmpty(rootPath))
        {
            string autorunPath = Path.Combine(rootPath, "autorun.inf");
            if (File.Exists(autorunPath))
            {
                string content = File.ReadAllText(autorunPath);
                if (content.Contains("shell\\") && (content.Contains("cmd") || content.Contains("powershell")))
                {
                    Console.WriteLine("[MalScan] 检测到恶意 autorun.inf");
                    isMalicious = true;
                }
            }
        }

        bool isBadUSB = CheckBadUSBPattern(deviceInfo.PnpDeviceID);
        if (isBadUSB) { Console.WriteLine("[MalScan] 检测到 BadUSB 特征"); isMalicious = true; }

        return isMalicious;
    }

    private bool CheckBadUSBPattern(string pnpDeviceID)
    {
        try
        {
            using var hidSearcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_Keyboard WHERE PNPDeviceID LIKE '%USB%'");
            foreach (ManagementObject kb in hidSearcher.Get())
            {
                string kbPnpID = kb["PNPDeviceID"]?.ToString() ?? "";
                if (kbPnpID.Contains("USB\\") && pnpDeviceID.Contains("USB\\"))
                    return true;
            }
        }
        catch { }
        return false;
    }
}
