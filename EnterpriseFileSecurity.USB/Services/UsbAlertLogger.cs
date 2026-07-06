using System;
using System.Collections.Generic;
using System.Data.SQLite;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.USB.Services;

public class UsbAlertLogger
{
    private readonly string _connectionString;

    public UsbAlertLogger(string dbPath)
    {
        _connectionString = $"Data Source={dbPath};Version=3;";
        InitializeSchema();
    }

    private void InitializeSchema()
    {
        using var conn = new SQLiteConnection(_connectionString);
        conn.Open();
        string sql = @"
            CREATE TABLE IF NOT EXISTS UsbAlertLog (
                AlertID            TEXT PRIMARY KEY NOT NULL,
                AlertType          TEXT NOT NULL,
                Timestamp          TEXT NOT NULL,
                PnpDeviceID        TEXT,
                DeviceModel        TEXT,
                SerialNumber       TEXT,
                VID                TEXT,
                PID                TEXT,
                DeviceFingerprint  TEXT,
                DriveLetter        TEXT,
                DeviceSizeBytes    INTEGER,
                Severity           TEXT NOT NULL,
                Description        TEXT NOT NULL,
                Action             TEXT NOT NULL,
                Recommendation     TEXT,
                CurrentUser        TEXT,
                MachineName        TEXT,
                CreatedAt          TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_usb_alert_time ON UsbAlertLog(Timestamp);
            CREATE INDEX IF NOT EXISTS idx_usb_alert_type ON UsbAlertLog(AlertType, Timestamp);";
        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    public void LogAlert(UsbDeviceInfo device, UsbAlertType alertType, string description)
    {
        try
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();
            string sql = @"INSERT INTO UsbAlertLog (
                AlertID, AlertType, Timestamp, PnpDeviceID, DeviceModel,
                SerialNumber, VID, PID, DeviceFingerprint, DriveLetter,
                DeviceSizeBytes, Severity, Description, Action, Recommendation,
                CurrentUser, MachineName)
                VALUES (@aid, @at, @ts, @pid, @model, @sn, @vid, @pid2, @fp, @dl,
                @ds, @sev, @desc, @act, @rec, @cu, @mn)";
            using var cmd = new SQLiteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@aid", Guid.NewGuid().ToString("N"));
            cmd.Parameters.AddWithValue("@at", alertType.ToString());
            cmd.Parameters.AddWithValue("@ts", DateTime.UtcNow.ToString("o"));
            cmd.Parameters.AddWithValue("@pid", device.PnpDeviceID ?? "");
            cmd.Parameters.AddWithValue("@model", device.Model ?? "");
            cmd.Parameters.AddWithValue("@sn", device.SerialNumber ?? "");
            cmd.Parameters.AddWithValue("@vid", device.VID ?? "");
            cmd.Parameters.AddWithValue("@pid2", device.PID ?? "");
            cmd.Parameters.AddWithValue("@fp", device.DeviceFingerprint ?? "");
            cmd.Parameters.AddWithValue("@dl", device.DriveLetter ?? "");
            cmd.Parameters.AddWithValue("@ds", (long)device.SizeBytes);
            cmd.Parameters.AddWithValue("@sev", MapSeverity(alertType));
            cmd.Parameters.AddWithValue("@desc", description);
            cmd.Parameters.AddWithValue("@act", MapAction(alertType));
            cmd.Parameters.AddWithValue("@rec", MapRecommendation(alertType) ?? "");
            cmd.Parameters.AddWithValue("@cu", Environment.UserName);
            cmd.Parameters.AddWithValue("@mn", Environment.MachineName);
            cmd.ExecuteNonQuery();
        }
        catch { }
    }

    private string MapSeverity(UsbAlertType type) => type switch
    {
        UsbAlertType.MaliciousDeviceBlocked or UsbAlertType.BadUSBDetected => "Critical",
        UsbAlertType.UnauthorizedDeviceBlocked or UsbAlertType.DuplicateDeviceWarning => "High",
        UsbAlertType.HotplugRapidReinsert => "Medium",
        _ => "Info"
    };

    private string MapAction(UsbAlertType type) => type switch
    {
        UsbAlertType.UnauthorizedDeviceBlocked or UsbAlertType.MaliciousDeviceBlocked or UsbAlertType.BadUSBDetected => "Blocked",
        UsbAlertType.AuthorizedDeviceAllowed => "Allowed",
        UsbAlertType.DeviceEjected => "Ejected",
        _ => "Recorded"
    };

    private string MapRecommendation(UsbAlertType type) => type switch
    {
        UsbAlertType.UnauthorizedDeviceBlocked => "联系管理员将该设备加入白名单",
        UsbAlertType.MaliciousDeviceBlocked => "立即拔出设备并扫描主机是否被感染",
        UsbAlertType.BadUSBDetected => "立即拔出设备！该设备可能是 BadUSB 攻击工具",
        _ => ""
    };
}
