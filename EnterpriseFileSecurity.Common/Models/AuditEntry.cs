using System;
using System.IO;

namespace EnterpriseFileSecurity.Common;

public class AuditEntry
{
    public string AuditID { get; set; } = Guid.NewGuid().ToString("N");
    public string UserID { get; set; }
    public string UserName { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string FilePath { get; set; }
    public string FileName => Path.GetFileName(FilePath ?? "");
    public FileOperationType OperationType { get; set; }
    public AuditResult Result { get; set; }
    public string Detail { get; set; }
    public long? FileSize { get; set; }
    public string ProcessName { get; set; }
    public string MachineName { get; set; } = Environment.MachineName;
    public string SessionID { get; set; }
    public string FileSecurityLevel { get; set; }
}
