using System;
using System.IO;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.Core.Services;

public class AntiLeakGuardian
{
    private readonly string _protectedMountPoint;
    private readonly string _protectedRealPath;
    private readonly AuditLogger _auditLogger;

    public AntiLeakGuardian(string protectedMountPoint, string protectedRealPath, AuditLogger auditLogger)
    {
        _protectedMountPoint = protectedMountPoint;
        _protectedRealPath = protectedRealPath;
        _auditLogger = auditLogger;
    }

    public bool IsInsideProtectedArea(string absolutePath)
    {
        string normalized = Path.GetFullPath(absolutePath).TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();
        string protectedRoot = Path.GetFullPath(_protectedRealPath).TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();
        string mountPoint = _protectedMountPoint.TrimEnd(Path.DirectorySeparatorChar).ToLowerInvariant();
        return normalized.StartsWith(protectedRoot) || normalized.StartsWith(mountPoint);
    }

    public bool PreCopyCheck(string sourceVirtualPath, string destRealPath)
    {
        if (!IsInsideProtectedArea(destRealPath))
        {
            _auditLogger.LogAsync(new AuditEntry
            {
                UserID = SessionContext.CurrentUserID ?? "SYSTEM",
                Timestamp = DateTime.UtcNow,
                FilePath = sourceVirtualPath,
                OperationType = FileOperationType.Download,
                Result = AuditResult.Deny,
                Detail = $"防泄密拦截：加密文件被尝试复制到非保护区 {destRealPath}"
            });
            return false;
        }
        return true;
    }
}
