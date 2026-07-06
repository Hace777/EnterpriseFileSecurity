using System;
using System.Collections.Generic;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.Core.Services;

public interface IAuditLogger
{
    void LogAsync(AuditEntry entry);
    void LogSync(AuditEntry entry);
    List<AuditEntry> QueryByUser(string userId, DateTime from, DateTime to);
    List<AuditEntry> QueryAll(DateTime from, DateTime to, int limit = 500);
    string ExportToCsv(List<AuditEntry> entries);
}