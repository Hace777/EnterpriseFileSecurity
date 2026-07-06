using System.Collections.Generic;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.Core.Services;

public interface IAccessControlEngine
{
    AccessDecision CheckPermission(string userId, UserRole role, FileOperationType operation, int fileLevel, string filePath);
    int GetFileSecurityLevel(string filePath);
    List<string> GetAuthorizedUsers(string filePath);
}
