using System;

namespace EnterpriseFileSecurity.Common;

public class UserRecord
{
    public string UserID { get; set; }
    public string UserName { get; set; }
    public string DisplayName { get; set; }
    public string PasswordHash { get; set; }
    public string PasswordSalt { get; set; }
    public int HashIterations { get; set; }
    public int RoleID { get; set; }
    public bool IsLocked { get; set; }
    public DateTime? LockUntil { get; set; }
    public int FailedAttempts { get; set; }
    public DateTime CreatedAt { get; set; }
}
