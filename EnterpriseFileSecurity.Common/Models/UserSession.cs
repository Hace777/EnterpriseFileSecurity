using System;

namespace EnterpriseFileSecurity.Common;

public class UserSession
{
    public string SessionID { get; set; }
    public string UserID { get; set; }
    public string UserName { get; set; }
    public int RoleID { get; set; }
    public byte[] PrivateKey { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}
