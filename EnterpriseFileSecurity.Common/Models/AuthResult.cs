using System;

namespace EnterpriseFileSecurity.Common;

public class AuthResult
{
    public bool Success { get; set; }
    public string UserID { get; set; }
    public string UserName { get; set; }
    public int RoleID { get; set; }
    public string SessionToken { get; set; }
    public byte[] PrivateKey { get; set; }
    public string ErrorMessage { get; set; }
    public bool IsLocked { get; set; }
}
