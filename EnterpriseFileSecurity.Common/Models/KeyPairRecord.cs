using System;

namespace EnterpriseFileSecurity.Common;

public class KeyPairRecord
{
    public string KeyID { get; set; }
    public string UserID { get; set; }
    public string PublicKey { get; set; }
    public string PrivateKeyEnc { get; set; }
    public string PrivateKeyIV { get; set; }
    public string PrivateKeyTag { get; set; }
    public string KeySalt { get; set; }
    public int KeyIterations { get; set; }
    public int KeySizeBits { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
}
