namespace EnterpriseFileSecurity.Common;

public class FileEncryptionContext
{
    public byte[] AESKey { get; set; }
    public byte[] AESIV { get; set; }
    public byte[] EncryptedFEK { get; set; }
    public byte[] FileContentEncrypted { get; set; }
    public byte[] FileContentTag { get; set; }
    public string FilePath { get; set; }
}
