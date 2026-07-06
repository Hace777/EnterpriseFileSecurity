using System;
using System.Security.Cryptography;
using System.Text;

namespace EnterpriseFileSecurity.Core.Crypto;

public static class RsaEncryption
{
    private const int RsaKeySize = 2048;

    public static (byte[] publicKeyDer, byte[] privateKeyPkcs8) GenerateKeyPair()
    {
        using var rsa = RSA.Create(RsaKeySize);
        byte[] publicKey = rsa.ExportRSAPublicKey();
        byte[] privateKey = rsa.ExportPkcs8PrivateKey();
        return (publicKey, privateKey);
    }

    public static string ExportPublicKeyPem(byte[] publicKeyDer)
    {
        string base64 = Convert.ToBase64String(publicKeyDer);
        return "-----BEGIN RSA PUBLIC KEY-----\n" +
               ChunkBase64(base64, 64) +
               "\n-----END RSA PUBLIC KEY-----";
    }

    public static byte[] EncryptWithPublicKey(byte[] data, byte[] publicKeyDer)
    {
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKeyDer, out _);
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] DecryptWithPrivateKey(byte[] encryptedData, byte[] privateKeyPkcs8)
    {
        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(privateKeyPkcs8, out _);
        return rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] ParsePublicKeyPem(string pem)
    {
        string base64 = pem
            .Replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .Replace("-----END RSA PUBLIC KEY-----", "")
            .Replace("\n", "").Replace("\r", "");
        return Convert.FromBase64String(base64);
    }

    private static string ChunkBase64(string base64, int chunkSize)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < base64.Length; i += chunkSize)
        {
            sb.Append(base64.Substring(i, Math.Min(chunkSize, base64.Length - i)));
            sb.Append('\n');
        }
        if (sb.Length > 0) sb.Length--;
        return sb.ToString();
    }
}
