using System;
using System.Security.Cryptography;

namespace EnterpriseFileSecurity.Core.Crypto;

public static class AesGcmEncryption
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public static byte[] GenerateAesKey()
    {
        byte[] key = new byte[KeySize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(key);
        return key;
    }

    public static byte[] GenerateNonce()
    {
        byte[] nonce = new byte[NonceSize];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(nonce);
        return nonce;
    }

    /// <summary>
    /// AES-256-GCM 加密。空文件（0字节明文）正常返回空密文+有效Tag。
    /// </summary>
    public static (byte[] ciphertext, byte[] tag, byte[] nonce) Encrypt(
        byte[] plaintext, byte[] key, byte[]? associatedData = null)
    {
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
        if (key == null) throw new ArgumentNullException(nameof(key));

        byte[] nonce = GenerateNonce();
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
        return (ciphertext, tag, nonce);
    }

    /// <summary>
    /// AES-256-GCM 解密。空密文（0字节）正常返回空明文。
    /// </summary>
    public static byte[] Decrypt(
        byte[] ciphertext, byte[] key, byte[] nonce, byte[] tag,
        byte[]? associatedData = null)
    {
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (nonce == null) throw new ArgumentNullException(nameof(nonce));
        if (tag == null) throw new ArgumentNullException(nameof(tag));

        byte[] plaintext = new byte[ciphertext.Length];

        using var aesGcm = new AesGcm(key, TagSize);
        aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
        return plaintext;
    }
}
