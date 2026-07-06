using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace EnterpriseFileSecurity.Core.Crypto;

public class CryptoPipeline
{
    private const int HeaderSize = 4096;

    public byte[] GenerateFEK() => AesGcmEncryption.GenerateAesKey();

    public byte[] GetMasterNonce(string path) => new byte[8];

    public byte[] GenerateMasterNonce()
    {
        byte[] nonce = new byte[8];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(nonce);
        return nonce;
    }

    public long GetHeaderSize(string path) => HeaderSize;
    public long GetHeaderSize(FileStream fs) => HeaderSize;

    public (byte[] ciphertext, byte[] tag, byte[] nonce) AesGcmEncrypt(
        byte[] plaintext, byte[] key, byte[] nonce)
    {
        if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (nonce == null) throw new ArgumentNullException(nameof(nonce));
        // 空文件（0字节）可正常加密
        return AesGcmEncryption.Encrypt(plaintext, key);
    }

    public byte[] AesGcmDecrypt(byte[] ciphertext, byte[] key, byte[] nonce, byte[] tag)
    {
        if (ciphertext == null) throw new ArgumentNullException(nameof(ciphertext));
        if (key == null) throw new ArgumentNullException(nameof(key));
        if (nonce == null) throw new ArgumentNullException(nameof(nonce));
        if (tag == null) throw new ArgumentNullException(nameof(tag));
        // 空密文（0字节）可正常解密
        return AesGcmEncryption.Decrypt(ciphertext, key, nonce, tag);
    }
}
