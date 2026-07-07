using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EnterpriseFileSecurity.Common;
using EnterpriseFileSecurity.Core.Crypto;

namespace EnterpriseFileSecurity.Core.Services;

/// <summary>
/// 文件加密服务实现 —— 64KB分块 AES-256-GCM 加密，加密文件头存储EFEK与元数据
/// 
/// 加密文件格式（二进制）：
/// ┌──────────────────────────────────────────────────┐
/// │  Magic Number (8 bytes): "SECFS\x01\x00"         │
/// │  Header JSON Length (4 bytes, int32 LE)          │
/// │  Header JSON (UTF-8): EncryptedFileMetadata       │
/// │  Chunk 0: ciphertext (≤64KB)                     │
/// │  Chunk 1: ciphertext (≤64KB)                     │
/// │  ...                                             │
/// └──────────────────────────────────────────────────┘
/// </summary>
public class FileEncryptorService : IFileEncryptorService
{
    private const int ChunkSize = 64 * 1024; // 64KB
    private static readonly byte[] MagicNumber = { (byte)'S', (byte)'E', (byte)'C', (byte)'F', (byte)'S', 0x01, 0x00 };

    private readonly IAuthenticationService _authService;
    private readonly string _vaultPath;

    public string VaultPath => _vaultPath;

    public FileEncryptorService(IAuthenticationService authService, string vaultPath)
    {
        _authService = authService ?? throw new ArgumentNullException(nameof(authService));
        _vaultPath = vaultPath ?? throw new ArgumentNullException(nameof(vaultPath));
        Directory.CreateDirectory(_vaultPath);
    }

    /// <summary>
    /// 加密源文件：生成FEK → 分块AES-256-GCM加密 → 构建加密文件头 → 写入加密存储
    /// </summary>
    public string EncryptFile(string sourceFilePath, string securityLevel, List<string> authorizedUserIds)
    {
        if (!File.Exists(sourceFilePath))
            throw new FileNotFoundException("源文件不存在", sourceFilePath);

        // 1. 为每个授权用户生成 EFEK（用 RSA 公钥加密同一把 FEK），返回的 fek 即实际加密密钥
        var (fek, efekList) = _authService.GenerateAndEncryptFEK(authorizedUserIds);
        var efekMap = new Dictionary<string, byte[]>();
        foreach (var (userId, efek) in efekList)
            efekMap[userId] = efek;

        // 2. 读取源文件并分块加密
        byte[] sourceData = File.ReadAllBytes(sourceFilePath);
        int totalChunks = (int)Math.Ceiling((double)sourceData.Length / ChunkSize);
        if (totalChunks == 0) totalChunks = 1; // 空文件也占1个块

        var chunks = new List<ChunkEncryptionParams>();
        var encryptedStream = new MemoryStream();

        for (int i = 0; i < totalChunks; i++)
        {
            int offset = i * ChunkSize;
            int remaining = sourceData.Length - offset;
            int currentChunkSize = Math.Min(ChunkSize, remaining);

            byte[] chunkPlaintext = new byte[currentChunkSize];
            if (currentChunkSize > 0)
                Buffer.BlockCopy(sourceData, offset, chunkPlaintext, 0, currentChunkSize);

            var (ciphertext, tag, nonce) = AesGcmEncryption.Encrypt(chunkPlaintext, fek);
            encryptedStream.Write(ciphertext, 0, ciphertext.Length);

            chunks.Add(new ChunkEncryptionParams
            {
                ChunkIndex = i,
                Nonce = nonce,
                Tag = tag
            });
        }

        // 3. 构建元数据
        var metadata = new EncryptedFileMetadata
        {
            OriginalFileName = Path.GetFileName(sourceFilePath),
            SecurityLevel = securityLevel,
            AuthorizedUserIds = authorizedUserIds,
            OriginalFileSize = new FileInfo(sourceFilePath).Length,
            EncryptedAt = DateTime.UtcNow.ToString("o"),
            EncryptedBy = SessionContext.CurrentUserID ?? "SYSTEM",
            EFEKMap = efekMap,
            Chunks = chunks
        };

        // 4. 生成加密文件
        string encryptedFileName = $"{Guid.NewGuid():N}.secfs";
        string encryptedFilePath = Path.Combine(_vaultPath, encryptedFileName);
        WriteEncryptedFile(encryptedFilePath, metadata, encryptedStream.ToArray());

        return encryptedFilePath;
    }

    /// <summary>
    /// 解密加密文件：读取文件头 → 获取EFEK → 解密FEK → 分块解密 → 返回明文
    /// </summary>
    public string DecryptFile(string encryptedFilePath)
    {
        if (!File.Exists(encryptedFilePath))
            throw new FileNotFoundException("加密文件不存在", encryptedFilePath);

        // 1. 读取文件头和加密数据
        var (metadata, encryptedData) = ReadEncryptedFile(encryptedFilePath);

        // 2. 获取当前用户的EFEK
        string currentUserId = SessionContext.CurrentUserID
            ?? throw new InvalidOperationException("未登录，无法解密文件");
        byte[] currentUserPrivateKey = SessionContext.CurrentPrivateKey
            ?? throw new InvalidOperationException("未登录，私钥不可用");

        if (!metadata.EFEKMap.TryGetValue(currentUserId, out byte[] efek))
            throw new UnauthorizedAccessException($"当前用户 {currentUserId} 不在文件授权列表中");

        // 3. 用RSA私钥解密EFEK得到FEK
        byte[] fek = _authService.DecryptFEK(efek, currentUserPrivateKey);

        // 4. 分块解密
        var plaintextStream = new MemoryStream();
        int encryptedOffset = 0;

        for (int i = 0; i < metadata.Chunks.Count; i++)
        {
            var chunk = metadata.Chunks[i];

            // 计算当前块密文长度
            int chunkCipherLen = (i == metadata.Chunks.Count - 1)
                ? encryptedData.Length - encryptedOffset
                : ChunkSize;

            byte[] chunkCiphertext = new byte[chunkCipherLen];
            Buffer.BlockCopy(encryptedData, encryptedOffset, chunkCiphertext, 0, chunkCipherLen);
            encryptedOffset += chunkCipherLen;

            byte[] plaintext = AesGcmEncryption.Decrypt(chunkCiphertext, fek, chunk.Nonce, chunk.Tag);
            plaintextStream.Write(plaintext, 0, plaintext.Length);
        }

        // 5. 写入解密文件（输出到解密目录，保留原文件名）
        string outputFileName = metadata.OriginalFileName ?? $"decrypted_{Guid.NewGuid():N}";
        string outputPath = Path.Combine(DatabaseInitializer.DecryptedOutputPath, outputFileName);
        // 若同名文件已存在，追加序号
        if (File.Exists(outputPath))
        {
            string nameNoExt = Path.GetFileNameWithoutExtension(outputFileName);
            string ext = Path.GetExtension(outputFileName);
            outputPath = Path.Combine(DatabaseInitializer.DecryptedOutputPath,
                $"{nameNoExt}_{DateTime.Now:HHmmss}{ext}");
        }
        File.WriteAllBytes(outputPath, plaintextStream.ToArray());

        return outputPath;
    }

    public EncryptedFileMetadata ReadMetadata(string encryptedFilePath)
    {
        var (metadata, _) = ReadEncryptedFile(encryptedFilePath);
        return metadata;
    }

    public List<string> ListEncryptedFiles()
    {
        return Directory.GetFiles(_vaultPath, "*.secfs").ToList();
    }

    /// <summary>清理 Vault 中所有 .secfs 文件，返回删除数量</summary>
    public int ClearVault()
    {
        int count = 0;
        foreach (var f in Directory.GetFiles(_vaultPath, "*.secfs"))
        {
            try { File.Delete(f); count++; } catch { }
        }
        return count;
    }

    #region 文件格式读写

    private void WriteEncryptedFile(string filePath, EncryptedFileMetadata metadata, byte[] encryptedData)
    {
        using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write);

        // Magic Number
        fs.Write(MagicNumber, 0, MagicNumber.Length);

        // Header JSON
        string headerJson = JsonSerializer.Serialize(metadata, new JsonSerializerOptions
        {
            WriteIndented = false,
            PropertyNameCaseInsensitive = true
        });
        byte[] headerBytes = Encoding.UTF8.GetBytes(headerJson);
        byte[] headerLenBytes = BitConverter.GetBytes(headerBytes.Length);
        if (!BitConverter.IsLittleEndian) Array.Reverse(headerLenBytes);

        fs.Write(headerLenBytes, 0, 4);
        fs.Write(headerBytes, 0, headerBytes.Length);

        // Encrypted chunks
        fs.Write(encryptedData, 0, encryptedData.Length);
    }

    private (EncryptedFileMetadata metadata, byte[] encryptedData) ReadEncryptedFile(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);

        // 验证 Magic Number
        byte[] magic = new byte[MagicNumber.Length];
        fs.Read(magic, 0, magic.Length);
        if (!magic.SequenceEqual(MagicNumber))
            throw new InvalidDataException("无效的加密文件格式（Magic Number不匹配）");

        // 读取 Header JSON 长度
        byte[] lenBytes = new byte[4];
        fs.Read(lenBytes, 0, 4);
        if (!BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
        int headerLen = BitConverter.ToInt32(lenBytes, 0);

        // 读取 Header JSON
        byte[] headerBytes = new byte[headerLen];
        fs.Read(headerBytes, 0, headerLen);
        string headerJson = Encoding.UTF8.GetString(headerBytes);

        var metadata = JsonSerializer.Deserialize<EncryptedFileMetadata>(headerJson,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("加密文件头解析失败");

        // 读取加密数据
        long remaining = fs.Length - fs.Position;
        byte[] encryptedData = new byte[remaining];
        fs.Read(encryptedData, 0, encryptedData.Length);

        return (metadata, encryptedData);
    }

    #endregion
}