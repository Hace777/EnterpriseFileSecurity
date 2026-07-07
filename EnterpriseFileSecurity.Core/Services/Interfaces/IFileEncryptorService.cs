using System.Collections.Generic;
using System.IO;

namespace EnterpriseFileSecurity.Core.Services;

/// <summary>
/// 文件透明加密服务接口 —— 负责文件内容的 AES-256-GCM 加密/解密，以及加密文件头的读写
/// </summary>
public interface IFileEncryptorService
{
    /// <summary>加密文件（AES-256-GCM 64KB分块，生成加密文件头）</summary>
    string EncryptFile(string sourceFilePath, string securityLevel, List<string> authorizedUserIds);

    /// <summary>解密文件到临时路径（返回明文临时文件路径）</summary>
    string DecryptFile(string encryptedFilePath);

    /// <summary>获取加密文件的元数据（安全等级、授权用户列表等）</summary>
    EncryptedFileMetadata ReadMetadata(string encryptedFilePath);

    /// <summary>获取加密存储路径下的所有加密文件列表</summary>
    List<string> ListEncryptedFiles();

    /// <summary>加密存储根目录</summary>
    string VaultPath { get; }

    /// <summary>清理加密存储目录中的所有 .secfs 文件</summary>
    int ClearVault();
}

/// <summary>
/// 加密文件头中存储的元数据
/// </summary>
public class EncryptedFileMetadata
{
    public string OriginalFileName { get; set; }
    public string SecurityLevel { get; set; } = "D";
    public List<string> AuthorizedUserIds { get; set; } = new();
    public long OriginalFileSize { get; set; }
    public string EncryptedAt { get; set; }
    public string EncryptedBy { get; set; }

    /// <summary>每个授权用户对应的 EFEK（Encrypted File Encryption Key）</summary>
    public Dictionary<string, byte[]> EFEKMap { get; set; } = new();

    /// <summary>每个分块的加密参数（nonce + tag）</summary>
    public List<ChunkEncryptionParams> Chunks { get; set; } = new();
}

public class ChunkEncryptionParams
{
    public int ChunkIndex { get; set; }
    public byte[] Nonce { get; set; }
    public byte[] Tag { get; set; }
}