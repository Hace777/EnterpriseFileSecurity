using System;
using System.Data.SQLite;
using System.IO;
using System.Security.Cryptography;
using EnterpriseFileSecurity.Core.Crypto;

namespace EnterpriseFileSecurity.Core.Services;

public static class DatabaseInitializer
{
    private static readonly string DefaultDbDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecFS");

    private static readonly string DefaultAuditDbDirectory =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SecFS");

    public static string KeyStoreDbPath => Path.Combine(DefaultDbDirectory, "KeyStore.db");
    public static string AuditDbPath => Path.Combine(DefaultAuditDbDirectory, "AuditLog.db");
    public static string UsbAlertDbPath => Path.Combine(DefaultAuditDbDirectory, "UsbAlertLog.db");

    /// <summary>加密文件（密文）存储路径</summary>
    public static string EncryptedStoragePath => Path.Combine(OutputBaseDir, "加密文件");

    /// <summary>解密后文件（明文）输出路径</summary>
    public static string DecryptedOutputPath => Path.Combine(OutputBaseDir, "解密文件");

    /// <summary>所有测试输出根目录</summary>
    private static readonly string OutputBaseDir = @"D:\Resources\小学期实验\测试";

    static DatabaseInitializer()
    {
        try { Directory.CreateDirectory(DefaultDbDirectory); } catch { }
        try { Directory.CreateDirectory(DefaultAuditDbDirectory); } catch { }
        try { Directory.CreateDirectory(EncryptedStoragePath); } catch { }
        try { Directory.CreateDirectory(DecryptedOutputPath); } catch { }
    }

    public static void EnsureAllDatabasesCreated()
    {
        using var keyStore = new SQLiteConnection($"Data Source={KeyStoreDbPath};Version=3;");
        keyStore.Open();
        using var cmd = new SQLiteCommand(@"
            CREATE TABLE IF NOT EXISTS Users (
                UserID          TEXT PRIMARY KEY NOT NULL,
                UserName        TEXT UNIQUE NOT NULL,
                DisplayName     TEXT,
                PasswordHash    TEXT NOT NULL,
                PasswordSalt    TEXT NOT NULL,
                HashIterations  INTEGER NOT NULL DEFAULT 100000,
                RoleID          INTEGER NOT NULL DEFAULT 2,
                IsLocked        INTEGER NOT NULL DEFAULT 0,
                LockUntil       TEXT,
                FailedAttempts  INTEGER NOT NULL DEFAULT 0,
                CreatedAt       TEXT NOT NULL DEFAULT (datetime('now')),
                UpdatedAt       TEXT NOT NULL DEFAULT (datetime('now')),
                IsDeleted       INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS KeyPairs (
                KeyID           TEXT PRIMARY KEY NOT NULL,
                UserID          TEXT NOT NULL,
                PublicKey       TEXT NOT NULL,
                PrivateKeyEnc   TEXT NOT NULL,
                PrivateKeyIV    TEXT NOT NULL,
                PrivateKeyTag   TEXT NOT NULL,
                KeySalt         TEXT NOT NULL,
                KeyIterations   INTEGER NOT NULL DEFAULT 100000,
                KeySizeBits     INTEGER NOT NULL DEFAULT 2048,
                IsActive        INTEGER NOT NULL DEFAULT 1,
                CreatedAt       TEXT NOT NULL DEFAULT (datetime('now')),
                ExpiresAt       TEXT,
                RevokedAt       TEXT,
                FOREIGN KEY (UserID) REFERENCES Users(UserID)
            );
            CREATE TABLE IF NOT EXISTS KeyRotationHistory (
                RotationID      TEXT PRIMARY KEY NOT NULL,
                UserID          TEXT NOT NULL,
                OldKeyID        TEXT,
                NewKeyID        TEXT NOT NULL,
                FilesProcessed  INTEGER NOT NULL DEFAULT 0,
                FilesFailed     INTEGER NOT NULL DEFAULT 0,
                RotationTrigger TEXT NOT NULL DEFAULT 'SCHEDULED',
                StartedAt       TEXT NOT NULL DEFAULT (datetime('now')),
                CompletedAt     TEXT,
                Status          TEXT NOT NULL DEFAULT 'RUNNING',
                ErrorMessage    TEXT,
                FOREIGN KEY (UserID) REFERENCES Users(UserID)
            );", keyStore);
        cmd.ExecuteNonQuery();

        using var auditConn = new SQLiteConnection($"Data Source={AuditDbPath};Version=3;");
        auditConn.Open();
        using var auditCmd = new SQLiteCommand(@"
            CREATE TABLE IF NOT EXISTS AuditLog (
                AuditID         TEXT PRIMARY KEY NOT NULL,
                UserID          TEXT NOT NULL,
                UserName        TEXT NOT NULL,
                Timestamp       TEXT NOT NULL,
                FilePath        TEXT NOT NULL,
                FileName        TEXT NOT NULL,
                OperationType   TEXT NOT NULL,
                Result          TEXT NOT NULL,
                Detail          TEXT,
                FileSize        INTEGER,
                ProcessName     TEXT,
                MachineName     TEXT,
                SessionID       TEXT,
                FileSecurityLevel TEXT,
                CreatedAt       TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_audit_user_time ON AuditLog(UserID, Timestamp);", auditConn);
        auditCmd.ExecuteNonQuery();

        using var usbConn = new SQLiteConnection($"Data Source={UsbAlertDbPath};Version=3;");
        usbConn.Open();
        using var usbCmd = new SQLiteCommand(@"
            CREATE TABLE IF NOT EXISTS UsbAlertLog (
                AlertID            TEXT PRIMARY KEY NOT NULL,
                AlertType          TEXT NOT NULL,
                Timestamp          TEXT NOT NULL,
                PnpDeviceID        TEXT,
                DeviceModel        TEXT,
                SerialNumber       TEXT,
                VID                TEXT,
                PID                TEXT,
                DeviceFingerprint  TEXT,
                DriveLetter        TEXT,
                DeviceSizeBytes    INTEGER,
                Severity           TEXT NOT NULL,
                Description        TEXT NOT NULL,
                Action             TEXT NOT NULL,
                Recommendation     TEXT,
                CurrentUser        TEXT,
                MachineName        TEXT,
                CreatedAt          TEXT NOT NULL DEFAULT (datetime('now'))
            );", usbConn);
        usbCmd.ExecuteNonQuery();
    }

    public static void SeedDefaultAdmin(SQLiteConnection connection, string adminPassword = "Admin@123")
    {
        using var checkCmd = new SQLiteCommand("SELECT COUNT(1) FROM Users WHERE UserName='admin'", connection);
        if ((long)checkCmd.ExecuteScalar() > 0) return;

        string userId = Guid.NewGuid().ToString("N");
        var (pwdHash, pwdSalt, pwdIterations) = PasswordHasher.HashPassword(adminPassword);
        var (pubKeyDer, privKeyPkcs8) = RsaEncryption.GenerateKeyPair();
        string publicKeyPem = RsaEncryption.ExportPublicKeyPem(pubKeyDer);

        byte[] kekSalt = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(kekSalt);
        byte[] kek = PasswordHasher.DeriveKEK(adminPassword, kekSalt);
        var (encPrivKey, privKeyTag, privKeyIV) = AesGcmEncryption.Encrypt(privKeyPkcs8, kek);

        using var transaction = connection.BeginTransaction();
        try
        {
            using var cmdUser = new SQLiteCommand(@"INSERT INTO Users (UserID, UserName, DisplayName, PasswordHash, PasswordSalt, HashIterations, RoleID)
                VALUES (@uid, 'admin', '系统管理员', @phash, @psalt, @piter, 0)", connection);
            cmdUser.Parameters.AddWithValue("@uid", userId);
            cmdUser.Parameters.AddWithValue("@phash", Convert.ToBase64String(pwdHash));
            cmdUser.Parameters.AddWithValue("@psalt", Convert.ToBase64String(pwdSalt));
            cmdUser.Parameters.AddWithValue("@piter", pwdIterations);
            cmdUser.ExecuteNonQuery();

            string keyId = Guid.NewGuid().ToString("N");
            using var cmdKey = new SQLiteCommand(@"INSERT INTO KeyPairs (KeyID, UserID, PublicKey, PrivateKeyEnc, PrivateKeyIV, PrivateKeyTag, KeySalt, KeyIterations, KeySizeBits, ExpiresAt)
                VALUES (@kid, @uid, @pub, @priv, @iv, @tag, @ksalt, 100000, 2048, datetime('now', '+90 days'))", connection);
            cmdKey.Parameters.AddWithValue("@kid", keyId);
            cmdKey.Parameters.AddWithValue("@uid", userId);
            cmdKey.Parameters.AddWithValue("@pub", publicKeyPem);
            cmdKey.Parameters.AddWithValue("@priv", Convert.ToBase64String(encPrivKey));
            cmdKey.Parameters.AddWithValue("@iv", Convert.ToBase64String(privKeyIV));
            cmdKey.Parameters.AddWithValue("@tag", Convert.ToBase64String(privKeyTag));
            cmdKey.Parameters.AddWithValue("@ksalt", Convert.ToBase64String(kekSalt));
            cmdKey.ExecuteNonQuery();

            transaction.Commit();
        }
        catch { transaction.Rollback(); }
    }
}
