using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Security.Cryptography;
using EnterpriseFileSecurity.Common;
using EnterpriseFileSecurity.Core.Crypto;

namespace EnterpriseFileSecurity.Core.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly SQLiteConnection _connection;
    private const int MaxFailedAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    public AuthenticationService(SQLiteConnection connection)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
    }

    public (bool success, string userId, string error) RegisterUser(
        string userName, string password, string displayName, int roleID)
    {
        if (UserExists(userName))
            return (false, null, "用户名已存在");

        string userID = Guid.NewGuid().ToString("N");

        var (pwdHash, pwdSalt, pwdIterations) = PasswordHasher.HashPassword(password);
        var (pubKeyDer, privKeyPkcs8) = RsaEncryption.GenerateKeyPair();
        string publicKeyPem = RsaEncryption.ExportPublicKeyPem(pubKeyDer);

        byte[] kekSalt = new byte[16];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(kekSalt);
        byte[] kek = PasswordHasher.DeriveKEK(password, kekSalt);
        var (encPrivKey, privKeyTag, privKeyIV) = AesGcmEncryption.Encrypt(privKeyPkcs8, kek);

        using var transaction = _connection.BeginTransaction();
        try
        {
            string insertUserSql = @"INSERT INTO Users (UserID, UserName, DisplayName, PasswordHash,
                PasswordSalt, HashIterations, RoleID)
                VALUES (@uid, @uname, @dname, @phash, @psalt, @piter, @role)";
            using var cmdUser = new SQLiteCommand(insertUserSql, _connection);
            cmdUser.Parameters.AddWithValue("@uid", userID);
            cmdUser.Parameters.AddWithValue("@uname", userName);
            cmdUser.Parameters.AddWithValue("@dname", displayName ?? "");
            cmdUser.Parameters.AddWithValue("@phash", Convert.ToBase64String(pwdHash));
            cmdUser.Parameters.AddWithValue("@psalt", Convert.ToBase64String(pwdSalt));
            cmdUser.Parameters.AddWithValue("@piter", pwdIterations);
            cmdUser.Parameters.AddWithValue("@role", roleID);
            cmdUser.ExecuteNonQuery();

            string keyID = Guid.NewGuid().ToString("N");
            string insertKeySql = @"INSERT INTO KeyPairs (KeyID, UserID, PublicKey, PrivateKeyEnc,
                PrivateKeyIV, PrivateKeyTag, KeySalt, KeyIterations, KeySizeBits, ExpiresAt)
                VALUES (@kid, @uid, @pub, @priv, @iv, @tag, @ksalt, @kiter, @kbits,
                datetime('now', '+90 days'))";
            using var cmdKey = new SQLiteCommand(insertKeySql, _connection);
            cmdKey.Parameters.AddWithValue("@kid", keyID);
            cmdKey.Parameters.AddWithValue("@uid", userID);
            cmdKey.Parameters.AddWithValue("@pub", publicKeyPem);
            cmdKey.Parameters.AddWithValue("@priv", Convert.ToBase64String(encPrivKey));
            cmdKey.Parameters.AddWithValue("@iv", Convert.ToBase64String(privKeyIV));
            cmdKey.Parameters.AddWithValue("@tag", Convert.ToBase64String(privKeyTag));
            cmdKey.Parameters.AddWithValue("@ksalt", Convert.ToBase64String(kekSalt));
            cmdKey.Parameters.AddWithValue("@kiter", 100000);
            cmdKey.Parameters.AddWithValue("@kbits", 2048);
            cmdKey.ExecuteNonQuery();

            transaction.Commit();
            return (true, userID, null);
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    public AuthResult Login(string userName, string password)
    {
        var result = new AuthResult();

        var user = GetUserByUserName(userName);
        if (user == null)
        {
            result.ErrorMessage = "用户名或密码错误";
            return result;
        }

        if (user.IsLocked)
        {
            if (user.LockUntil.HasValue && user.LockUntil.Value > DateTime.UtcNow)
            {
                result.IsLocked = true;
                result.ErrorMessage = $"账号已锁定，请于 {user.LockUntil.Value:HH:mm:ss} 后重试";
                return result;
            }
            UnlockAccount(user.UserID);
            user.IsLocked = false;
            user.FailedAttempts = 0;
        }

        byte[] storedHash = Convert.FromBase64String(user.PasswordHash);
        byte[] storedSalt = Convert.FromBase64String(user.PasswordSalt);
        bool passwordValid = PasswordHasher.VerifyPassword(
            password, storedHash, storedSalt, user.HashIterations);

        if (!passwordValid)
        {
            int newFailedCount = user.FailedAttempts + 1;
            UpdateFailedAttempts(user.UserID, newFailedCount);
            if (newFailedCount >= MaxFailedAttempts)
            {
                LockAccount(user.UserID, DateTime.UtcNow.Add(LockoutDuration));
                result.IsLocked = true;
                result.ErrorMessage = $"密码连续错误{MaxFailedAttempts}次，账号已锁定15分钟";
            }
            else
            {
                result.ErrorMessage = $"用户名或密码错误（剩余尝试次数：{MaxFailedAttempts - newFailedCount}）";
            }
            return result;
        }

        ResetFailedAttempts(user.UserID);

        var keyPair = GetActiveKeyPair(user.UserID);
        if (keyPair == null)
        {
            result.ErrorMessage = "密钥对不存在，请联系管理员";
            return result;
        }

        byte[] kekSalt = Convert.FromBase64String(keyPair.KeySalt);
        byte[] kek = PasswordHasher.DeriveKEK(password, kekSalt, keyPair.KeyIterations);
        byte[] encPrivKey = Convert.FromBase64String(keyPair.PrivateKeyEnc);
        byte[] privKeyIV = Convert.FromBase64String(keyPair.PrivateKeyIV);
        byte[] privKeyTag = Convert.FromBase64String(keyPair.PrivateKeyTag);

        byte[] privateKeyPkcs8;
        try
        {
            privateKeyPkcs8 = AesGcmEncryption.Decrypt(encPrivKey, kek, privKeyIV, privKeyTag);
        }
        catch (CryptographicException)
        {
            result.ErrorMessage = "私钥解密失败（密钥数据可能已损坏）";
            return result;
        }

        string sessionToken = GenerateSessionToken(user.UserID, user.RoleID);

        result.Success = true;
        result.UserID = user.UserID;
        result.UserName = user.UserName;
        result.RoleID = user.RoleID;
        result.SessionToken = sessionToken;
        result.PrivateKey = privateKeyPkcs8;
        return result;
    }

    public (byte[] fek, List<(string userId, byte[] efek)> efekList)
        GenerateAndEncryptFEK(List<string> authorizedUserIds)
    {
        byte[] fek = AesGcmEncryption.GenerateAesKey();
        var efekList = new List<(string userId, byte[] efek)>();
        foreach (string userId in authorizedUserIds)
        {
            var keyPair = GetActiveKeyPair(userId);
            if (keyPair == null)
                throw new InvalidOperationException($"用户 {userId} 没有活跃密钥对");
            byte[] publicKeyDer = RsaEncryption.ParsePublicKeyPem(keyPair.PublicKey);
            byte[] efek = RsaEncryption.EncryptWithPublicKey(fek, publicKeyDer);
            efekList.Add((userId, efek));
        }
        return (fek, efekList);
    }

    public byte[] DecryptFEK(byte[] efek, byte[] privateKeyPkcs8)
        => RsaEncryption.DecryptWithPrivateKey(efek, privateKeyPkcs8);

    private bool UserExists(string userName)
    {
        string sql = "SELECT COUNT(1) FROM Users WHERE UserName=@uname AND IsDeleted=0";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@uname", userName);
        return (long)(cmd.ExecuteScalar() ?? 0L) > 0;
    }

    private UserRecord GetUserByUserName(string userName)
    {
        string sql = @"SELECT UserID, UserName, DisplayName, PasswordHash,
            PasswordSalt, HashIterations, RoleID, IsLocked, LockUntil,
            FailedAttempts FROM Users WHERE UserName=@uname AND IsDeleted=0";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@uname", userName);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return new UserRecord
        {
            UserID = reader.GetString(0),
            UserName = reader.GetString(1),
            DisplayName = reader.IsDBNull(2) ? null : reader.GetString(2),
            PasswordHash = reader.GetString(3),
            PasswordSalt = reader.GetString(4),
            HashIterations = reader.GetInt32(5),
            RoleID = reader.GetInt32(6),
            IsLocked = reader.GetInt32(7) == 1,
            LockUntil = reader.IsDBNull(8) ? null : DateTime.Parse(reader.GetString(8)),
            FailedAttempts = reader.GetInt32(9)
        };
    }

    public KeyPairRecord GetActiveKeyPair(string userId)
    {
        string sql = @"SELECT KeyID, UserID, PublicKey, PrivateKeyEnc,
            PrivateKeyIV, PrivateKeyTag, KeySalt, KeyIterations, KeySizeBits,
            IsActive, CreatedAt, ExpiresAt FROM KeyPairs
            WHERE UserID=@uid AND IsActive=1 AND RevokedAt IS NULL
            ORDER BY CreatedAt DESC LIMIT 1";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@uid", userId);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return new KeyPairRecord
        {
            KeyID = reader.GetString(0),
            UserID = reader.GetString(1),
            PublicKey = reader.GetString(2),
            PrivateKeyEnc = reader.GetString(3),
            PrivateKeyIV = reader.GetString(4),
            PrivateKeyTag = reader.GetString(5),
            KeySalt = reader.GetString(6),
            KeyIterations = reader.GetInt32(7),
            KeySizeBits = reader.GetInt32(8),
            IsActive = reader.GetInt32(9) == 1,
            CreatedAt = DateTime.Parse(reader.GetString(10)),
            ExpiresAt = reader.IsDBNull(11) ? null : DateTime.Parse(reader.GetString(11))
        };
    }

    private void UpdateFailedAttempts(string userId, int count)
    {
        string sql = "UPDATE Users SET FailedAttempts=@cnt, UpdatedAt=datetime('now') WHERE UserID=@uid";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@cnt", count);
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.ExecuteNonQuery();
    }

    private void ResetFailedAttempts(string userId)
    {
        string sql = "UPDATE Users SET FailedAttempts=0, IsLocked=0, LockUntil=NULL, UpdatedAt=datetime('now') WHERE UserID=@uid";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.ExecuteNonQuery();
    }

    private void LockAccount(string userId, DateTime lockUntil)
    {
        string sql = "UPDATE Users SET IsLocked=1, LockUntil=@lt, UpdatedAt=datetime('now') WHERE UserID=@uid";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@lt", lockUntil.ToString("o"));
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.ExecuteNonQuery();
    }

    private void UnlockAccount(string userId) => ResetFailedAttempts(userId);

    private string GenerateSessionToken(string userId, int roleId)
    {
        byte[] tokenData = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(tokenData);
        return Convert.ToBase64String(tokenData);
    }

    public List<UserRecord> ListAllUsers()
    {
        string sql = @"SELECT UserID, UserName, DisplayName, RoleID, IsLocked,
            FailedAttempts, CreatedAt FROM Users WHERE IsDeleted=0";
        using var cmd = new SQLiteCommand(sql, _connection);
        using var reader = cmd.ExecuteReader();
        var users = new List<UserRecord>();
        while (reader.Read())
        {
            users.Add(new UserRecord
            {
                UserID = reader.GetString(0),
                UserName = reader.GetString(1),
                DisplayName = reader.IsDBNull(2) ? null : reader.GetString(2),
                RoleID = reader.GetInt32(3),
                IsLocked = reader.GetInt32(4) == 1,
                FailedAttempts = reader.GetInt32(5),
                CreatedAt = DateTime.Parse(reader.GetString(6))
            });
        }
        return users;
    }

    public bool DeleteUser(string userId)
    {
        string sql = "UPDATE Users SET IsDeleted=1, UpdatedAt=datetime('now') WHERE UserID=@uid";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@uid", userId);
        return cmd.ExecuteNonQuery() > 0;
    }

    public bool UpdateUserRole(string userId, int newRoleID)
    {
        string sql = "UPDATE Users SET RoleID=@role, UpdatedAt=datetime('now') WHERE UserID=@uid";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@role", newRoleID);
        cmd.Parameters.AddWithValue("@uid", userId);
        return cmd.ExecuteNonQuery() > 0;
    }

    public bool ResetUserPassword(string userId, string newPassword)
    {
        var (pwdHash, pwdSalt, pwdIterations) = PasswordHasher.HashPassword(newPassword);
        var (pubKeyDer, privKeyPkcs8) = RsaEncryption.GenerateKeyPair();
        string publicKeyPem = RsaEncryption.ExportPublicKeyPem(pubKeyDer);

        byte[] kekSalt = new byte[16];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(kekSalt);
        byte[] kek = PasswordHasher.DeriveKEK(newPassword, kekSalt);
        var (encPrivKey, privKeyTag, privKeyIV) = AesGcmEncryption.Encrypt(privKeyPkcs8, kek);

        using var transaction = _connection.BeginTransaction();
        try
        {
            string updateUserSql = @"UPDATE Users SET PasswordHash=@phash, PasswordSalt=@psalt,
                HashIterations=@piter, UpdatedAt=datetime('now') WHERE UserID=@uid";
            using var cmdUser = new SQLiteCommand(updateUserSql, _connection);
            cmdUser.Parameters.AddWithValue("@phash", Convert.ToBase64String(pwdHash));
            cmdUser.Parameters.AddWithValue("@psalt", Convert.ToBase64String(pwdSalt));
            cmdUser.Parameters.AddWithValue("@piter", pwdIterations);
            cmdUser.Parameters.AddWithValue("@uid", userId);
            cmdUser.ExecuteNonQuery();

            string updateKeySql = @"UPDATE KeyPairs SET PublicKey=@pub, PrivateKeyEnc=@priv,
                PrivateKeyIV=@iv, PrivateKeyTag=@tag, KeySalt=@ksalt, KeyIterations=@kiter,
                ExpiresAt=datetime('now', '+90 days')
                WHERE UserID=@uid AND IsActive=1 AND RevokedAt IS NULL";
            using var cmdKey = new SQLiteCommand(updateKeySql, _connection);
            cmdKey.Parameters.AddWithValue("@pub", publicKeyPem);
            cmdKey.Parameters.AddWithValue("@priv", Convert.ToBase64String(encPrivKey));
            cmdKey.Parameters.AddWithValue("@iv", Convert.ToBase64String(privKeyIV));
            cmdKey.Parameters.AddWithValue("@tag", Convert.ToBase64String(privKeyTag));
            cmdKey.Parameters.AddWithValue("@ksalt", Convert.ToBase64String(kekSalt));
            cmdKey.Parameters.AddWithValue("@kiter", 100000);
            cmdKey.Parameters.AddWithValue("@uid", userId);
            cmdKey.ExecuteNonQuery();

            transaction.Commit();
            return true;
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    public bool UnlockUser(string userId) { ResetFailedAttempts(userId); return true; }
}
