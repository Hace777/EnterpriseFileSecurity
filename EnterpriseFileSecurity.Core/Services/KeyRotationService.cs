using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Security.Cryptography;
using EnterpriseFileSecurity.Common;
using EnterpriseFileSecurity.Core.Crypto;

namespace EnterpriseFileSecurity.Core.Services;

public class KeyRotationService : IKeyRotationService
{
    private readonly SQLiteConnection _connection;
    private readonly IAuthenticationService _authService;

    public KeyRotationService(SQLiteConnection connection, IAuthenticationService authService)
    {
        _connection = connection;
        _authService = authService;
    }

    public List<string> CheckExpiringKeys()
    {
        var expiringUsers = new List<string>();
        string sql = @"SELECT DISTINCT UserID FROM KeyPairs
            WHERE IsActive=1 AND RevokedAt IS NULL
            AND ExpiresAt <= datetime('now', '+7 days')";
        using var cmd = new SQLiteCommand(sql, _connection);
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) expiringUsers.Add(reader.GetString(0));
        return expiringUsers;
    }

    public (bool success, RotationRecord rotation) RotateKeys(
        string userId, string password, string trigger = "SCHEDULED")
    {
        string rotationID = Guid.NewGuid().ToString("N");
        var rotation = new RotationRecord
        {
            RotationID = rotationID,
            UserID = userId,
            RotationTrigger = trigger,
            Status = "RUNNING"
        };

        var oldKeyPair = _authService.GetActiveKeyPair(userId);
        if (oldKeyPair == null)
            throw new InvalidOperationException("用户没有活跃密钥对");

        byte[] oldKekSalt = Convert.FromBase64String(oldKeyPair.KeySalt);
        byte[] oldKek = PasswordHasher.DeriveKEK(password, oldKekSalt);
        byte[] oldEncPrivKey = Convert.FromBase64String(oldKeyPair.PrivateKeyEnc);
        byte[] oldPrivKeyIV = Convert.FromBase64String(oldKeyPair.PrivateKeyIV);
        byte[] oldPrivKeyTag = Convert.FromBase64String(oldKeyPair.PrivateKeyTag);
        byte[] oldPrivKey = AesGcmEncryption.Decrypt(oldEncPrivKey, oldKek, oldPrivKeyIV, oldPrivKeyTag);

        var (newPubKeyDer, newPrivKeyPkcs8) = RsaEncryption.GenerateKeyPair();
        string newPublicKeyPem = RsaEncryption.ExportPublicKeyPem(newPubKeyDer);

        byte[] newKekSalt = new byte[16];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(newKekSalt);
        byte[] newKek = PasswordHasher.DeriveKEK(password, newKekSalt);
        var (newEncPrivKey, newPrivKeyTag, newPrivKeyIV) = AesGcmEncryption.Encrypt(newPrivKeyPkcs8, newKek);

        string newKeyID = Guid.NewGuid().ToString("N");
        InsertKeyPair(newKeyID, userId, newPublicKeyPem,
            Convert.ToBase64String(newEncPrivKey),
            Convert.ToBase64String(newPrivKeyIV),
            Convert.ToBase64String(newPrivKeyTag),
            Convert.ToBase64String(newKekSalt));

        RevokeKeyPair(oldKeyPair.KeyID);

        using var transaction = _connection.BeginTransaction();
        try
        {
            string insertSql = @"INSERT INTO KeyRotationHistory
                (RotationID, UserID, OldKeyID, NewKeyID, FilesProcessed,
                 FilesFailed, RotationTrigger, StartedAt, CompletedAt, Status)
                VALUES (@rid, @uid, @old, @new, 0, 0, @trig,
                        datetime('now'), datetime('now'), 'COMPLETED')";
            using var cmd = new SQLiteCommand(insertSql, _connection);
            cmd.Parameters.AddWithValue("@rid", rotationID);
            cmd.Parameters.AddWithValue("@uid", userId);
            cmd.Parameters.AddWithValue("@old", oldKeyPair.KeyID);
            cmd.Parameters.AddWithValue("@new", newKeyID);
            cmd.Parameters.AddWithValue("@trig", trigger);
            cmd.ExecuteNonQuery();
            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }

        rotation.OldKeyID = oldKeyPair.KeyID;
        rotation.NewKeyID = newKeyID;
        rotation.Status = "COMPLETED";
        Array.Clear(oldPrivKey, 0, oldPrivKey.Length);
        return (true, rotation);
    }

    private void InsertKeyPair(string keyID, string userId,
        string publicKey, string privKeyEnc, string privKeyIV,
        string privKeyTag, string keySalt)
    {
        string sql = @"INSERT INTO KeyPairs
            (KeyID, UserID, PublicKey, PrivateKeyEnc, PrivateKeyIV,
             PrivateKeyTag, KeySalt, KeyIterations, KeySizeBits, IsActive, ExpiresAt)
            VALUES (@kid, @uid, @pub, @privenc, @priviv, @privtag,
                    @ksalt, 100000, 2048, 1, datetime('now', '+90 days'))";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@kid", keyID);
        cmd.Parameters.AddWithValue("@uid", userId);
        cmd.Parameters.AddWithValue("@pub", publicKey);
        cmd.Parameters.AddWithValue("@privenc", privKeyEnc);
        cmd.Parameters.AddWithValue("@priviv", privKeyIV);
        cmd.Parameters.AddWithValue("@privtag", privKeyTag);
        cmd.Parameters.AddWithValue("@ksalt", keySalt);
        cmd.ExecuteNonQuery();
    }

    private void RevokeKeyPair(string keyId)
    {
        string sql = "UPDATE KeyPairs SET IsActive=0, RevokedAt=datetime('now') WHERE KeyID=@kid";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.Parameters.AddWithValue("@kid", keyId);
        cmd.ExecuteNonQuery();
    }
}
