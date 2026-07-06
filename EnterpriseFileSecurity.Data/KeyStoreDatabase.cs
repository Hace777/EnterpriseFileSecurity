using System;
using System.Data.SQLite;

namespace EnterpriseFileSecurity.Data;

public class KeyStoreDatabase : IDisposable
{
    private readonly SQLiteConnection _connection;

    public KeyStoreDatabase(string dbPath)
    {
        _connection = new SQLiteConnection($"Data Source={dbPath};Version=3;");
        _connection.Open();
        InitializeSchema();
    }

    public SQLiteConnection Connection => _connection;

    private void InitializeSchema()
    {
        string sql = @"
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
            );
        ";
        using var cmd = new SQLiteCommand(sql, _connection);
        cmd.ExecuteNonQuery();
    }

    public void Dispose() => _connection?.Dispose();
}
