using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Data.SQLite;
using System.Threading;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.Core.Services;

public class AuditLogger : IAuditLogger, IDisposable
{
    private readonly string _connectionString;
    private readonly BlockingCollection<AuditEntry> _writeQueue;
    private readonly Thread _writerThread;
    private volatile bool _disposed;
    private static int _instanceCount;

    public AuditLogger(string dbPath)
    {
        // Prevent BlockingCollection constructor hang: use a bounded capacity
        _writeQueue = new BlockingCollection<AuditEntry>(new ConcurrentQueue<AuditEntry>(), 10000);
        _connectionString = $"Data Source={dbPath};Version=3;";
        InitializeSchema();
        _writerThread = new Thread(WriterLoop)
        {
            IsBackground = true,
            Name = $"AuditLogWriter-{Interlocked.Increment(ref _instanceCount)}"
        };
        _writerThread.Start();
    }

    private void InitializeSchema()
    {
        try
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();
            string sql = @"
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
                CREATE INDEX IF NOT EXISTS idx_audit_user_time ON AuditLog(UserID, Timestamp);";
            using var cmd = new SQLiteCommand(sql, conn);
            cmd.ExecuteNonQuery();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuditLogger] Schema init failed: {ex.Message}");
        }
    }

    public void LogAsync(AuditEntry entry)
    {
        if (_disposed || _writeQueue.IsAddingCompleted) return;
        // Non-blocking add
        _writeQueue.TryAdd(entry);
    }

    public void LogSync(AuditEntry entry)
    {
        try
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();
            InsertEntry(conn, entry);
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuditLogger] Sync write failed: {ex.Message}");
        }
    }

    private void WriterLoop()
    {
        while (!_disposed)
        {
            try
            {
                // TryTake with timeout to allow clean shutdown
                if (_writeQueue.TryTake(out var entry, TimeSpan.FromMilliseconds(500)))
                {
                    using var conn = new SQLiteConnection(_connectionString);
                    conn.Open();
                    InsertEntry(conn, entry);
                }
            }
            catch (ThreadAbortException) { break; }
            catch (ThreadInterruptedException) { break; }
            catch { /* Silently continue; don't crash the writer thread */ }
        }
    }

    private static void InsertEntry(SQLiteConnection conn, AuditEntry entry)
    {
        string sql = @"INSERT INTO AuditLog (
            AuditID, UserID, UserName, Timestamp, FilePath, FileName,
            OperationType, Result, Detail, FileSize, ProcessName,
            MachineName, SessionID, FileSecurityLevel)
            VALUES (@aid, @uid, @uname, @ts, @fpath, @fname,
            @optype, @result, @detail, @fsize, @pname, @mname, @sid, @fle)";
        using var cmd = new SQLiteCommand(sql, conn);
        cmd.Parameters.AddWithValue("@aid", entry.AuditID);
        cmd.Parameters.AddWithValue("@uid", entry.UserID ?? "");
        cmd.Parameters.AddWithValue("@uname", entry.UserName ?? "");
        cmd.Parameters.AddWithValue("@ts", entry.Timestamp.ToString("o"));
        cmd.Parameters.AddWithValue("@fpath", entry.FilePath ?? "");
        cmd.Parameters.AddWithValue("@fname", entry.FileName ?? "");
        cmd.Parameters.AddWithValue("@optype", entry.OperationType.ToString());
        cmd.Parameters.AddWithValue("@result", entry.Result.ToString());
        cmd.Parameters.AddWithValue("@detail", entry.Detail ?? "");
        cmd.Parameters.AddWithValue("@fsize", entry.FileSize.HasValue ? (object)entry.FileSize.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("@pname", entry.ProcessName ?? "");
        cmd.Parameters.AddWithValue("@mname", entry.MachineName ?? "");
        cmd.Parameters.AddWithValue("@sid", entry.SessionID ?? "");
        cmd.Parameters.AddWithValue("@fle", entry.FileSecurityLevel ?? "D");
        cmd.ExecuteNonQuery();
    }

    public List<AuditEntry> QueryByUser(string userId, DateTime from, DateTime to)
    {
        var results = new List<AuditEntry>();
        try
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();
            string sql = @"SELECT AuditID, UserID, UserName, Timestamp, FilePath,
                FileName, OperationType, Result, Detail FROM AuditLog
                WHERE UserID=@uid AND Timestamp BETWEEN @from AND @to
                ORDER BY Timestamp DESC LIMIT 500";
            using var cmd = new SQLiteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@uid", userId);
            cmd.Parameters.AddWithValue("@from", from.ToString("o"));
            cmd.Parameters.AddWithValue("@to", to.ToString("o"));
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(new AuditEntry
                {
                    AuditID = reader.GetString(0),
                    UserID = reader.GetString(1),
                    UserName = reader.GetString(2),
                    Timestamp = DateTime.Parse(reader.GetString(3)),
                    FilePath = reader.GetString(4),
                    OperationType = Enum.Parse<FileOperationType>(reader.GetString(6)),
                    Result = Enum.Parse<AuditResult>(reader.GetString(7)),
                    Detail = reader.IsDBNull(8) ? null : reader.GetString(8)
                });
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuditLogger] Query failed: {ex.Message}");
        }
        return results;
    }

    public List<AuditEntry> QueryAll(DateTime from, DateTime to, int limit = 500)
    {
        var results = new List<AuditEntry>();
        try
        {
            using var conn = new SQLiteConnection(_connectionString);
            conn.Open();
            string sql = @"SELECT AuditID, UserID, UserName, Timestamp, FilePath,
                FileName, OperationType, Result, Detail, FileSize, ProcessName,
                MachineName, SessionID, FileSecurityLevel FROM AuditLog
                WHERE Timestamp BETWEEN @from AND @to
                ORDER BY Timestamp DESC LIMIT @limit";
            using var cmd = new SQLiteCommand(sql, conn);
            cmd.Parameters.AddWithValue("@from", from.ToString("o"));
            cmd.Parameters.AddWithValue("@to", to.ToString("o"));
            cmd.Parameters.AddWithValue("@limit", limit);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                results.Add(new AuditEntry
                {
                    AuditID = reader.GetString(0),
                    UserID = reader.GetString(1),
                    UserName = reader.GetString(2),
                    Timestamp = DateTime.Parse(reader.GetString(3)),
                    FilePath = reader.GetString(4),
                    // FileName is computed from FilePath
                    OperationType = Enum.Parse<FileOperationType>(reader.GetString(6)),
                    Result = Enum.Parse<AuditResult>(reader.GetString(7)),
                    Detail = reader.IsDBNull(8) ? null : reader.GetString(8),
                    FileSize = reader.IsDBNull(9) ? null : reader.GetInt64(9),
                    ProcessName = reader.IsDBNull(10) ? null : reader.GetString(10),
                    MachineName = reader.IsDBNull(11) ? null : reader.GetString(11),
                    SessionID = reader.IsDBNull(12) ? null : reader.GetString(12),
                    FileSecurityLevel = reader.IsDBNull(13) ? null : reader.GetString(13)
                });
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[AuditLogger] QueryAll failed: {ex.Message}");
        }
        return results;
    }

    public string ExportToCsv(List<AuditEntry> entries)
    {
        var sb = new System.Text.StringBuilder();
        // Write CSV header
        sb.AppendLine("AuditID,UserID,UserName,Timestamp,FilePath,FileName,OperationType,Result,Detail,FileSize,ProcessName,MachineName,SessionID,FileSecurityLevel");
        // Write data rows
        foreach (var e in entries)
        {
            sb.Append(CsvEscape(e.AuditID)); sb.Append(',');
            sb.Append(CsvEscape(e.UserID)); sb.Append(',');
            sb.Append(CsvEscape(e.UserName)); sb.Append(',');
            sb.Append(CsvEscape(e.Timestamp.ToString("o"))); sb.Append(',');
            sb.Append(CsvEscape(e.FilePath)); sb.Append(',');
            sb.Append(CsvEscape(e.FileName)); sb.Append(',');
            sb.Append(CsvEscape(e.OperationType.ToString())); sb.Append(',');
            sb.Append(CsvEscape(e.Result.ToString())); sb.Append(',');
            sb.Append(CsvEscape(e.Detail)); sb.Append(',');
            sb.Append(e.FileSize?.ToString() ?? ""); sb.Append(',');
            sb.Append(CsvEscape(e.ProcessName)); sb.Append(',');
            sb.Append(CsvEscape(e.MachineName)); sb.Append(',');
            sb.Append(CsvEscape(e.SessionID)); sb.Append(',');
            sb.AppendLine(CsvEscape(e.FileSecurityLevel));
        }
        return sb.ToString();
    }

    private static string CsvEscape(string? field)
    {
        if (field == null) return "";
        if (field.Contains(',') || field.Contains('"') || field.Contains('\n') || field.Contains('\r'))
        {
            return "\"" + field.Replace("\"", "\"\"") + "\"";
        }
        return field;
    }

    public void Dispose()
    {
        _disposed = true;
        _writeQueue.CompleteAdding();
        _writerThread.Join(3000);
        _writeQueue.Dispose();
    }
}
