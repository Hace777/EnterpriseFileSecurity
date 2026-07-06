using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.Core.Services;

public class AccessControlEngine : IAccessControlEngine
{
    private readonly RbacPolicyDocument _policy;
    private readonly Dictionary<string, List<string>> _rolePermCache;

    public static readonly string DefaultPolicyJson = @"{
  ""version"": ""1.0"",
  ""roles"": [
    {""name"":""总经理"",""code"":""GeneralManager"",""priority"":1,
     ""permissions"":{""S"":[""Read"",""Write"",""Delete"",""Share""],""A"":[""Read"",""Write"",""Delete"",""Share""],""B"":[""Read"",""Write"",""Delete"",""Share""],""C"":[""Read"",""Write"",""Delete"",""Share""],""D"":[""Read"",""Write"",""Delete"",""Share""]}},
    {""name"":""经理"",""code"":""Manager"",""priority"":2,
     ""permissions"":{""S"":[""Read""],""A"":[""Read"",""Write"",""Delete"",""Share""],""B"":[""Read"",""Write"",""Delete"",""Share""],""C"":[""Read"",""Write"",""Delete"",""Share""],""D"":[""Read"",""Write"",""Delete"",""Share""]}},
    {""name"":""员工"",""code"":""Employee"",""priority"":3,
     ""permissions"":{""C"":[""Read"",""Write"",""Delete""],""D"":[""Read"",""Write"",""Delete""]}},
    {""name"":""实习生"",""code"":""Intern"",""priority"":4,
     ""permissions"":{""D"":[""Read""]}}
  ]
}";

    public AccessControlEngine(string? policyJson = null)
    {
        _policy = JsonSerializer.Deserialize<RbacPolicyDocument>(
            policyJson ?? DefaultPolicyJson,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;

        _rolePermCache = new Dictionary<string, List<string>>();
        foreach (var role in _policy.Roles)
        {
            var flatPerms = new List<string>();
            if (role.Permissions != null)
            {
                foreach (var kv in role.Permissions)
                    foreach (var op in kv.Value)
                        flatPerms.Add($"{kv.Key}:{op}");
            }
            _rolePermCache[role.Code] = flatPerms;
        }
    }

    public AccessDecision CheckPermission(
        string userId, UserRole role, FileOperationType operation,
        int fileLevel, string filePath)
    {
        string roleCode = RoleCodeFromEnum(role);
        string levelCode = LevelCodeFromInt(fileLevel);
        string opCode = OpCodeFromEnum(operation);

        if (!_rolePermCache.TryGetValue(roleCode, out var allowedPerms))
        {
            return new AccessDecision
            {
                Allowed = false,
                Reason = $"角色 {role} 未在策略中定义"
            };
        }

        string requiredPerm = $"{levelCode}:{opCode}";
        if (allowedPerms.Contains(requiredPerm))
        {
            return new AccessDecision
            {
                Allowed = true,
                Reason = $"允许：{role} 对 {levelCode} 级文件有 {opCode} 权限"
            };
        }

        return new AccessDecision
        {
            Allowed = false,
            Reason = $"拒绝：{role} 对 {levelCode} 级文件没有 {opCode} 权限"
        };
    }

    public int GetFileSecurityLevel(string filePath)
    {
        string? dir = Path.GetDirectoryName(filePath);
        if (dir == null) return 4;
        if (dir.Contains("\\S-")) return 0;
        if (dir.Contains("\\A-")) return 1;
        if (dir.Contains("\\B-")) return 2;
        if (dir.Contains("\\C-")) return 3;
        return 4;
    }

    public List<string> GetAuthorizedUsers(string filePath) => new() { "" };

    private static string RoleCodeFromEnum(UserRole role) => role switch
    {
        UserRole.GeneralManager => "GeneralManager",
        UserRole.Manager => "Manager",
        UserRole.Employee => "Employee",
        UserRole.Intern => "Intern",
        _ => "Employee"
    };

    private static string LevelCodeFromInt(int level) => level switch
    {
        0 => "S", 1 => "A", 2 => "B", 3 => "C", 4 => "D", _ => "D"
    };

    private static string OpCodeFromEnum(FileOperationType op) => op switch
    {
        FileOperationType.Read => "Read",
        FileOperationType.Write => "Write",
        FileOperationType.Delete => "Delete",
        FileOperationType.Share => "Share",
        FileOperationType.Move => "Write",
        FileOperationType.Download => "Read",
        _ => "Read"
    };
}
