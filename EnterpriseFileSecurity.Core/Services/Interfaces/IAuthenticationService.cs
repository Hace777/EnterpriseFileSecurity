using System;
using System.Collections.Generic;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.Core.Services;

public interface IAuthenticationService
{
    (bool success, string userId, string error) RegisterUser(string userName, string password, string displayName, int roleID);
    AuthResult Login(string userName, string password);
    (byte[] fek, List<(string userId, byte[] efek)> efekList) GenerateAndEncryptFEK(List<string> authorizedUserIds);
    byte[] DecryptFEK(byte[] efek, byte[] privateKeyPkcs8);
    KeyPairRecord GetActiveKeyPair(string userId);

    // ── 管理员用户管理 ──
    List<UserRecord> ListAllUsers();
    bool DeleteUser(string userId);
    bool UpdateUserRole(string userId, int newRoleID);
    bool ResetUserPassword(string userId, string newPassword);
    bool UnlockUser(string userId);
}