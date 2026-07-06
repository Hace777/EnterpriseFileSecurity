using System.Threading;

namespace EnterpriseFileSecurity.Common;

public static class SessionContext
{
    private static readonly AsyncLocal<SessionData> _session = new AsyncLocal<SessionData>();

    public static void SetSession(string userId, UserRole role, byte[] privateKey)
    {
        _session.Value = new SessionData
        {
            UserID = userId,
            Role = role,
            PrivateKey = privateKey
        };
    }

    public static void ClearSession()
    {
        _session.Value = null;
    }

    public static string CurrentUserID => _session.Value?.UserID;
    public static UserRole CurrentRole => _session.Value?.Role ?? UserRole.Intern;
    public static byte[] CurrentPrivateKey => _session.Value?.PrivateKey;
    public static bool IsAuthenticated => _session.Value != null;

    private class SessionData
    {
        public string UserID { get; set; }
        public UserRole Role { get; set; }
        public byte[] PrivateKey { get; set; }
    }
}
