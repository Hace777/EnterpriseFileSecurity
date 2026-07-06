namespace EnterpriseFileSecurity.Common;

public enum BlockReason
{
    NotInWhitelist = 1,
    MaliciousDevice = 2,
    BlacklistedVendor = 3,
    PolicyDenied = 4
}
