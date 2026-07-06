namespace EnterpriseFileSecurity.Common;

public enum UsbAlertType
{
    UnauthorizedDeviceBlocked,
    AuthorizedDeviceAllowed,
    MaliciousDeviceBlocked,
    HotplugRapidReinsert,
    DuplicateDeviceWarning,
    DeviceRemoved,
    DeviceEjected,
    WhitelistModified,
    BadUSBDetected,
    SystemError
}
