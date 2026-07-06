using System.Collections.Generic;
using EnterpriseFileSecurity.Common;

namespace EnterpriseFileSecurity.Core.Services;

public interface IKeyRotationService
{
    List<string> CheckExpiringKeys();
    (bool success, RotationRecord rotation) RotateKeys(string userId, string password, string trigger = "SCHEDULED");
}
