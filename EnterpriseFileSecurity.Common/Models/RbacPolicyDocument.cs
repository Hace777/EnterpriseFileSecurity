using System.Collections.Generic;

namespace EnterpriseFileSecurity.Common;

public class RbacPolicyDocument
{
    public string Version { get; set; }
    public string Description { get; set; }
    public List<RoleDefinition> Roles { get; set; }
    public List<SecurityLevelDef> SecurityLevels { get; set; }
    public List<OperationDefinition> Operations { get; set; }
}

public class RoleDefinition
{
    public string Name { get; set; }
    public string Code { get; set; }
    public int Priority { get; set; }
    public string Description { get; set; }
    public Dictionary<string, List<string>> Permissions { get; set; }
}

public class SecurityLevelDef
{
    public string Code { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
}

public class OperationDefinition
{
    public string Code { get; set; }
    public string Name { get; set; }
    public string Description { get; set; }
}
