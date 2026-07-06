namespace EnterpriseFileSecurity.Common;

public class RotationRecord
{
    public string RotationID { get; set; }
    public string UserID { get; set; }
    public string OldKeyID { get; set; }
    public string NewKeyID { get; set; }
    public int FilesProcessed { get; set; }
    public int FilesFailed { get; set; }
    public string RotationTrigger { get; set; }
    public string Status { get; set; }
}
