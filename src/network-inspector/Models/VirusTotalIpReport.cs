namespace NetworkInspector.Models;

public class VirusTotalIpReport
{
    public string Ip { get; set; } = "Unknown";
    public string AsOwner { get; set; } = "Unknown";
    public string Country { get; set; } = "Unknown";
    public int Reputation { get; set; }
    public int MaliciousDetections { get; set; }
    public int SuspiciousDetections { get; set; }
    public int HarmlessDetections { get; set; }
    public int UndetectedDetections { get; set; }
    public List<string> Tags { get; set; } = new();
    public bool IsPotentiallySuspicious { get; set; }
}