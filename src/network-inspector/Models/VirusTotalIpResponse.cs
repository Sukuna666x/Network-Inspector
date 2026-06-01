using System.Text.Json.Serialization;

namespace NetworkInspector.Models;

public class VirusTotalIpResponse
{
    [JsonPropertyName("data")]
    public VirusTotalData? Data { get; set; }
}

public class VirusTotalData
{
    [JsonPropertyName("attributes")]
    public VirusTotalAttributes? Attributes { get; set; }
}

public class VirusTotalAttributes
{
    [JsonPropertyName("last_analysis_stats")]
    public VirusTotalAnalysisStats? LastAnalysisStats { get; set; }

    [JsonPropertyName("reputation")]
    public int Reputation { get; set; }

    [JsonPropertyName("country")]
    public string? Country { get; set; }

    [JsonPropertyName("as_owner")]
    public string? AsOwner { get; set; }

    [JsonPropertyName("tags")]
    public List<string>? Tags { get; set; }
}

public class VirusTotalAnalysisStats
{
    [JsonPropertyName("malicious")]
    public int Malicious { get; set; }

    [JsonPropertyName("suspicious")]
    public int Suspicious { get; set; }

    [JsonPropertyName("harmless")]
    public int Harmless { get; set; }

    [JsonPropertyName("undetected")]
    public int Undetected { get; set; }
}