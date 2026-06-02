using System;
using System.Collections.Generic;

namespace NetworkInspector.Models;

public class LogEvent
{
    public DateTimeOffset Timestamp { get; set; }
    public string? Level { get; set; }
    public string? EventType { get; set; }
    public string? Outcome { get; set; }
    public string? CorrelationId { get; set; }
    public string? Source { get; set; }
    public string? Selection { get; set; }
    public string? Message { get; set; }
    public string? Input { get; set; }
    public string? Reason { get; set; }
    public string? Ip { get; set; }
    public string? AsOwner { get; set; }
    public string? Country { get; set; }
    public int? Reputation { get; set; }
    public int? Malicious { get; set; }
    public int? Suspicious { get; set; }
    public int? Harmless { get; set; }
    public int? Undetected { get; set; }
    public List<string>? Tags { get; set; }
    public bool? PotentiallySuspicious { get; set; }
}