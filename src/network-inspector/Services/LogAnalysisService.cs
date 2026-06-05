using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace NetworkInspector.Services;

public static class LogAnalysisService
{
    private static readonly string LogFilePath = Path.Combine(
        AppContext.BaseDirectory,
        "logs",
        "network-inspector.jsonl");

    public static void DisplaySummary()
    {
        Console.WriteLine();
        Console.WriteLine("===== Local Log Analysis =====");
        Console.WriteLine();

        if (!File.Exists(LogFilePath))
        {
            Console.WriteLine("No log file found yet. Run some checks first.");
            return;
        }

        var stats = AnalyzeLog();

        Console.WriteLine($"Total events: {stats.TotalEvents}");
        Console.WriteLine($"ip_check_started: {stats.IpCheckStarted}");
        Console.WriteLine($"ip_check_completed: {stats.IpCheckCompleted}");
        Console.WriteLine($"case_report_generated: {stats.CaseReportGenerated}");
        Console.WriteLine($"case_status_updated: {stats.CaseStatusUpdated}");
        Console.WriteLine();

        Console.WriteLine($"Potentially suspicious IP events: {stats.PotentiallySuspiciousEvents}");
        Console.WriteLine();

        Console.WriteLine("Top observed IPs (by ip_check_completed):");
        if (stats.TopIps.Count == 0)
        {
            Console.WriteLine("  (none yet)");
        }
        else
        {
            foreach (var entry in stats.TopIps)
            {
                Console.WriteLine($"  {entry.Ip,-18} {entry.Count,3} events (malicious={entry.TotalMalicious}, suspicious={entry.TotalSuspicious})");
            }
        }

        Console.WriteLine();
        Console.WriteLine("Last 5 suspicious ip_check_completed events:");
        if (stats.LastSuspiciousEvents.Count == 0)
        {
            Console.WriteLine("  (none yet)");
        }
        else
        {
            foreach (var e in stats.LastSuspiciousEvents)
            {
                Console.WriteLine($"  [{e.Timestamp}] ip={e.Ip}, malicious={e.Malicious}, suspicious={e.Suspicious}, correlation_id={e.CorrelationId}");
            }
        }

        Console.WriteLine();
        Console.WriteLine("Tip: Use these IPs with menu [2] to re-check reputation, or generate new cases with menu [4].");
    }

    private static LogStats AnalyzeLog()
    {
        var stats = new LogStats();

        var ipCounters = new Dictionary<string, IpAggregate>(StringComparer.OrdinalIgnoreCase);
        var suspiciousEvents = new List<SuspiciousEvent>();

        foreach (string line in File.ReadLines(LogFilePath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            JsonDocument? document = null;
            try
            {
                document = JsonDocument.Parse(line);
            }
            catch (JsonException)
            {
                continue;
            }

            using (document)
            {
                JsonElement root = document.RootElement;

                stats.TotalEvents++;

                string? eventType = GetString(root, "event_type");

                switch (eventType)
                {
                    case "ip_check_started":
                        stats.IpCheckStarted++;
                        break;

                    case "ip_check_completed":
                        stats.IpCheckCompleted++;
                        HandleIpCheckCompleted(root, ipCounters, suspiciousEvents);
                        break;

                    case "case_report_generated":
                        stats.CaseReportGenerated++;
                        break;

                    case "case_status_updated":
                        stats.CaseStatusUpdated++;
                        break;
                }
            }
        }

        stats.PotentiallySuspiciousEvents = suspiciousEvents.Count;

        stats.TopIps = ipCounters
            .OrderByDescending(kv => kv.Value.Count)
            .Take(5)
            .Select(kv => new TopIp
            {
                Ip = kv.Key,
                Count = kv.Value.Count,
                TotalMalicious = kv.Value.TotalMalicious,
                TotalSuspicious = kv.Value.TotalSuspicious
            })
            .ToList();

        stats.LastSuspiciousEvents = suspiciousEvents
            .OrderByDescending(e => e.Timestamp)
            .Take(5)
            .OrderBy(e => e.Timestamp)
            .ToList();

        return stats;
    }

    private static void HandleIpCheckCompleted(
        JsonElement root,
        Dictionary<string, IpAggregate> ipCounters,
        List<SuspiciousEvent> suspiciousEvents)
    {
        string ip = GetString(root, "ip") ?? "unknown";
        int malicious = GetInt(root, "malicious");
        int suspicious = GetInt(root, "suspicious");
        bool potentiallySuspicious = GetBool(root, "potentially_suspicious");
        string correlationId = GetString(root, "correlation_id") ?? "";
        string timestamp = GetString(root, "timestamp") ?? "";

        if (!ipCounters.TryGetValue(ip, out IpAggregate? aggregate))
        {
            aggregate = new IpAggregate();
            ipCounters[ip] = aggregate;
        }

        aggregate.Count++;
        aggregate.TotalMalicious += malicious;
        aggregate.TotalSuspicious += suspicious;

        if (potentiallySuspicious)
        {
            suspiciousEvents.Add(new SuspiciousEvent
            {
                Timestamp = ParseTimestamp(timestamp),
                Ip = ip,
                Malicious = malicious,
                Suspicious = suspicious,
                CorrelationId = correlationId
            });
        }
    }

    private static DateTimeOffset ParseTimestamp(string timestamp)
    {
        if (DateTimeOffset.TryParse(timestamp, out DateTimeOffset parsed))
        {
            return parsed;
        }

        return DateTimeOffset.MinValue;
    }

    private static string? GetString(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out JsonElement value) &&
            value.ValueKind == JsonValueKind.String)
        {
            return value.GetString();
        }

        return null;
    }

    private static bool GetBool(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out JsonElement value) &&
            (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
        {
            return value.GetBoolean();
        }

        return false;
    }

    private static int GetInt(JsonElement element, string propertyName)
    {
        if (element.TryGetProperty(propertyName, out JsonElement value) &&
            value.ValueKind == JsonValueKind.Number &&
            value.TryGetInt32(out int result))
        {
            return result;
        }

        return 0;
    }

    private sealed class LogStats
    {
        public int TotalEvents { get; set; }
        public int IpCheckStarted { get; set; }
        public int IpCheckCompleted { get; set; }
        public int CaseReportGenerated { get; set; }
        public int CaseStatusUpdated { get; set; }
        public int PotentiallySuspiciousEvents { get; set; }

        public List<TopIp> TopIps { get; set; } = new();
        public List<SuspiciousEvent> LastSuspiciousEvents { get; set; } = new();
    }

    private sealed class IpAggregate
    {
        public int Count { get; set; }
        public int TotalMalicious { get; set; }
        public int TotalSuspicious { get; set; }
    }

    private sealed class TopIp
    {
        public string Ip { get; set; } = "";
        public int Count { get; set; }
        public int TotalMalicious { get; set; }
        public int TotalSuspicious { get; set; }
    }

    private sealed class SuspiciousEvent
    {
        public DateTimeOffset Timestamp { get; set; }
        public string Ip { get; set; } = "";
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public string CorrelationId { get; set; } = "";
    }
}