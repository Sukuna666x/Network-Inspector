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

    public static string GetLogFilePath()
    {
        return LogFilePath;
    }

    public static void DisplaySummary()
    {
        if (!File.Exists(LogFilePath))
        {
            Console.WriteLine();
            Console.WriteLine("No log events found yet.");
            Console.WriteLine($"Expected log file: {LogFilePath}");
            return;
        }

        int totalEvents = 0;
        int successfulIpChecks = 0;
        int failedIpChecks = 0;
        int suspiciousHits = 0;

        Dictionary<string, int> ipCounts = new();

        foreach (string line in File.ReadLines(LogFilePath))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                using JsonDocument document = JsonDocument.Parse(line);
                JsonElement root = document.RootElement;

                totalEvents++;

                string? eventType = GetString(root, "event_type");
                string? ip = GetString(root, "ip");
                bool potentiallySuspicious = GetBool(root, "potentially_suspicious");

                if (eventType == "ip_check_completed")
                {
                    successfulIpChecks++;

                    if (!string.IsNullOrWhiteSpace(ip))
                    {
                        if (ipCounts.ContainsKey(ip))
                        {
                            ipCounts[ip]++;
                        }
                        else
                        {
                            ipCounts[ip] = 1;
                        }
                    }

                    if (potentiallySuspicious)
                    {
                        suspiciousHits++;
                    }
                }
                else if (eventType == "ip_check_failed")
                {
                    failedIpChecks++;
                }
            }
            catch (JsonException)
            {
            }
        }

        var topIps = ipCounts
            .OrderByDescending(x => x.Value)
            .ThenBy(x => x.Key)
            .Take(5)
            .ToList();

        Console.WriteLine();
        Console.WriteLine("===== Local Log Analysis =====");
        Console.WriteLine($"Log file: {LogFilePath}");
        Console.WriteLine($"Total events: {totalEvents}");
        Console.WriteLine($"Successful IP checks: {successfulIpChecks}");
        Console.WriteLine($"Failed IP checks: {failedIpChecks}");
        Console.WriteLine($"Potentially suspicious results: {suspiciousHits}");

        Console.WriteLine();
        Console.WriteLine("Top checked IPs:");

        if (topIps.Count == 0)
        {
            Console.WriteLine("- None");
        }
        else
        {
            foreach (var item in topIps)
            {
                Console.WriteLine($"- {item.Key}: {item.Value} time(s)");
            }
        }
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
}