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
        Dictionary<string, int> failureReasons = new();
        Dictionary<string, int> countryCounts = new();
        List<string> suspiciousIpSummaries = new();

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
                string? reason = GetString(root, "reason");
                string? country = GetString(root, "country");

                int malicious = GetInt(root, "malicious");
                int suspicious = GetInt(root, "suspicious");
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

                    if (!string.IsNullOrWhiteSpace(country))
                    {
                        if (countryCounts.ContainsKey(country))
                        {
                            countryCounts[country]++;
                        }
                        else
                        {
                            countryCounts[country] = 1;
                        }
                    }

                    if (potentiallySuspicious)
                    {
                        suspiciousHits++;

                        string severity = GetSeverity(malicious, suspicious);
                        string summary = !string.IsNullOrWhiteSpace(ip)
                            ? $"{ip} | country={country ?? "unknown"} | malicious={malicious} | suspicious={suspicious} | severity={severity}"
                            : $"unknown-ip | country={country ?? "unknown"} | malicious={malicious} | suspicious={suspicious} | severity={severity}";

                        suspiciousIpSummaries.Add(summary);
                    }
                }
                else if (eventType == "ip_check_failed")
                {
                    failedIpChecks++;

                    string normalizedReason = string.IsNullOrWhiteSpace(reason) ? "unknown" : reason;

                    if (failureReasons.ContainsKey(normalizedReason))
                    {
                        failureReasons[normalizedReason]++;
                    }
                    else
                    {
                        failureReasons[normalizedReason] = 1;
                    }
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

        var topReasons = failureReasons
            .OrderByDescending(x => x.Value)
            .ThenBy(x => x.Key)
            .Take(5)
            .ToList();

        var topCountries = countryCounts
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
        PrintKeyValueList(topIps, "time(s)");

        Console.WriteLine();
        Console.WriteLine("Top failure reasons:");
        PrintKeyValueList(topReasons, "event(s)");

        Console.WriteLine();
        Console.WriteLine("Countries seen:");
        PrintKeyValueList(topCountries, "result(s)");

        Console.WriteLine();
        Console.WriteLine("Suspicious IPs:");
        if (suspiciousIpSummaries.Count == 0)
        {
            Console.WriteLine("- None");
        }
        else
        {
            foreach (string item in suspiciousIpSummaries.Take(5))
            {
                Console.WriteLine($"- {item}");
            }
        }
    }

    private static void PrintKeyValueList(List<KeyValuePair<string, int>> items, string suffix)
    {
        if (items.Count == 0)
        {
            Console.WriteLine("- None");
            return;
        }

        foreach (var item in items)
        {
            Console.WriteLine($"- {item.Key}: {item.Value} {suffix}");
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

    private static string GetSeverity(int malicious, int suspicious)
    {
        if (malicious > 0)
        {
            return "high";
        }

        if (suspicious > 0)
        {
            return "medium";
        }

        return "low";
    }
}