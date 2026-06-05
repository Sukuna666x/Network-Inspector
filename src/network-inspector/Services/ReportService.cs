using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetworkInspector.Services;

public sealed class CaseReportSummary
{
    public string GeneratedAt { get; init; } = "";
    public string CaseId { get; init; } = "";
    public string Priority { get; init; } = "";
    public string Status { get; init; } = "";
    public string CaseSource { get; init; } = "";
}

public static class ReportService
{
    private static readonly string LogFilePath = Path.Combine(
        AppContext.BaseDirectory,
        "logs",
        "network-inspector.jsonl");

    private static readonly string ReportsDirectory = Path.Combine(
        AppContext.BaseDirectory,
        "reports");

    public static async Task<string?> GenerateLatestSuspiciousCaseReportAsync()
    {
        if (!File.Exists(LogFilePath))
        {
            return null;
        }

        string? latestSuspiciousLine = File
            .ReadLines(LogFilePath)
            .Reverse()
            .FirstOrDefault(IsSuspiciousCompletedEvent);

        if (string.IsNullOrWhiteSpace(latestSuspiciousLine))
        {
            return null;
        }

        using JsonDocument document = JsonDocument.Parse(latestSuspiciousLine);
        JsonElement root = document.RootElement;

        string correlationId = GetString(root, "correlation_id") ?? Guid.NewGuid().ToString();
        string caseId = GenerateHumanReadableCaseId();

        string generatedAt = DateTimeOffset.UtcNow.ToString("u");
        string observedAt = GetString(root, "timestamp") ?? "unknown";
        string source = GetString(root, "source") ?? "network-inspector";
        string caseSource = "virustotal_ip_check";

        string ip = GetString(root, "ip") ?? "unknown";
        string country = GetString(root, "country") ?? "unknown";
        string asOwner = GetString(root, "as_owner") ?? "unknown";
        int reputation = GetInt(root, "reputation");
        int malicious = GetInt(root, "malicious");
        int suspicious = GetInt(root, "suspicious");
        int harmless = GetInt(root, "harmless");
        int undetected = GetInt(root, "undetected");

        string detectionUseCase = "Suspicious outbound IP reputation check";
        string mitreAttack = MapMitreAttack(malicious, suspicious);
        string environment = "homelab";
        string affectedAsset = Environment.MachineName;
        string analyst = "finn";

        string severity = GetSeverity(malicious, suspicious);
        string priority = severity;
        string status = "open";
        string owner = analyst;
        string disposition = GetDisposition(malicious, suspicious);
        string nextStep = GetNextStep(malicious, suspicious);
        string recommendedAction = GetRecommendedAction(malicious, suspicious);

        Directory.CreateDirectory(ReportsDirectory);

        string safeCaseId = caseId.Replace(":", "-").Replace("/", "-");
        string fileName = $"case-report-{safeCaseId}.md";
        string reportPath = Path.Combine(ReportsDirectory, fileName);

        StringBuilder markdown = new();

        markdown.AppendLine("# SOC Case Report");
        markdown.AppendLine();

        markdown.AppendLine("## Executive Summary");
        markdown.AppendLine($"A suspicious IP analysis result was identified by `{source}` and converted into a local SOC-style case report. The observed IP was `{ip}` with severity classified as `{severity}` based on the current local triage logic.");
        markdown.AppendLine();

        markdown.AppendLine("## Case Metadata");
        markdown.AppendLine($"- Case ID: `{caseId}`");
        markdown.AppendLine($"- Correlation ID: `{correlationId}`");
        markdown.AppendLine($"- Status: `{status}`");
        markdown.AppendLine($"- Owner: `{owner}`");
        markdown.AppendLine($"- Analyst: `{analyst}`");
        markdown.AppendLine($"- Priority: `{priority}`");
        markdown.AppendLine($"- Disposition: `{disposition}`");
        markdown.AppendLine($"- Next Step: `{nextStep}`");
        markdown.AppendLine($"- Case Source: `{caseSource}`");
        markdown.AppendLine();

        markdown.AppendLine("## Detection Context");
        markdown.AppendLine($"- Detection Use Case: `{detectionUseCase}`");
        markdown.AppendLine($"- MITRE ATT&CK: `{mitreAttack}`");
        markdown.AppendLine($"- Environment: `{environment}`");
        markdown.AppendLine($"- Affected Asset: `{affectedAsset}`");
        markdown.AppendLine();

        markdown.AppendLine("## Incident Details");
        markdown.AppendLine($"- Generated At (UTC): `{generatedAt}`");
        markdown.AppendLine($"- Observed At: `{observedAt}`");
        markdown.AppendLine($"- Source: `{source}`");
        markdown.AppendLine($"- Observed IP: `{ip}`");
        markdown.AppendLine($"- Country: `{country}`");
        markdown.AppendLine($"- AS Owner: `{asOwner}`");
        markdown.AppendLine($"- Reputation: `{reputation}`");
        markdown.AppendLine($"- Severity: `{severity}`");
        markdown.AppendLine();

        markdown.AppendLine("## Detection Results");
        markdown.AppendLine($"- Malicious detections: `{malicious}`");
        markdown.AppendLine($"- Suspicious detections: `{suspicious}`");
        markdown.AppendLine($"- Harmless detections: `{harmless}`");
        markdown.AppendLine($"- Undetected results: `{undetected}`");
        markdown.AppendLine();

        markdown.AppendLine("## Evidence Summary");
        markdown.AppendLine($"The most recent suspicious `ip_check_completed` event in the local JSONL log was used as the evidence source for this case. The result indicates that the IP `{ip}` returned `malicious={malicious}` and `suspicious={suspicious}`, which triggered a severity of `{severity}` in the current triage model.");
        markdown.AppendLine();

        markdown.AppendLine("## Case Timeline");
        markdown.AppendLine($"- `{NormalizeTimelineTimestamp(observedAt)}` - Source event observed for IP `{ip}`");
        markdown.AppendLine($"- `{NormalizeTimelineTimestamp(generatedAt)}` - Case created with status `{status}` from suspicious IP event");
        markdown.AppendLine();

        markdown.AppendLine("## Recommended Action");
        markdown.AppendLine(recommendedAction);
        markdown.AppendLine();

        markdown.AppendLine("## Analyst Notes");
        markdown.AppendLine("- This report was generated automatically from the latest suspicious local event.");
        markdown.AppendLine("- This case should be reviewed manually before any real blocking or escalation decision is made.");
        markdown.AppendLine("- Future improvements can include timeline expansion, IOC enrichment, and case status tracking.");
        markdown.AppendLine();

        markdown.AppendLine("## Detection and Response Notes");
        markdown.AppendLine($"- Detection source: `{caseSource}`");
        markdown.AppendLine("- Report type: locally generated training case");
        markdown.AppendLine("- Intended use: homelab practice, portfolio evidence, SOC workflow training");

        await File.WriteAllTextAsync(reportPath, markdown.ToString());

        await EventLogger.LogAsync(new
        {
            timestamp = DateTimeOffset.UtcNow,
            level = "INFO",
            event_type = "case_report_generated",
            outcome = "success",
            source = "network-inspector",
            case_id = caseId,
            correlation_id = correlationId,
            ip,
            severity,
            status,
            owner,
            analyst,
            priority,
            environment,
            affected_asset = affectedAsset,
            detection_use_case = detectionUseCase,
            mitre_attack = mitreAttack,
            next_step = nextStep,
            report_path = reportPath
        });

        return reportPath;
    }

    public static async Task<List<CaseReportSummary>> GetCaseReportSummariesAsync()
    {
        var result = new List<CaseReportSummary>();

        if (!Directory.Exists(ReportsDirectory))
        {
            return result;
        }

        string[] files = Directory.GetFiles(ReportsDirectory, "case-report-*.md");

        foreach (string file in files.OrderByDescending(f => f))
        {
            string[] lines = await File.ReadAllLinesAsync(file);

            string generatedAt = ExtractValueFromLine(lines, "Generated At (UTC):");
            string caseId = ExtractValueFromLine(lines, "Case ID:");
            string correlationId = ExtractValueFromLine(lines, "Correlation ID:");
            string priority = ExtractValueFromLine(lines, "Priority:");
            string status = ExtractValueFromLine(lines, "Status:");
            string caseSource = ExtractValueFromLine(lines, "Case Source:");

            string displayCaseId = !string.IsNullOrWhiteSpace(caseId)
                ? caseId
                : correlationId;

            result.Add(new CaseReportSummary
            {
                GeneratedAt = generatedAt,
                CaseId = displayCaseId,
                Priority = priority,
                Status = status,
                CaseSource = caseSource
            });
        }

        return result;
    }

    public static async Task<bool> UpdateCaseStatusAsync(string caseIdentifier, string newStatus)
    {
        if (!Directory.Exists(ReportsDirectory))
        {
            return false;
        }

        string[] files = Directory.GetFiles(ReportsDirectory, "case-report-*.md");

        string? matchingFile = null;
        string matchedCaseId = "";
        string matchedCorrelationId = "";

        foreach (string file in files.OrderByDescending(f => f))
        {
            string[] lines = await File.ReadAllLinesAsync(file);

            string existingCaseId = ExtractValueFromLine(lines, "Case ID:");
            string existingCorrelationId = ExtractValueFromLine(lines, "Correlation ID:");

            bool caseIdMatches = !string.IsNullOrWhiteSpace(existingCaseId) &&
                                 string.Equals(existingCaseId, caseIdentifier, StringComparison.OrdinalIgnoreCase);

            bool correlationIdMatches = !string.IsNullOrWhiteSpace(existingCorrelationId) &&
                                        string.Equals(existingCorrelationId, caseIdentifier, StringComparison.OrdinalIgnoreCase);

            if (caseIdMatches || correlationIdMatches)
            {
                matchingFile = file;
                matchedCaseId = existingCaseId;
                matchedCorrelationId = existingCorrelationId;
                break;
            }
        }

        if (string.IsNullOrWhiteSpace(matchingFile))
        {
            return false;
        }

        string content = await File.ReadAllTextAsync(matchingFile);

        string currentStatus = ExtractValueFromContent(content, "- Status: `");
        if (string.Equals(currentStatus, newStatus, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string oldStatusLinePrefix = "- Status: `";
        int statusLineStart = content.IndexOf(oldStatusLinePrefix, StringComparison.Ordinal);

        if (statusLineStart < 0)
        {
            return false;
        }

        int statusValueStart = statusLineStart + oldStatusLinePrefix.Length;
        int statusValueEnd = content.IndexOf('`', statusValueStart);

        if (statusValueEnd < 0)
        {
            return false;
        }

        string updatedContent = content.Substring(0, statusValueStart) +
                                newStatus +
                                content.Substring(statusValueEnd);

        string timelineHeader = "## Case Timeline";
        int timelineIndex = updatedContent.IndexOf(timelineHeader, StringComparison.Ordinal);

        if (timelineIndex >= 0)
        {
            int insertionPoint = updatedContent.IndexOf("## Recommended Action", timelineIndex, StringComparison.Ordinal);
            string previousStatusText = string.IsNullOrWhiteSpace(currentStatus) ? "unknown" : currentStatus;
            string timelineEntry = $"- `{DateTimeOffset.UtcNow:u}` - Status changed from `{previousStatusText}` to `{newStatus}`{Environment.NewLine}";

            if (insertionPoint >= 0)
            {
                updatedContent = updatedContent.Insert(insertionPoint, timelineEntry);
            }
            else
            {
                updatedContent += Environment.NewLine + timelineEntry;
            }
        }

        await File.WriteAllTextAsync(matchingFile, updatedContent);

        await EventLogger.LogAsync(new
        {
            timestamp = DateTimeOffset.UtcNow,
            level = "INFO",
            event_type = "case_status_updated",
            outcome = "success",
            source = "network-inspector",
            case_identifier = caseIdentifier,
            case_id = matchedCaseId,
            correlation_id = matchedCorrelationId,
            previous_status = currentStatus,
            new_status = newStatus,
            report_path = matchingFile
        });

        return true;
    }

    private static void AppendTimelineEntry(StringBuilder markdown, string timestamp, string description)
    {
        markdown.AppendLine($"- `{NormalizeTimelineTimestamp(timestamp)}` - {description}");
    }

    private static string NormalizeTimelineTimestamp(string timestamp)
    {
        if (DateTimeOffset.TryParse(timestamp, out DateTimeOffset parsed))
        {
            return parsed.UtcDateTime.ToString("u").TrimEnd();
        }

        return timestamp;
    }

    private static string ExtractValueFromContent(string content, string prefix)
    {
        int lineStart = content.IndexOf(prefix, StringComparison.Ordinal);
        if (lineStart < 0)
        {
            return "";
        }

        int valueStart = lineStart + prefix.Length;
        int valueEnd = content.IndexOf('`', valueStart);

        if (valueEnd < 0)
        {
            return "";
        }

        return content.Substring(valueStart, valueEnd - valueStart);
    }

    private static string GenerateHumanReadableCaseId()
    {
        Directory.CreateDirectory(ReportsDirectory);

        string datePart = DateTime.UtcNow.ToString("yyyyMMdd");
        string prefix = $"NI-{datePart}-";

        int nextNumber = Directory
            .GetFiles(ReportsDirectory, $"case-report-NI-{datePart}-*.md")
            .Length + 1;

        return $"{prefix}{nextNumber:D4}";
    }

    private static bool IsSuspiciousCompletedEvent(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(line);
            JsonElement root = document.RootElement;

            string? eventType = GetString(root, "event_type");
            bool potentiallySuspicious = GetBool(root, "potentially_suspicious");

            return eventType == "ip_check_completed" && potentiallySuspicious;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string MapMitreAttack(int malicious, int suspicious)
    {
        if (malicious > 0)
        {
            return "TA0011 Command and Control / T1071 Application Layer Protocol";
        }

        if (suspicious > 0)
        {
            return "TA0011 Command and Control";
        }

        return "N/A";
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

    private static string GetDisposition(int malicious, int suspicious)
    {
        if (malicious > 0)
        {
            return "escalate";
        }

        if (suspicious > 0)
        {
            return "needs_review";
        }

        return "informational";
    }

    private static string GetNextStep(int malicious, int suspicious)
    {
        if (malicious > 0)
        {
            return "Review related logs and escalate for deeper investigation";
        }

        if (suspicious > 0)
        {
            return "Correlate this IP with additional local events";
        }

        return "Document and monitor";
    }

    private static string GetRecommendedAction(int malicious, int suspicious)
    {
        if (malicious > 0)
        {
            return "- Escalate this case for deeper investigation.\n- Validate whether the IP appears elsewhere in local logs.\n- Consider temporary blocking or monitoring in a controlled lab context.";
        }

        if (suspicious > 0)
        {
            return "- Review the IP manually and correlate it with other local events.\n- Continue monitoring for repeated activity.\n- Add analyst notes before deciding whether to escalate.";
        }

        return "- No immediate escalation required.\n- Keep the event documented for future reference.";
    }

    private static string ExtractValueFromLine(string[] lines, string label)
    {
        string? line = lines.FirstOrDefault(l => l.TrimStart().StartsWith($"- {label}"));

        if (string.IsNullOrWhiteSpace(line))
        {
            return "";
        }

        int firstBacktickIndex = line.IndexOf('`');
        if (firstBacktickIndex < 0)
        {
            return "";
        }

        int lastBacktickIndex = line.LastIndexOf('`');
        if (lastBacktickIndex <= firstBacktickIndex)
        {
            return "";
        }

        return line.Substring(firstBacktickIndex + 1, lastBacktickIndex - firstBacktickIndex - 1);
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
}