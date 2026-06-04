using System;
using System.Net;
using System.Threading.Tasks;
using NetworkInspector.Models;
using NetworkInspector.Services;

namespace NetworkInspector.App;

public class ConsoleApp
{
    public async Task RunAsync()
    {
        Console.Title = "Sukuna666x Network-Inspector";

        await EventLogger.LogAsync(new
        {
            timestamp = DateTimeOffset.UtcNow,
            level = "INFO",
            event_type = "application_start",
            outcome = "success",
            source = "network-inspector",
            message = "Application started"
        });

        bool isRunning = true;

        while (isRunning)
        {
            Console.Clear();
            DisplayBanner();
            DisplayMenu();

            string? choice = Console.ReadLine();

            await EventLogger.LogAsync(new
            {
                timestamp = DateTimeOffset.UtcNow,
                level = "INFO",
                event_type = "menu_selection",
                outcome = "success",
                source = "network-inspector",
                selection = choice ?? "null"
            });

            switch (choice)
            {
                case "1":
                    ShowPlaceholder("Active connection scanner will be added next.");
                    break;

                case "2":
                    await CheckIpAsync();
                    break;

                case "3":
                    LogAnalysisService.DisplaySummary();
                    break;

                case "4":
                    await GenerateCaseReportAsync();
                    break;

                case "5":
                    await ListCaseReportsAsync();
                    break;

                case "6":
                    await UpdateCaseStatusAsync();
                    break;

                case "0":
                    isRunning = false;
                    Console.WriteLine();
                    Console.WriteLine("Exiting Sukuna666x Network-Inspector...");

                    await EventLogger.LogAsync(new
                    {
                        timestamp = DateTimeOffset.UtcNow,
                        level = "INFO",
                        event_type = "application_exit",
                        outcome = "success",
                        source = "network-inspector",
                        message = "Application exited by user"
                    });
                    break;

                default:
                    ShowPlaceholder("Invalid selection. Please try again.");

                    await EventLogger.LogAsync(new
                    {
                        timestamp = DateTimeOffset.UtcNow,
                        level = "WARN",
                        event_type = "menu_selection_invalid",
                        outcome = "failure",
                        source = "network-inspector",
                        selection = choice ?? "null",
                        reason = "invalid_menu_option"
                    });
                    break;
            }

            if (isRunning)
            {
                Console.WriteLine();
                Console.WriteLine("Press Enter to return to the menu...");
                Console.ReadLine();
            }
        }
    }

    private void DisplayBanner()
    {
        Console.WriteLine("========================================");
        Console.WriteLine("      Sukuna666x Network-Inspector      ");
        Console.WriteLine("========================================");
        Console.WriteLine();
    }

    private void DisplayMenu()
    {
        Console.WriteLine("Welcome! What would you like to do?");
        Console.WriteLine("[1] List active network connections");
        Console.WriteLine("[2] Check an IP address");
        Console.WriteLine("[3] Analyze local log file");
        Console.WriteLine("[4] Generate SOC case report");
        Console.WriteLine("[5] List all SOC cases");
        Console.WriteLine("[6] Update case status");
        Console.WriteLine("[0] Exit");
        Console.Write("Enter your choice: ");
    }

    private void ShowPlaceholder(string message)
    {
        Console.WriteLine();
        Console.WriteLine(message);
    }

    private void DisplayVirusTotalReport(VirusTotalIpReport report)
    {
        Console.WriteLine();
        Console.WriteLine("===== VirusTotal Result =====");
        Console.WriteLine($"IP: {report.Ip}");
        Console.WriteLine($"AS Owner: {report.AsOwner}");
        Console.WriteLine($"Country: {report.Country}");
        Console.WriteLine($"Reputation: {report.Reputation}");
        Console.WriteLine($"Malicious detections: {report.MaliciousDetections}");
        Console.WriteLine($"Suspicious detections: {report.SuspiciousDetections}");
        Console.WriteLine($"Harmless detections: {report.HarmlessDetections}");
        Console.WriteLine($"Undetected: {report.UndetectedDetections}");

        if (report.Tags.Count > 0)
        {
            Console.WriteLine($"Tags: {string.Join(", ", report.Tags)}");
        }
        else
        {
            Console.WriteLine("Tags: None");
        }

        Console.WriteLine();

        if (report.IsPotentiallySuspicious)
        {
            Console.WriteLine("Result: Potentially suspicious.");
        }
        else
        {
            Console.WriteLine("Result: No malicious detections reported.");
        }
    }

    private async Task CheckIpAsync()
    {
        string correlationId = Guid.NewGuid().ToString();

        Console.WriteLine();
        Console.Write("Enter an IP address: ");
        string? input = Console.ReadLine();

        if (string.IsNullOrWhiteSpace(input))
        {
            Console.WriteLine("No input provided.");

            await EventLogger.LogAsync(new
            {
                timestamp = DateTimeOffset.UtcNow,
                level = "WARN",
                event_type = "ip_check_failed",
                outcome = "failure",
                correlation_id = correlationId,
                source = "network-inspector",
                reason = "empty_input"
            });

            return;
        }

        if (!IPAddress.TryParse(input, out IPAddress? parsedIp))
        {
            Console.WriteLine("Invalid IP address.");

            await EventLogger.LogAsync(new
            {
                timestamp = DateTimeOffset.UtcNow,
                level = "WARN",
                event_type = "ip_check_failed",
                outcome = "failure",
                correlation_id = correlationId,
                source = "network-inspector",
                input,
                reason = "invalid_ip"
            });

            return;
        }

        string ip = parsedIp.ToString();
        string? apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            Console.WriteLine("VirusTotal API key not found.");
            Console.WriteLine("Please set the VT_API_KEY environment variable first.");

            await EventLogger.LogAsync(new
            {
                timestamp = DateTimeOffset.UtcNow,
                level = "WARN",
                event_type = "ip_check_failed",
                outcome = "failure",
                correlation_id = correlationId,
                source = "network-inspector",
                ip,
                reason = "missing_api_key"
            });

            return;
        }

        await EventLogger.LogAsync(new
        {
            timestamp = DateTimeOffset.UtcNow,
            level = "INFO",
            event_type = "ip_check_started",
            outcome = "success",
            correlation_id = correlationId,
            source = "network-inspector",
            ip
        });

        VirusTotalIpReport? report = await VirusTotalService.CheckIpWithVirusTotalAsync(ip, apiKey);

        if (report is null)
        {
            Console.WriteLine("No report could be retrieved.");

            await EventLogger.LogAsync(new
            {
                timestamp = DateTimeOffset.UtcNow,
                level = "ERROR",
                event_type = "ip_check_failed",
                outcome = "failure",
                correlation_id = correlationId,
                source = "network-inspector",
                ip,
                reason = "no_report"
            });

            return;
        }

        await EventLogger.LogAsync(new
        {
            timestamp = DateTimeOffset.UtcNow,
            level = "INFO",
            event_type = "ip_check_completed",
            outcome = "success",
            correlation_id = correlationId,
            source = "network-inspector",
            ip = report.Ip,
            as_owner = report.AsOwner,
            country = report.Country,
            reputation = report.Reputation,
            malicious = report.MaliciousDetections,
            suspicious = report.SuspiciousDetections,
            harmless = report.HarmlessDetections,
            undetected = report.UndetectedDetections,
            tags = report.Tags,
            potentially_suspicious = report.IsPotentiallySuspicious
        });

        DisplayVirusTotalReport(report);
    }

    private async Task GenerateCaseReportAsync()
    {
        string? reportPath = await ReportService.GenerateLatestSuspiciousCaseReportAsync();

        Console.WriteLine();

        if (string.IsNullOrWhiteSpace(reportPath))
        {
            Console.WriteLine("No suspicious event found. No report was generated.");
            return;
        }

        Console.WriteLine("SOC case report generated successfully.");
        Console.WriteLine($"Report path: {reportPath}");
    }

    private async Task ListCaseReportsAsync()
    {
        var summaries = await ReportService.GetCaseReportSummariesAsync();

        Console.WriteLine();

        if (summaries.Count == 0)
        {
            Console.WriteLine("No SOC case reports found.");
            return;
        }

        Console.WriteLine("Existing SOC case reports:");
        Console.WriteLine();

        Console.WriteLine("{0,-25} {1,-20} {2,-8} {3,-14} {4,-24}",
            "Generated At (UTC)", "Case ID", "Prio", "Status", "Source");

        Console.WriteLine(new string('-', 100));

        foreach (var summary in summaries)
        {
            Console.WriteLine("{0,-25} {1,-20} {2,-8} {3,-14} {4,-24}",
                summary.GeneratedAt,
                summary.CaseId,
                summary.Priority,
                summary.Status,
                summary.CaseSource);
        }
    }

    private async Task UpdateCaseStatusAsync()
    {
        Console.WriteLine();
        Console.Write("Enter Case ID or Correlation ID (e.g. NI-20260604-0001 or afdebbe1-23c3-4f8a-aa81-96bb30a40227): ");        string? caseId = Console.ReadLine();

        if (string.IsNullOrWhiteSpace(caseId))
        {
            Console.WriteLine("No Case ID provided.");
            return;
        }

        Console.WriteLine();
        Console.WriteLine("Select new status:");
        Console.WriteLine("[1] open");
        Console.WriteLine("[2] under_review");
        Console.WriteLine("[3] closed");
        Console.Write("Enter your choice: ");

        string? statusChoice = Console.ReadLine();

        string? newStatus = statusChoice switch
        {
            "1" => "open",
            "2" => "under_review",
            "3" => "closed",
            _ => null
        };

        if (string.IsNullOrWhiteSpace(newStatus))
        {
            Console.WriteLine("Invalid status selection.");
            return;
        }

        bool updated = await ReportService.UpdateCaseStatusAsync(caseId.Trim(), newStatus);

        Console.WriteLine();

        if (!updated)
        {
            Console.WriteLine("Case not found or status could not be updated.");
            return;
        }

        Console.WriteLine($"Case status updated successfully to '{newStatus}'.");
    }
}