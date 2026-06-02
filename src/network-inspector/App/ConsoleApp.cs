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
}