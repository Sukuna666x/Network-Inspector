using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

#region App Startup

Console.Title = "Sukuna666x Network-Inspector";

bool isRunning = true;

while (isRunning)
{
    Console.Clear();
    DisplayBanner();
    DisplayMenu();

    string? choice = Console.ReadLine();

    switch (choice)
    {
        case "1":
            ShowPlaceholder("Active connection scanner will be added next.");
            break;

        case "2":
            await CheckIpAsync();
            break;

        case "0":
            isRunning = false;
            Console.WriteLine();
            Console.WriteLine("Exiting Sukuna666x Network-Inspector...");
            break;

        default:
            ShowPlaceholder("Invalid selection. Please try again.");
            break;
    }

    if (isRunning)
    {
        Console.WriteLine();
        Console.WriteLine("Press Enter to return to the menu...");
        Console.ReadLine();
    }
}

#endregion

#region UI Methods

static void DisplayBanner()
{
    Console.WriteLine("========================================");
    Console.WriteLine("      Sukuna666x Network-Inspector      ");
    Console.WriteLine("========================================");
    Console.WriteLine();
}

static void DisplayMenu()
{
    Console.WriteLine("Welcome! What would you like to do?");
    Console.WriteLine("[1] List active network connections");
    Console.WriteLine("[2] Check an IP address");
    Console.WriteLine("[0] Exit");
    Console.Write("Enter your choice: ");
}

static void ShowPlaceholder(string message)
{
    Console.WriteLine();
    Console.WriteLine(message);
}

#endregion

#region IP Validation

static async Task CheckIpAsync()
{
    Console.WriteLine();
    Console.Write("Enter an IP address: ");
    string? input = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(input))
    {
        Console.WriteLine("No input provided.");
        return;
    }

    if (!IPAddress.TryParse(input, out IPAddress? parsedIp))
    {
        Console.WriteLine("Invalid IP address.");
        return;
    }

    string? apiKey = Environment.GetEnvironmentVariable("VT_API_KEY");

    if (string.IsNullOrWhiteSpace(apiKey))
    {
        Console.WriteLine("VirusTotal API key not found.");
        Console.WriteLine("Please set the VT_API_KEY environment variable first.");
        return;
    }

    await CheckIpWithVirusTotalAsync(parsedIp.ToString(), apiKey);
}

#endregion

#region VirusTotal Integration

static async Task CheckIpWithVirusTotalAsync(string ip, string apiKey)
{
    string url = $"https://www.virustotal.com/api/v3/ip_addresses/{ip}";

    using HttpClient client = new HttpClient();
    client.DefaultRequestHeaders.Add("x-apikey", apiKey);

    try
    {
        HttpResponseMessage response = await client.GetAsync(url);

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine($"Request failed: {(int)response.StatusCode} {response.ReasonPhrase}");
            return;
        }

        string json = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(json);

        JsonElement root = doc.RootElement;
        JsonElement data = root.GetProperty("data");
        JsonElement attributes = data.GetProperty("attributes");
        JsonElement stats = attributes.GetProperty("last_analysis_stats");

        int malicious = stats.TryGetProperty("malicious", out JsonElement maliciousValue)
            ? maliciousValue.GetInt32()
            : 0;

        int suspicious = stats.TryGetProperty("suspicious", out JsonElement suspiciousValue)
            ? suspiciousValue.GetInt32()
            : 0;

        int harmless = stats.TryGetProperty("harmless", out JsonElement harmlessValue)
            ? harmlessValue.GetInt32()
            : 0;

        int undetected = stats.TryGetProperty("undetected", out JsonElement undetectedValue)
            ? undetectedValue.GetInt32()
            : 0;

        int reputation = attributes.TryGetProperty("reputation", out JsonElement reputationValue)
            ? reputationValue.GetInt32()
            : 0;

        string country = attributes.TryGetProperty("country", out JsonElement countryValue)
            ? countryValue.GetString() ?? "Unknown"
            : "Unknown";

        string asOwner = attributes.TryGetProperty("as_owner", out JsonElement ownerValue)
            ? ownerValue.GetString() ?? "Unknown"
            : "Unknown";

        Console.WriteLine();
        Console.WriteLine("===== VirusTotal Result =====");
        Console.WriteLine($"IP: {ip}");
        Console.WriteLine($"AS Owner: {asOwner}");
        Console.WriteLine($"Country: {country}");
        Console.WriteLine($"Reputation: {reputation}");
        Console.WriteLine($"Malicious detections: {malicious}");
        Console.WriteLine($"Suspicious detections: {suspicious}");
        Console.WriteLine($"Harmless detections: {harmless}");
        Console.WriteLine($"Undetected: {undetected}");

        if (attributes.TryGetProperty("tags", out JsonElement tagsElement) &&
            tagsElement.ValueKind == JsonValueKind.Array &&
            tagsElement.GetArrayLength() > 0)
        {
            Console.Write("Tags: ");

            bool first = true;
            foreach (JsonElement tag in tagsElement.EnumerateArray())
            {
                if (!first)
                {
                    Console.Write(", ");
                }

                Console.Write(tag.GetString());
                first = false;
            }

            Console.WriteLine();
        }
        else
        {
            Console.WriteLine("Tags: None");
        }

        Console.WriteLine();

        if (malicious > 0 || suspicious > 0)
        {
            Console.WriteLine("Result: Potentially suspicious.");
        }
        else
        {
            Console.WriteLine("Result: No malicious detections reported.");
        }
    }
    catch (HttpRequestException ex)
    {
        Console.WriteLine($"HTTP error: {ex.Message}");
    }
    catch (JsonException ex)
    {
        Console.WriteLine($"JSON parsing error: {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Unexpected error: {ex.Message}");
    }
}

#endregion