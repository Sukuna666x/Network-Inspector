using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using NetworkInspector.Models;

namespace NetworkInspector.Services;

public static class VirusTotalService
{
    #region VirusTotal Integration

    public static async Task<VirusTotalIpReport?> CheckIpWithVirusTotalAsync(string ip, string apiKey)
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
                return null;
            }

            string json = await response.Content.ReadAsStringAsync();
            VirusTotalIpResponse? result = JsonSerializer.Deserialize<VirusTotalIpResponse>(json);

            if (result?.Data?.Attributes?.LastAnalysisStats is null)
            {
                Console.WriteLine("No analysis data returned.");
                return null;
            }

            VirusTotalAttributes attributes = result.Data.Attributes;
            VirusTotalAnalysisStats stats = attributes.LastAnalysisStats;

            return new VirusTotalIpReport
            {
                Ip = ip,
                AsOwner = string.IsNullOrWhiteSpace(attributes.AsOwner) ? "Unknown" : attributes.AsOwner,
                Country = string.IsNullOrWhiteSpace(attributes.Country) ? "Unknown" : attributes.Country,
                Reputation = attributes.Reputation,
                MaliciousDetections = stats.Malicious,
                SuspiciousDetections = stats.Suspicious,
                HarmlessDetections = stats.Harmless,
                UndetectedDetections = stats.Undetected,
                Tags = attributes.Tags ?? new List<string>(),
                IsPotentiallySuspicious = stats.Malicious > 0 || stats.Suspicious > 0
            };
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"HTTP error: {ex.Message}");
            return null;
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"JSON parsing error: {ex.Message}");
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Unexpected error: {ex.Message}");
            return null;
        }
    }

    #endregion
}