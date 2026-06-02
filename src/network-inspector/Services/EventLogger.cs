using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace NetworkInspector.Services;

public static class EventLogger
{
    private static readonly string LogDirectory = Path.Combine(AppContext.BaseDirectory, "logs");
    private static readonly string LogFilePath = Path.Combine(LogDirectory, "network-inspector.jsonl");

    private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
    {
        WriteIndented = false
    };

    public static async Task LogAsync(object logEvent)
    {
        Directory.CreateDirectory(LogDirectory);

        string json = JsonSerializer.Serialize(logEvent, JsonOptions);
        await File.AppendAllTextAsync(LogFilePath, json + Environment.NewLine);
    }
}