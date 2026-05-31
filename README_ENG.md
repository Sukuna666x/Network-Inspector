# Network-Inspector 🕵🏻‍♂️

A small C# console tool for Windows that displays active TCP connections and checks individual IP addresses with the VirusTotal API.

## Features 🔥

- Lists active TCP connections with local address, remote address, and PID
- Simple console-based menu
- Checks an IP address using the VirusTotal API

## Requirements ✍🏻

- Windows
- .NET SDK or .NET Runtime
- A valid VirusTotal API key

## Installation ⬇️

```bash
git clone https://github.com/<your-username>/network-inspector.git
cd network-inspector
dotnet build
```

## Configuration ⚙️

Add your VirusTotal API key directly in the code or load it from an environment variable such as `VT_API_KEY`.

## Usage 💻

```bash
dotnet run
```

Menu options:

- `1` List active network connections
- `2` Check an IP address with VirusTotal

## Notes ‼️

This project is intended as a learning and lab tool. Future improvements may include migration to the VirusTotal v3 API, proper JSON parsing, and more secure secret handling.
