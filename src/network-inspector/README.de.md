# Network-Inspector 🕵🏻‍♂️

[Deutsch](README.de.md)

Network-Inspector is a small C# console project for learning and experimenting with IP reputation checks using the VirusTotal API v3.  
At the current stage, the tool provides a simple console menu, validates IP addresses, and retrieves IP-related reputation data from VirusTotal such as ASN owner, country, reputation score, and detection statistics. [web:137][web:314]

## Features

- Simple console-based menu
- IP address validation before lookup
- VirusTotal IP lookup via API v3
- Displays:
  - AS owner
  - Country
  - Reputation
  - Malicious detections
  - Suspicious detections
  - Harmless detections
  - Undetected results
  - Tags (if available)

## Current Status

This project is currently in an early learning phase.  
The VirusTotal IP check is already working, while additional features such as active TCP connection inspection are planned for later development.

## Requirements

- .NET SDK installed
- VirusTotal account with API key
- macOS, Linux, or Windows for the current console version

## Installation

```bash
git clone https://github.com/<your-username>/network-inspector.git
cd network-inspector
dotnet build ./src/NetworkInspector
```

## Configuration

Set your VirusTotal API key as an environment variable instead of hardcoding it into the source code.

Example on macOS/Linux:

```bash
export VT_API_KEY="your_api_key_here"
```

This project reads the API key from:

```csharp
Environment.GetEnvironmentVariable("VT_API_KEY")
```

## Usage

Run the project with:

```bash
cd src/NetworkInspector
dotnet run
```

Menu options:

- `1` Placeholder for future network connection inspection
- `2` Check an IP address with VirusTotal
- `0` Exit the application

## Example Output

```text
===== VirusTotal Result =====
IP: 8.8.8.8
AS Owner: Google LLC
Country: US
Reputation: 543
Malicious detections: 0
Suspicious detections: 0
Harmless detections: 55
Undetected: 36
Tags: None
```

## Roadmap

Planned next steps:

- Refactor VirusTotal logic into a separate service class
- Improve project structure
- Add better error handling
- Add active TCP connection inspection
- Improve README and repository metadata further

## Notes

This project is intended as a learning project and lab tool.  
API keys should never be committed to GitHub or stored directly in the code.

## License

No license has been added yet.
