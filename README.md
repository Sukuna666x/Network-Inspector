# Network Inspector

**Languages:** [English](README.md) | [Deutsch](README.de.md)

A beginner-friendly C#/.NET security project for checking IP addresses with VirusTotal, writing structured JSONL logs, and performing simple local log triage.

## Overview

`network-inspector` is a small console-based security tool built as part of a hands-on blue-team / SOC learning path.  
It helps inspect IP addresses, log actions in structured JSON format, and summarize activity from local logs.

The project is designed to be simple enough for a beginner to understand, while still showing practical ideas that matter in security work:
- IP reputation checking
- structured logging
- correlation IDs
- local log analysis
- basic triage logic

## Features

- Console menu interface
- Check an IP address with the VirusTotal API
- Structured JSONL logging
- Correlation IDs for IP check workflows
- Local log analysis from the generated log file
- Triage summary with:
  - top checked IPs
  - top failure reasons
  - countries seen
  - suspicious IP summaries
  - simple severity rating

## Project Structure

```text
network-inspector/
├── src/
│   └── network-inspector/
│       ├── App/
│       │   └── ConsoleApp.cs
│       ├── Models/
│       │   ├── LogEvent.cs
│       │   ├── VirusTotalIpReport.cs
│       │   └── VirusTotalIpResponse.cs
│       ├── Services/
│       │   ├── EventLogger.cs
│       │   ├── LogAnalysisService.cs
│       │   └── VirusTotalService.cs
│       ├── Program.cs
│       └── NetworkInspector.csproj
```

## Why I Built This

I built this project to practice practical SOC-style skills in a small and understandable format.  
Instead of only making API calls, I wanted to learn how to:
- collect useful security data
- store it in structured logs
- analyze those logs locally
- create a small triage-style workflow

## Requirements

- .NET SDK installed
- A VirusTotal API key for IP reputation checks
- Terminal / command line access

## Installation

Clone the repository:

```bash
git clone <your-repo-url>
cd network-inspector
```

Build the project:

```bash
dotnet build src/network-inspector/NetworkInspector.csproj
```

## Configuration

For VirusTotal lookups, set your API key as an environment variable.

Temporary for the current shell session:

```bash
export VT_API_KEY="your_api_key_here"
```

Check that it is set:

```bash
echo $VT_API_KEY
```

## Usage

Run the project with:

```bash
dotnet run --project src/network-inspector/NetworkInspector.csproj
```

You will then see a menu like this:

```text
 List active network connections
 Check an IP address
 Analyze local log file
 Exit
```

### Option 2: Check an IP address

This option sends the IP to VirusTotal and displays a short summary such as:
- AS owner
- country
- reputation
- malicious / suspicious / harmless detections
- tags
- result summary

### Option 3: Analyze local log file

This option reads the generated JSONL log file and displays:
- total events
- successful IP checks
- failed IP checks
- potentially suspicious results
- top checked IPs
- top failure reasons
- countries seen
- suspicious IPs with severity

## Example Output

```text
===== Local Log Analysis =====
Log file: /.../logs/network-inspector.jsonl
Total events: 53
Successful IP checks: 3
Failed IP checks: 4
Potentially suspicious results: 1

Top checked IPs:
- 8.8.8.8: 2 time(s)
- 9.9.9.9: 1 time(s)

Top failure reasons:
- invalid_ip: 2 event(s)
- empty_input: 1 event(s)
- missing_api_key: 1 event(s)

Countries seen:
- US: 2 result(s)
- Unknown: 1 result(s)

Suspicious IPs:
- 9.9.9.9 | country=Unknown | malicious=1 | suspicious=0 | severity=high
```

## Logging

The application writes structured JSON lines (`.jsonl`) to a local log file.

Current event examples include:
- `application_start`
- `menu_selection`
- `ip_check_started`
- `ip_check_completed`
- `ip_check_failed`
- `application_exit`

The logs include fields such as:
- `timestamp`
- `level`
- `event_type`
- `outcome`
- `correlation_id`
- `ip`
- `reason`
- `country`
- `malicious`
- `suspicious`

## What I Learned

This project helped me practice:
- building a console app in C#
- working with external APIs
- using environment variables securely
- writing structured logs
- debugging JSON parsing issues
- turning raw log data into a simple analyst-style summary

## Roadmap

Planned improvements:
- add `duration_ms` for API requests
- add active network connection analysis
- export triage summaries to file
- improve severity logic
- add tests
- improve README with screenshots

## Notes

This project is for learning, homelab practice, and portfolio development.  
It is not intended to replace professional threat intelligence or SIEM tooling.

## License

This project currently has no license attached.  
You can add an MIT license later if you want to make reuse easier.