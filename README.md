# Network Inspector

**Languages:** [English](README.md) | [Deutsch](README.de.md)

A beginner-friendly C#/.NET security project for checking IP addresses with VirusTotal, writing structured JSONL logs, generating SOC-style case reports, and performing simple local log triage.

## Overview

`network-inspector` is a small console-based security tool built as part of a hands-on blue-team / SOC learning path.  
It helps inspect IP addresses, log actions in structured JSON format, generate local SOC-style case reports, track case status changes, and summarize activity from local logs.

The project is designed to be simple enough for a beginner to understand, while still showing practical ideas that matter in security work:
- IP reputation checking
- structured logging
- correlation IDs
- local log analysis
- SOC-style case creation
- case status tracking
- basic triage logic

## Features

- Console menu interface
- Check an IP address with the VirusTotal API
- Structured JSONL logging
- Correlation IDs for IP check workflows
- Generate SOC-style Markdown case reports
- Human-readable case IDs (for example `NI-20260605-0001`)
- List all locally generated SOC cases
- Update case status (`open`, `under_review`, `closed`)
- Track status changes inside the case timeline
- Local log analysis from the generated log file
- Log summary with:
  - total events by type
  - suspicious IP events
  - top observed IPs
  - recent suspicious events

## Project Structure

```text
network-inspector/
├── README.md
├── README.de.md
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
│       │   ├── ReportService.cs
│       │   └── VirusTotalService.cs
│       ├── Program.cs
│       └── NetworkInspector.csproj
├── logs/
├── reports/
└── docs/
```

## Why I Built This

I built this project to practice practical SOC-style skills in a small and understandable format.  
Instead of only making API calls, I wanted to learn how to:
- collect useful security data
- store it in structured logs
- analyze those logs locally
- create a small triage-style workflow
- turn suspicious events into documented cases
- track case status over time

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
 Generate SOC case report
 List all SOC cases
 Update case status
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
- `ip_check_started`
- `ip_check_completed`
- `case_report_generated`
- `case_status_updated`
- potentially suspicious IP events
- top observed IPs
- recent suspicious events

### Option 4: Generate SOC case report

This option generates a local Markdown case report from the most recent suspicious IP event.  
The report includes:
- executive summary
- case metadata
- detection context
- incident details
- evidence summary
- case timeline
- recommended action
- analyst notes

### Option 5: List all SOC cases

This option lists the locally generated case reports with:
- generated timestamp
- case ID
- priority
- status
- case source

### Option 6: Update case status

This option lets you update a case by using either:
- the human-readable case ID, or
- the correlation ID

Supported statuses:
- `open`
- `under_review`
- `closed`

Status changes are also written into the case timeline.

## Example Output

### Example IP check

```text
===== VirusTotal Result =====
IP: 38.86.221.116
AS Owner: PT MITRA TELEMEDIA MANUNGGAL
Country: ID
Reputation: 0
Malicious detections: 1
Suspicious detections: 0
Harmless detections: 55
Undetected: 35

Result: Potentially suspicious.
```

### Example case timeline

```text
## Case Timeline
- `2026-06-05 07:53:28Z` - Source event observed for IP `38.86.221.116`
- `2026-06-05 07:54:01Z` - Case created with status `open` from suspicious IP event
```

### Example log analysis

```text
===== Local Log Analysis =====

Total events: 12
ip_check_started: 3
ip_check_completed: 3
case_report_generated: 2
case_status_updated: 1

Potentially suspicious IP events: 2
```

## Logging

The application writes structured JSON lines (`.jsonl`) to a local log file.

Current event examples include:
- `application_start`
- `menu_selection`
- `ip_check_started`
- `ip_check_completed`
- `ip_check_failed`
- `case_report_generated`
- `case_status_updated`
- `application_exit`

The logs include fields such as:
- `timestamp`
- `level`
- `event_type`
- `outcome`
- `correlation_id`
- `case_id`
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
- building a simple local case workflow
- generating Markdown reports
- tracking case lifecycle changes
- turning raw event data into analyst-style output

## Roadmap

Planned improvements:
- add active network connection analysis for menu option `1`
- improve severity logic beyond a simple malicious/suspicious threshold
- enrich reports with additional event correlation
- add filters for case listing
- add tests
- improve README with screenshots

## Notes

This project is for learning, homelab practice, and portfolio development.  
It is not intended to replace professional threat intelligence, IR platforms, or SIEM tooling.

## License

This project currently has no license attached.  
You can add an MIT license later if you want to make reuse easier.
