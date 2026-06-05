# Network Inspector

**Sprachen:** [English](README.md) | [Deutsch](README.de.md)

Ein einsteigerfreundliches C#/.NET-Sicherheitsprojekt zum Prüfen von IP-Adressen mit VirusTotal, zum Schreiben strukturierter JSONL-Logs, zum Erzeugen SOC-ähnlicher Case-Reports und zur einfachen lokalen Log-Triage.

## Überblick

`network-inspector` ist ein kleines konsolenbasiertes Security-Tool, das im Rahmen eines praxisnahen Blue-Team-/SOC-Lernpfads entwickelt wurde.  
Es hilft dabei, IP-Adressen zu prüfen, Aktionen in strukturiertem JSON zu protokollieren, lokale SOC-ähnliche Case-Reports zu erzeugen, Case-Statusänderungen nachzuverfolgen und Aktivitäten aus lokalen Logs zusammenzufassen.

Das Projekt ist bewusst einfach genug gehalten, damit es auch für Einsteiger verständlich bleibt, zeigt aber trotzdem praktische Ideen, die in der Sicherheitsarbeit wichtig sind:
- IP-Reputationsprüfung
- strukturiertes Logging
- Correlation IDs
- lokale Log-Analyse
- SOC-ähnliche Case-Erstellung
- Case-Status-Tracking
- einfache Triage-Logik

## Funktionen

- Konsolenbasiertes Menü
- Prüfung von IP-Adressen über die VirusTotal-API
- Strukturiertes JSONL-Logging
- Correlation IDs für IP-Check-Workflows
- Erzeugung von SOC-ähnlichen Markdown-Case-Reports
- Menschlich lesbare Case-IDs (zum Beispiel `NI-20260605-0001`)
- Auflisten aller lokal erzeugten SOC-Cases
- Aktualisierung des Case-Status (`open`, `under_review`, `closed`)
- Nachverfolgung von Statusänderungen innerhalb der Case-Timeline
- Lokale Log-Analyse auf Basis der erzeugten Log-Datei
- Log-Zusammenfassung mit:
  - Gesamtzahl der Events nach Typ
  - suspicious IP-Events
  - am häufigsten beobachteten IPs
  - zuletzt erkannten suspicious Events

## Projektstruktur

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

## Warum ich dieses Projekt gebaut habe

Ich habe dieses Projekt gebaut, um praktische SOC-nahe Fähigkeiten in einem kleinen und verständlichen Format zu üben.  
Statt nur API-Abfragen auszuführen, wollte ich lernen, wie man:
- nützliche Sicherheitsdaten sammelt
- sie in strukturierten Logs speichert
- diese Logs lokal analysiert
- einen kleinen Triage-Workflow aufbaut
- suspicious Events in dokumentierte Cases überführt
- den Status eines Cases über die Zeit nachverfolgt

## Voraussetzungen

- Installiertes .NET SDK
- Ein VirusTotal-API-Key für IP-Reputationsprüfungen
- Zugriff auf Terminal / Kommandozeile

## Installation

Repository klonen:

```bash
git clone <deine-repo-url>
cd network-inspector
```

Projekt bauen:

```bash
dotnet build src/network-inspector/NetworkInspector.csproj
```

## Konfiguration

Für VirusTotal-Abfragen muss der API-Key als Umgebungsvariable gesetzt werden.

Temporär für die aktuelle Shell-Session:

```bash
export VT_API_KEY="dein_api_key_hier"
```

Prüfen, ob die Variable gesetzt ist:

```bash
echo $VT_API_KEY
```

## Verwendung

Projekt starten mit:

```bash
dotnet run --project src/network-inspector/NetworkInspector.csproj
```

Danach erscheint ein Menü wie dieses:

```text
 Aktive Netzwerkverbindungen auflisten
 Eine IP-Adresse prüfen
 Lokale Log-Datei analysieren
 SOC-Case-Report erzeugen
 Alle SOC-Cases auflisten
 Case-Status aktualisieren
 Beenden
```

### Option 2: Eine IP-Adresse prüfen

Diese Option sendet die IP an VirusTotal und zeigt eine kurze Zusammenfassung an, zum Beispiel:
- AS Owner
- Land
- Reputation
- malicious / suspicious / harmless detections
- Tags
- Ergebniszusammenfassung

### Option 3: Lokale Log-Datei analysieren

Diese Option liest die erzeugte JSONL-Log-Datei und zeigt unter anderem:
- Gesamtzahl der Events
- `ip_check_started`
- `ip_check_completed`
- `case_report_generated`
- `case_status_updated`
- potenziell suspicious IP-Events
- am häufigsten beobachtete IPs
- zuletzt erkannte suspicious Events

### Option 4: SOC-Case-Report erzeugen

Diese Option erzeugt aus dem zuletzt erkannten suspicious IP-Event einen lokalen Markdown-Case-Report.  
Der Report enthält:
- Executive Summary
- Case-Metadaten
- Detection Context
- Incident Details
- Evidence Summary
- Case Timeline
- Recommended Action
- Analyst Notes

### Option 5: Alle SOC-Cases auflisten

Diese Option listet die lokal erzeugten Case-Reports auf mit:
- Erstellungszeitpunkt
- Case-ID
- Priorität
- Status
- Case Source

### Option 6: Case-Status aktualisieren

Mit dieser Option kann ein Case entweder über:
- die lesbare Case-ID oder
- die Correlation ID

aktualisiert werden.

Unterstützte Statuswerte:
- `open`
- `under_review`
- `closed`

Statusänderungen werden zusätzlich in die Case-Timeline geschrieben.

## Beispielausgabe

### Beispiel für einen IP-Check

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

### Beispiel für eine Case-Timeline

```text
## Case Timeline
- `2026-06-05 07:53:28Z` - Source event observed for IP `38.86.221.116`
- `2026-06-05 07:54:01Z` - Case created with status `open` from suspicious IP event
```

### Beispiel für die Log-Analyse

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

Die Anwendung schreibt strukturierte JSON-Zeilen (`.jsonl`) in eine lokale Log-Datei.

Aktuelle Event-Beispiele:
- `application_start`
- `menu_selection`
- `ip_check_started`
- `ip_check_completed`
- `ip_check_failed`
- `case_report_generated`
- `case_status_updated`
- `application_exit`

Die Logs enthalten Felder wie:
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

## Was ich dabei gelernt habe

Dieses Projekt hat mir geholfen, Folgendes zu üben:
- Aufbau einer Konsolenanwendung in C#
- Arbeit mit externen APIs
- sicherer Umgang mit Umgebungsvariablen
- Schreiben strukturierter Logs
- Aufbau eines einfachen lokalen Case-Workflows
- Erzeugen von Markdown-Reports
- Nachverfolgung von Case-Lifecycle-Änderungen
- Umwandlung roher Event-Daten in analystenähnliche Ausgaben

## Roadmap

Geplante Verbesserungen:
- Analyse aktiver Netzwerkverbindungen für Menüpunkt `1`
- realistischere Severity-Logik statt nur einer einfachen malicious/suspicious-Schwelle
- zusätzliche Event-Korrelation in Reports
- Filter für die Case-Liste
- Tests ergänzen
- README um Screenshots erweitern

## Hinweise

Dieses Projekt dient dem Lernen, der Homelab-Praxis und dem Portfolio-Aufbau.  
Es ist nicht als Ersatz für professionelle Threat-Intelligence-, Incident-Response- oder SIEM-Plattformen gedacht.

## Lizenz

Dieses Projekt hat aktuell noch keine Lizenz.  
Du kannst später zum Beispiel eine MIT-Lizenz hinzufügen, wenn du die Wiederverwendung ausdrücklich erlauben möchtest.
