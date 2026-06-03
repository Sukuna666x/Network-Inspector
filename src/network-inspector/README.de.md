# Network Inspector

**Sprachen:** [English](README.md) | [Deutsch](README.de.md)

Ein anfängerfreundliches C#/.NET-Sicherheitsprojekt zum Prüfen von IP-Adressen mit VirusTotal, zum Schreiben strukturierter JSONL-Logs und zur einfachen lokalen Log-Triage.

## Überblick

`network-inspector` ist ein kleines, konsolenbasiertes Security-Tool, das im Rahmen eines praktischen Blue-Team-/SOC-Lernwegs entwickelt wurde.  
Es hilft dabei, IP-Adressen zu prüfen, Aktionen in strukturierten JSON-Logs zu speichern und lokale Logdaten zusammenzufassen.

Das Projekt ist bewusst so aufgebaut, dass es für Einsteiger verständlich bleibt und trotzdem praktische Konzepte aus der Security-Arbeit zeigt:
- IP-Reputation-Checks
- strukturiertes Logging
- Correlation IDs
- lokale Log-Analyse
- einfache Triage-Logik

## Funktionen

- Konsolen-Menüoberfläche
- Prüfung einer IP-Adresse über die VirusTotal-API
- Strukturiertes JSONL-Logging
- Correlation IDs für IP-Check-Abläufe
- Lokale Log-Analyse aus der erzeugten Logdatei
- Triage-Zusammenfassung mit:
  - häufigsten geprüften IPs
  - häufigsten Fehlergründen
  - gesehenen Ländern
  - verdächtigen IP-Zusammenfassungen
  - einfacher Severity-Einstufung

## Projektstruktur

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

## Warum ich dieses Projekt gebaut habe

Ich habe dieses Projekt gebaut, um praktische SOC-nahe Fähigkeiten in einem kleinen und verständlichen Format zu trainieren.  
Statt nur einfache API-Aufrufe zu machen, wollte ich lernen, wie man:
- nützliche Security-Daten sammelt
- sie in strukturierten Logs speichert
- diese Logs lokal analysiert
- und daraus einen kleinen Triage-Workflow erstellt

## Voraussetzungen

- Installiertes .NET SDK
- Ein VirusTotal-API-Key für IP-Reputationsprüfungen
- Zugriff auf ein Terminal / die Kommandozeile

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

## Nutzung

Projekt starten mit:

```bash
dotnet run --project src/network-inspector/NetworkInspector.csproj
```

Danach erscheint ein Menü wie dieses:

```text
 List active network connections
 Check an IP address
 Analyze local log file
 Exit
```

### Option 2: IP-Adresse prüfen

Diese Option sendet die IP an VirusTotal und zeigt eine kurze Zusammenfassung an, zum Beispiel:
- AS Owner
- Land
- Reputation
- malicious / suspicious / harmless detections
- Tags
- Ergebniszusammenfassung

### Option 3: Lokale Logdatei analysieren

Diese Option liest die erzeugte JSONL-Logdatei ein und zeigt:
- Gesamtzahl der Events
- erfolgreiche IP-Checks
- fehlgeschlagene IP-Checks
- potenziell verdächtige Ergebnisse
- häufigste geprüfte IPs
- häufigste Fehlergründe
- gesehene Länder
- verdächtige IPs mit Severity-Einstufung

## Beispielausgabe

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

Die Anwendung schreibt strukturierte JSON-Zeilen (`.jsonl`) in eine lokale Logdatei.

Aktuelle Event-Beispiele:
- `application_start`
- `menu_selection`
- `ip_check_started`
- `ip_check_completed`
- `ip_check_failed`
- `application_exit`

Die Logs enthalten Felder wie:
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

## Was ich gelernt habe

Dieses Projekt hat mir geholfen, Folgendes zu üben:
- Aufbau einer Konsolenanwendung in C#
- Arbeiten mit externen APIs
- sicherer Umgang mit Umgebungsvariablen
- Schreiben strukturierter Logs
- Debugging von JSON-Parsing-Problemen
- Umwandlung roher Logdaten in eine einfache analystenartige Zusammenfassung

## Roadmap

Geplante Verbesserungen:
- `duration_ms` für API-Anfragen ergänzen
- Analyse aktiver Netzwerkverbindungen hinzufügen
- Triage-Zusammenfassungen in Datei exportieren
- Severity-Logik verbessern
- Tests hinzufügen
- README mit Screenshots erweitern

## Hinweise

Dieses Projekt ist für Lernen, Homelab-Praxis und Portfolio-Aufbau gedacht.  
Es soll keine professionelle Threat-Intelligence- oder SIEM-Lösung ersetzen.

## Lizenz

Aktuell ist für dieses Projekt noch keine Lizenz hinterlegt.  
Später kannst du z. B. eine MIT-Lizenz hinzufügen, wenn du Wiederverwendung erleichtern möchtest.