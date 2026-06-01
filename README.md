# Network-Inspector 🕵🏻‍♂️

[English](README.md)

Network-Inspector ist ein kleines C#-Konsolenprojekt zum Lernen und Experimentieren mit IP-Reputationsabfragen über die VirusTotal API v3.  
Der aktuelle Stand des Projekts bietet ein einfaches Konsolenmenü, validiert IP-Adressen und ruft zu einer IP-Adresse verschiedene VirusTotal-Informationen wie ASN-Owner, Land, Reputation und Analysewerte ab. [web:137][web:314]

## Funktionen

- Einfaches Konsolenmenü
- Validierung von IP-Adressen vor der Abfrage
- VirusTotal-IP-Abfrage über API v3
- Anzeige von:
  - AS Owner
  - Land
  - Reputation
  - Malicious Detections
  - Suspicious Detections
  - Harmless Detections
  - Undetected
  - Tags (falls vorhanden)

## Aktueller Stand

Das Projekt befindet sich aktuell in einer frühen Lern- und Aufbauphase.  
Die VirusTotal-IP-Abfrage funktioniert bereits, während weitere Funktionen wie das Auslesen aktiver TCP-Verbindungen erst in späteren Schritten umgesetzt werden.

## Voraussetzungen

- Installiertes .NET SDK
- VirusTotal-Account mit API-Key
- macOS, Linux oder Windows für die aktuelle Konsolenversion

## Installation

```bash
git clone https://github.com/<dein-username>/network-inspector.git
cd network-inspector
dotnet build ./src/NetworkInspector
```

## Konfiguration

Der VirusTotal-API-Key sollte nicht direkt in den Quellcode geschrieben werden, sondern als Umgebungsvariable gesetzt werden.

Beispiel für macOS/Linux:

```bash
export VT_API_KEY="dein_api_key"
```

Das Projekt liest den Key aktuell über folgende Zeile aus:

```csharp
Environment.GetEnvironmentVariable("VT_API_KEY")
```

## Nutzung

Projekt starten mit:

```bash
cd src/NetworkInspector
dotnet run
```

Menüoptionen:

- `1` Platzhalter für spätere Netzwerk-/TCP-Funktion
- `2` IP-Adresse mit VirusTotal prüfen
- `0` Anwendung beenden

## Beispielausgabe

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

Geplante nächste Schritte:

- VirusTotal-Logik in eigene Service-Klasse auslagern
- Projektstruktur verbessern
- Fehlerbehandlung erweitern
- Funktion für aktive TCP-Verbindungen ergänzen
- README und Repository-Metadaten weiter verbessern

## Hinweise

Dieses Projekt ist als Lernprojekt und kleines Lab-Tool gedacht.  
API-Keys sollten niemals in GitHub hochgeladen oder direkt im Code gespeichert werden.

## Lizenz

Aktuell wurde noch keine Lizenz hinzugefügt.
