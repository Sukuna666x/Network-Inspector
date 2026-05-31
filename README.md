# Network-Inspector 🕵🏻‍♂️

Kleines C#-Konsolentool für Windows, das aktive TCP-Verbindungen anzeigt und einzelne IP-Adressen mit VirusTotal prüft.

## Features 🔥

- Listet aktive TCP-Verbindungen mit lokaler Adresse, Remote-Adresse und PID
- Einfaches Konsolenmenü
- Prüfung einer IP-Adresse über die VirusTotal API

## Voraussetzungen ✍🏻

- Windows
- .NET SDK oder .NET Runtime
- Gültiger VirusTotal API-Key

## Installation ⬇️

```bash
git clone https://github.com/<dein-username>/network-inspector.git
cd network-inspector
dotnet build
```

## Konfiguration ⚙️

Trage deinen VirusTotal API-Key im Code ein oder lies ihn über eine Umgebungsvariable wie `VT_API_KEY` ein.

## Nutzung 💻

```bash
dotnet run
```

Menüoptionen:

- `1` Aktive Netzwerkverbindungen auflisten
- `2` IP-Adresse mit VirusTotal prüfen

## Hinweise ‼️

Das Projekt ist als Lern- und Lab-Tool gedacht. Später können u. a. die VirusTotal v3 API, JSON-Parsing und sicheres Secret-Handling ergänzt werden.
