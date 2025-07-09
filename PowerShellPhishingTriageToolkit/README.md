# PowerShell Phishing Triage Toolkit

A PowerShell script designed to automate phishing email triage by extracting Indicators of Compromise (IOCs) such as IPs, domains, and URLs from email headers or files, and enriching them with VirusTotal reputation lookups. Ideal for speeding up Level 1 SOC analyst workflows.

---
## Features

- **Input Options**: Paste email headers directly or load from a `.txt` file.
- **IOC Extraction**: Automatically extracts IP addresses, domains, and URLs using regex.
- **VirusTotal Enrichment**: Queries VirusTotal API to check reputation of extracted IOCs.
- **Colored Output**: Displays reputation results with color-coded statuses (Malicious = red, Suspicious = yellow, Clean = green).
- **Export Results**: Saves enriched IOC results to a CSV file for reporting or further analysis.
- **URL Encoding**: Automatically encodes URLs for VirusTotal API compliance.
- **Error Handling**: Handles API errors and invalid inputs gracefully.

---
## Requirements

- Windows PowerShell (tested on PowerShell 5.1+)
- Internet connection to access VirusTotal API
- VirusTotal API key (free sign-up at [VirusTotal](https://www.virustotal.com))

---
## Setup

1. Download or clone the script `phishing_triage.ps1` to your local machine.
2. Obtain your VirusTotal API key by creating a free account at [VirusTotal](https://www.virustotal.com).
3. Run PowerShell and navigate to the folder containing `phishing_triage.ps1`.

---
### Running the Script

Run the script:

.\phishing_triage.ps1

Choose input type:

- Enter 1 to paste email headers manually (type END on a new line when done).

- Enter 2 to load headers from a .txt file (enter full path when prompted).

Enter your VirusTotal API key.

View IOC extraction and VirusTotal reputation results in the console with colors.

Enter the output CSV file path to save the enriched IOC report (e.g., C:\temp\phishing_results.csv).

