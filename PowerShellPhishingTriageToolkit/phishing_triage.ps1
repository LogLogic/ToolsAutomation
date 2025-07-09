# PowerShell Phishing Triage Toolkit
# Extracts IOCs (IPs, domains, URLs) from email headers, enriches with VirusTotal, and exports to CSV.

# === Regex Pattern Log (for reference) ===
# IP Regex:        \b(?:\d{1,3}\.){3}\d{1,3}\b
# Domain Regex:    \b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b
# URL Regex:       http[s]?://[^\s"<>]+

Write-Host "=== PowerShell Phishing Triage Toolkit ==="

# === Get Email Headers from User ===
$choice = Read-Host "Choose input type: 1 = Paste headers, 2 = Load from .txt file"

if ($choice -eq "1") {
    Write-Host "Paste your email headers (type 'END' to finish):"
    $lines = @()
    while (($line = Read-Host) -ne "END") {
        $lines += $line
    }
    $emailHeader = $lines -join "`n"
}
elseif ($choice -eq "2") {
    $filePath = Read-Host "Enter full path to the .txt file"
    if (Test-Path $filePath) {
        $emailHeader = Get-Content $filePath -Raw
    } else {
        Write-Host "File not found. Exiting."
        exit
    }
} else {
    Write-Host "Invalid choice. Exiting."
    exit
}

Write-Host "`nInput loaded successfully. Starting extraction..."

# === IOC Extraction Functions ===
function Get-IPs {
    param ($text)
    $pattern = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return [regex]::Matches($text, $pattern) | ForEach-Object { $_.Value } | Sort-Object -Unique
}

function Get-Domains {
    param ($text)
    $pattern = '\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    return [regex]::Matches($text, $pattern) | ForEach-Object { $_.Value } | Sort-Object -Unique
}

function Get-URLs {
    param ($text)
    $pattern = 'http[s]?://[^\s"<>]+'
    return [regex]::Matches($text, $pattern) | ForEach-Object { $_.Value } | Sort-Object -Unique
}

# === Extract IOCs from Header Text ===
$ips = Get-IPs -text $emailHeader
$domains = Get-Domains -text $emailHeader
$urls = Get-URLs -text $emailHeader

Write-Host "`n==== Extracted IOCs ===="
Write-Host "`nIPs Found:"; $ips | ForEach-Object { Write-Host "- $_" }
Write-Host "`nDomains Found:"; $domains | ForEach-Object { Write-Host "- $_" }
Write-Host "`nURLs Found:"; $urls | ForEach-Object { Write-Host "- $_" }

# === VirusTotal Lookup Function ===
function Get-VTReputation {
    param (
        [string]$ioc,
        [string]$type,     # "ip" or "url"
        [string]$apiKey
    )

    $headers = @{ 
        "x-apikey" = $apiKey 
        "Content-Type" = "application/x-www-form-urlencoded"
    }

    try {
        if ($type -eq "ip") {
            # Simple IP lookup
            $url = "https://www.virustotal.com/api/v3/ip_addresses/$ioc"
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        }
        elseif ($type -eq "url") {
            # Encode URL to VirusTotal's Base64 URL-safe format
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($ioc)
            $base64 = [Convert]::ToBase64String($bytes)
            $urlId = $base64.Replace('+','-').Replace('/','_').TrimEnd('=')

            Start-Sleep -Seconds 30  # Allow time for analysis

            $lookupUrl = "https://www.virustotal.com/api/v3/urls/$urlId"

            try {
                $response = Invoke-RestMethod -Uri $lookupUrl -Headers $headers -Method Get
            } catch {
                return "Error fetching URL report: $($_.Exception.Message)"
            }
        }
        else {
            return "Unsupported type"
        }

        # Extract and interpret reputation stats
        $stats = $response.data.attributes.last_analysis_stats
        $malicious = $stats.malicious
        $suspicious = $stats.suspicious

        if ($malicious -gt 0) {
            return "Malicious"
        } elseif ($suspicious -gt 0) {
            return "Suspicious"
        } else {
            return "Clean"
        }
    } catch {
        return "Error: $($_.Exception.Message)"
    }
}

# === Ask for VirusTotal API Key ===
$vtApiKey = Read-Host "Enter your VirusTotal API key"

Write-Host "`n=== VirusTotal Enrichment Results ==="

# === Enrich IPs ===
foreach ($ip in $ips) {
    $result = Get-VTReputation -ioc $ip -type "ip" -apiKey $vtApiKey
    switch ($result) {
        "Malicious"   { Write-Host "IP: $ip --> $result" -ForegroundColor Red }
        "Suspicious"  { Write-Host "IP: $ip --> $result" -ForegroundColor Yellow }
        "Clean"       { Write-Host "IP: $ip --> $result" -ForegroundColor Green }
        default       { Write-Host "IP: $ip --> $result" }
    }
}

# === Enrich URLs ===
foreach ($url in $urls) {
    $result = Get-VTReputation -ioc $url -type "url" -apiKey $vtApiKey
    switch ($result) {
        "Malicious"   { Write-Host "URL: $url --> $result" -ForegroundColor Red }
        "Suspicious"  { Write-Host "URL: $url --> $result" -ForegroundColor Yellow }
        "Clean"       { Write-Host "URL: $url --> $result" -ForegroundColor Green }
        default       { Write-Host "URL: $url --> $result" }
    }
}

# === Collect All Results ===
$results = @()

foreach ($ip in $ips) {
    $result = Get-VTReputation -ioc $ip -type "ip" -apiKey $vtApiKey
    $results += [PSCustomObject]@{
        Type       = "IP"
        IOC        = $ip
        Reputation = $result
    }
}

foreach ($url in $urls) {
    $result = Get-VTReputation -ioc $url -type "url" -apiKey $vtApiKey
    $results += [PSCustomObject]@{
        Type       = "URL"
        IOC        = $url
        Reputation = $result
    }
}

# === Export to CSV ===
$outputPath = Read-Host "Enter output CSV file path (e.g., C:\temp\phishing_results.csv)"
$results | Export-Csv -Path $outputPath -NoTypeInformation
Write-Host "Results exported to $outputPath"
