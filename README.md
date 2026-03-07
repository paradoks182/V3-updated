# 🦀 NetRust

A high-performance, asynchronous network security scanner written in Rust. Fast, reliable, and feature-rich.

## ✨ Features

- **🚀 Blazing Fast** - Async I/O and parallel processing
- **🔍 Port Scanning** - TCP connect scans with service detection
- **🌐 Network Discovery** - Ping sweep and ARP scanning
- **📡 DNS Enumeration** - Record lookup and zone transfers
- **🌍 Web Scanning** - Directory brute force and vulnerability checks
- **📍 Geolocation** - IP address geolocation
- **🏭 MAC Lookup** - MAC address vendor identification
- **⚡ Speed Test** - Network bandwidth testing
- **📦 Packet Capture** - Network traffic analysis
- **📊 Multiple Output Formats** - Table, JSON, YAML

## 🚀 Quick Start

### Installation




Port Scanner

scan <TARGET>
    -p, --ports <RANGE>    Port range (1-1000 or 80,443,8080)
    -s, --service          Enable service detection
    -b, --banner           Enable banner grabbing
Network Discovery

discover <NETWORK>
    --ping                 Perform ping sweep
    --arp                  Perform ARP scan (requires root)
DNS Enumeration

dns <DOMAIN>
    --zone                 Attempt zone transfer
    --brute                Subdomain brute force
    -w, --wordlist <FILE>  Wordlist for brute force
Web Scanner

web <URL>
    --vuln                 Check for vulnerabilities
    --dirb                 Directory brute force
    -w, --wordlist <FILE>  Wordlist for directory scan
Geolocation

geoip <IP>                 Get IP location information
MAC Lookup
mac <MAC>                  Get MAC address vendor

Speed Test

speedtest                  Test network bandwidth

```bash
# Clone the repository
git clone 
cd NetRust
