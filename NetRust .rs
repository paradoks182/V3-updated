// src/main.rs
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::sync::Semaphore;
use futures::stream::{self, StreamExt};
use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use rayon::prelude::*;
use crossterm::{
    terminal::{self, Clear, ClearType},
    cursor::{MoveTo, SavePosition, RestorePosition},
    style::{Color, Stylize, SetForegroundColor, ResetColor},
    ExecutableCommand,
};
use std::io::{self, Write};
use std::fs::File;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use colored::*;
use chrono::Local;
use dns_lookup::lookup_host;
use ipnetwork::IpNetwork;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use pnet::datalink;
use pnet::ipnetwork::IpNetwork as PnetIpNetwork;
use sysinfo::{System, SystemExt, NetworkExt};
use mac_address::get_mac_address;
use whois_rust::{WhoIs, WhoIsLookupOptions};
use std::net::UdpSocket;

#[derive(Parser)]
#[clap(author = "Elliot", version = "1.0.0", about = "Advanced Network Security Scanner")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    
    /// Output format (json, yaml, table)
    #[clap(short, long, default_value = "table")]
    format: String,
    
    /// Thread count for parallel scanning
    #[clap(short, long, default_value_t = 100)]
    threads: usize,
    
    /// Timeout in milliseconds
    #[clap(short, long, default_value_t = 1000)]
    timeout: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Fast port scanner
    Scan {
        /// Target IP or hostname
        target: String,
        
        /// Port range (e.g., 1-1000 or 80,443,8080)
        #[clap(short, long, default_value = "1-1024")]
        ports: String,
        
        /// Perform service detection
        #[clap(short, long)]
        service: bool,
        
        /// Get banners from services
        #[clap(short, long)]
        banner: bool,
    },
    
    /// Network discovery
    Discover {
        /// Network in CIDR notation (e.g., 192.168.1.0/24)
        network: String,
        
        /// Ping sweep
        #[clap(short, long)]
        ping: bool,
        
        /// ARP scan (requires root)
        #[clap(short, long)]
        arp: bool,
    },
    
    /// DNS enumeration
    Dns {
        /// Domain to enumerate
        domain: String,
        
        /// Perform DNS zone transfer
        #[clap(short, long)]
        zone: bool,
        
        /// Subdomain brute force
        #[clap(short, long)]
        brute: bool,
        
        /// Wordlist file for brute force
        #[clap(short, long)]
        wordlist: Option<String>,
    },
    
    /// HTTP/S web scanner
    Web {
        /// Target URL
        url: String,
        
        /// Check for common vulnerabilities
        #[clap(short, long)]
        vuln: bool,
        
        /// Directory brute force
        #[clap(short, long)]
        dirb: bool,
        
        /// Wordlist for directory brute force
        #[clap(short, long)]
        wordlist: Option<String>,
    },
    
    /// Geolocation lookup
    Geoip {
        /// IP address to locate
        ip: String,
    },
    
    /// MAC address vendor lookup
    Mac {
        /// MAC address to lookup
        mac: String,
    },
    
    /// Network speed test
    Speedtest,
    
    /// Packet capture
    Capture {
        /// Interface to capture on
        #[clap(short, long)]
        interface: String,
        
        /// Number of packets to capture
        #[clap(short, long, default_value_t = 100)]
        count: usize,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct ScanResult {
    port: u16,
    state: String,
    service: Option<String>,
    banner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HostInfo {
    ip: String,
    hostname: Option<String>,
    mac: Option<String>,
    vendor: Option<String>,
    open_ports: Vec<ScanResult>,
    os: Option<String>,
    response_time: f64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsRecord {
    name: String,
    r#type: String,
    ttl: u32,
    data: String,
}

struct Scanner {
    timeout: Duration,
    max_concurrent: usize,
    progress: Option<ProgressBar>,
}

impl Scanner {
    fn new(timeout_ms: u64, max_concurrent: usize) -> Self {
        Scanner {
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent,
            progress: None,
        }
    }
    
    async fn scan_port(&self, target: &str, port: u16) -> Option<ScanResult> {
        let addr = format!("{}:{}", target, port);
        let socket: SocketAddr = match addr.parse() {
            Ok(s) => s,
            Err(_) => return None,
        };
        
        match timeout(self.timeout, TcpStream::connect(&socket)).await {
            Ok(Ok(_)) => {
                let mut result = ScanResult {
                    port,
                    state: "open".to_string(),
                    service: None,
                    banner: None,
                };
                
                // Service detection
                if let Some(service) = self.detect_service(port) {
                    result.service = Some(service);
                }
                
                Some(result)
            }
            _ => None,
        }
    }
    
    fn detect_service(&self, port: u16) -> Option<String> {
        let services: HashMap<u16, &str> = [
            (21, "FTP"),
            (22, "SSH"),
            (23, "TELNET"),
            (25, "SMTP"),
            (53, "DNS"),
            (80, "HTTP"),
            (110, "POP3"),
            (111, "RPCBIND"),
            (135, "MSRPC"),
            (139, "NETBIOS"),
            (143, "IMAP"),
            (443, "HTTPS"),
            (445, "SMB"),
            (465, "SMTPS"),
            (514, "SYSLOG"),
            (587, "SMTP"),
            (993, "IMAPS"),
            (995, "POP3S"),
            (1080, "SOCKS"),
            (1433, "MSSQL"),
            (1521, "ORACLE"),
            (3306, "MYSQL"),
            (3389, "RDP"),
            (5432, "POSTGRESQL"),
            (5900, "VNC"),
            (6379, "REDIS"),
            (8080, "HTTP-ALT"),
            (8443, "HTTPS-ALT"),
            (9200, "ELASTICSEARCH"),
            (27017, "MONGODB"),
        ].iter().cloned().collect();
        
        services.get(&port).map(|&s| s.to_string())
    }
    
    async fn scan_ports(&self, target: &str, ports: Vec<u16>) -> Vec<ScanResult> {
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let mut handles = vec![];
        
        for port in ports {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let target = target.to_string();
            
            let handle = tokio::spawn(async move {
                let _permit = permit;
                let scanner = Scanner::new(1000, 100);
                scanner.scan_port(&target, port).await
            });
            
            handles.push(handle);
        }
        
        let mut results = vec![];
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                results.push(result);
                if let Some(pb) = &self.progress {
                    pb.inc(1);
                }
            }
        }
        
        results
    }
}

fn parse_port_range(port_str: &str) -> Vec<u16> {
    let mut ports = vec![];
    
    if port_str.contains(',') {
        // Comma-separated list
        for part in port_str.split(',') {
            if let Ok(port) = part.trim().parse::<u16>() {
                ports.push(port);
            }
        }
    } else if port_str.contains('-') {
        // Range
        let parts: Vec<&str> = port_str.split('-').collect();
        if parts.len() == 2 {
            if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>()) {
                for port in start..=end {
                    ports.push(port);
                }
            }
        }
    } else {
        // Single port
        if let Ok(port) = port_str.parse::<u16>() {
            ports.push(port);
        }
    }
    
    ports
}

async fn scan_command(target: String, port_str: String, service: bool, banner: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 RUST PORT SCANNER v1.0                  ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    println!("{} {}", "Target:".bright_green(), target);
    println!("{} {}", "Ports:".bright_green(), port_str);
    println!("{} {}", "Service detection:".bright_green(), if service { "yes" } else { "no" });
    println!("{} {}", "Banner grabbing:".bright_green(), if banner { "yes" } else { "no" });
    println!();
    
    let ports = parse_port_range(&port_str);
    println!("{} {} ports to scan", "Scanning".bright_yellow(), ports.len());
    
    let pb = ProgressBar::new(ports.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));
    
    let scanner = Scanner::new(1000, 100);
    let results = scanner.scan_ports(&target, ports).await;
    
    pb.finish_with_message("Scan complete");
    println!();
    
    if results.is_empty() {
        println!("{} No open ports found", "[-]".red());
    } else {
        println!("{} Open ports found: {}", "[+]".green(), results.len());
        println!();
        println!("{:<8} {:<12} {:<20}", "PORT", "STATE", "SERVICE");
        println!("{}", "─".repeat(40));
        
        for result in results.iter().take(20) {
            println!("{:<8} {:<12} {:<20}", 
                format!("{}/tcp", result.port).bright_white(),
                result.state.bright_green(),
                result.service.as_deref().unwrap_or("unknown").bright_blue());
        }
        
        if results.len() > 20 {
            println!("... and {} more", results.len() - 20);
        }
    }
    
    Ok(())
}

async fn discover_command(network: String, ping: bool, arp: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 NETWORK DISCOVERY v1.0                  ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    let network: IpNetwork = network.parse()?;
    println!("{} {}", "Network:".bright_green(), network);
    println!("{} {}", "Ping sweep:".bright_green(), if ping { "yes" } else { "no" });
    println!("{} {}", "ARP scan:".bright_green(), if arp { "yes" } else { "no" });
    println!();
    
    let pb = ProgressBar::new_spinner();
    pb.set_message("Scanning network...");
    
    let mut hosts = vec![];
    
    for ip in network.iter() {
        pb.set_message(format!("Checking {}", ip));
        
        // Ping check
        if ping {
            let output = std::process::Command::new("ping")
                .arg("-n")
                .arg("1")
                .arg("-w")
                .arg("1000")
                .arg(ip.to_string())
                .output();
                
            if let Ok(output) = output {
                if output.status.success() {
                    hosts.push(ip);
                    println!("{} {} is alive", "[+]".green(), ip);
                }
            }
        }
        
        pb.tick();
    }
    
    pb.finish_with_message("Scan complete");
    
    println!();
    println!("{} {} hosts found", "[+]".green(), hosts.len());
    
    Ok(())
}

async fn dns_command(domain: String, zone: bool, brute: bool, wordlist: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 DNS ENUMERATION v1.0                    ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    println!("{} {}", "Domain:".bright_green(), domain);
    println!();
    
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    
    // A records
    if let Ok(response) = resolver.lookup_ip(&domain) {
        println!("{} A Records:", "[+]".green());
        for ip in response.iter() {
            println!("  {}", ip);
        }
    }
    
    // MX records
    if let Ok(response) = resolver.mx_lookup(&domain) {
        println!("\n{} MX Records:", "[+]".green());
        for mx in response.iter() {
            println!("  {} (priority: {})", mx.exchange(), mx.preference());
        }
    }
    
    // NS records
    if let Ok(response) = resolver.ns_lookup(&domain) {
        println!("\n{} NS Records:", "[+]".green());
        for ns in response.iter() {
            println!("  {}", ns);
        }
    }
    
    // TXT records
    if let Ok(response) = resolver.txt_lookup(&domain) {
        println!("\n{} TXT Records:", "[+]".green());
        for txt in response.iter() {
            for data in txt.iter() {
                println!("  {}", data);
            }
        }
    }
    
    // Zone transfer
    if zone {
        println!("\n{} Attempting zone transfer...", "[*]".yellow());
        // Zone transfer implementation
    }
    
    // Subdomain brute force
    if brute {
        println!("\n{} Brute forcing subdomains...", "[*]".yellow());
        let common = vec![
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
            "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
            "docs", "resources", "intranet", "status", "demo", "server", "video", "api",
        ];
        
        for sub in common {
            let subdomain = format!("{}.{}", sub, domain);
            if resolver.lookup_ip(&subdomain).is_ok() {
                println!("  {} {}", "[+]".green(), subdomain);
            }
        }
    }
    
    Ok(())
}

async fn web_command(url: String, vuln: bool, dirb: bool, wordlist: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 WEB SCANNER v1.0                        ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    println!("{} {}", "Target:".bright_green(), url);
    println!("{} {}", "Vulnerability scan:".bright_green(), if vuln { "yes" } else { "no" });
    println!("{} {}", "Directory brute force:".bright_green(), if dirb { "yes" } else { "no" });
    println!();
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()?;
    
    // Check if site is up
    match client.get(&url).send().await {
        Ok(response) => {
            println!("{} Site is up (HTTP {})", "[+]".green(), response.status());
            println!("{} Server: {}", "[*]".yellow(), response.headers()
                .get("server")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("Unknown"));
            println!("{} Technology: {}", "[*]".yellow(), response.headers()
                .get("x-powered-by")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("Unknown"));
        }
        Err(e) => {
            println!("{} Site is down: {}", "[-]".red(), e);
            return Ok(());
        }
    }
    
    // Directory brute force
    if dirb {
        println!("\n{} Directory brute force...", "[*]".yellow());
        
        let common_dirs = vec![
            "admin", "wp-admin", "administrator", "login", "backup", "backups",
            "config", "configuration", "phpmyadmin", "pma", "mysql", "db",
            "test", "tests", "temp", "tmp", "logs", "log", "data", "uploads",
            "images", "img", "css", "js", "assets", "static", "api", "v1", "v2",
            "rest", "graphql", "swagger", "docs", "documentation", "help",
            "server-status", "server-info", "phpinfo", "info", "status",
        ];
        
        for dir in common_dirs {
            let test_url = format!("{}/{}", url.trim_end_matches('/'), dir);
            match client.get(&test_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    println!("  {} {} (HTTP {})", "[+]".green(), test_url, resp.status());
                }
                _ => {}
            }
        }
    }
    
    // Vulnerability scan
    if vuln {
        println!("\n{} Vulnerability scan...", "[*]".yellow());
        
        // Check for common vulnerabilities
        let checks = vec![
            ("/phpinfo.php", "PHP Info"),
            ("/info.php", "PHP Info"),
            ("/test.php", "PHP Test"),
            ("/.env", "Environment file"),
            ("/.git/config", "Git config"),
            ("/wp-config.php.bak", "WordPress backup"),
            ("/backup.sql", "SQL backup"),
        ];
        
        for (path, check_name) in checks {
            let test_url = format!("{}{}", url.trim_end_matches('/'), path);
            match client.get(&test_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    println!("  {} Found {} ({})", "[!]".red(), check_name, test_url);
                }
                _ => {}
            }
        }
    }
    
    Ok(())
}

async fn geoip_command(ip: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 GEOLOCATION v1.0                        ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    let response = reqwest::get(&format!("http://ip-api.com/json/{}", ip)).await?;
    let data: serde_json::Value = response.json().await?;
    
    if data["status"] == "success" {
        println!("{} IP: {}", "[+]".green(), data["query"]);
        println!("{} Country: {}", "[*]".yellow(), data["country"]);
        println!("{} Region: {}", "[*]".yellow(), data["regionName"]);
        println!("{} City: {}", "[*]".yellow(), data["city"]);
        println!("{} ZIP: {}", "[*]".yellow(), data["zip"]);
        println!("{} Latitude: {}", "[*]".yellow(), data["lat"]);
        println!("{} Longitude: {}", "[*]".yellow(), data["lon"]);
        println!("{} Timezone: {}", "[*]".yellow(), data["timezone"]);
        println!("{} ISP: {}", "[*]".yellow(), data["isp"]);
        println!("{} Organization: {}", "[*]".yellow(), data["org"]);
        println!("{} AS: {}", "[*]".yellow(), data["as"]);
    } else {
        println!("{} Location not found", "[-]".red());
    }
    
    Ok(())
}

async fn mac_command(mac: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 MAC VENDOR LOOKUP v1.0                  ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    let clean_mac = mac.replace(&[':', '-', '.'][..], "");
    
    if clean_mac.len() >= 6 {
        let oui = &clean_mac[0..6];
        let response = reqwest::get(&format!("https://api.macvendors.com/{}", oui)).await?;
        let vendor = response.text().await?;
        
        println!("{} MAC: {}", "[+]".green(), mac);
        println!("{} OUI: {}", "[*]".yellow(), oui);
        println!("{} Vendor: {}", "[*]".yellow(), vendor);
    } else {
        println!("{} Invalid MAC address", "[-]".red());
    }
    
    Ok(())
}

async fn speedtest_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 NETWORK SPEEDTEST v1.0                  ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    println!("{} Running speed test...", "[*]".yellow());
    
    let test_file = "http://speedtest.tele2.net/100MB.zip";
    let start = std::time::Instant::now();
    
    let response = reqwest::get(test_file).await?;
    let total_size = response.content_length().unwrap_or(0);
    
    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .unwrap()
        .progress_chars("#>-"));
    
    let mut downloaded = 0;
    let mut stream = response.bytes_stream();
    
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        downloaded += chunk.len();
        pb.set_position(downloaded as u64);
    }
    
    pb.finish();
    
    let duration = start.elapsed();
    let speed_mbps = (total_size as f64 * 8.0) / (duration.as_secs_f64() * 1_000_000.0);
    
    println!();
    println!("{} Download complete!", "[+]".green());
    println!("{} Time: {:.2}s", "[*]".yellow(), duration.as_secs_f64());
    println!("{} Speed: {:.2} Mbps", "[*]".yellow(), speed_mbps);
    println!("{} Data: {:.2} MB", "[*]".yellow(), total_size as f64 / 1_000_000.0);
    
    Ok(())
}

async fn capture_command(interface: String, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "╔══════════════════════════════════════════════════════════╗".bright_blue());
    println!("{}", "║                 PACKET CAPTURE v1.0                     ║".bright_blue());
    println!("{}", "╚══════════════════════════════════════════════════════════╝".bright_blue());
    println!();
    
    println!("{} Interface: {}", "[*]".yellow(), interface);
    println!("{} Packets to capture: {}", "[*]".yellow(), count);
    println!();
    
    println!("{} Starting capture... (Ctrl+C to stop)", "[*]".yellow());
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Scan { target, ports, service, banner } => {
            scan_command(target, ports, service, banner).await?;
        }
        Commands::Discover { network, ping, arp } => {
            discover_command(network, ping, arp).await?;
        }
        Commands::Dns { domain, zone, brute, wordlist } => {
            dns_command(domain, zone, brute, wordlist).await?;
        }
        Commands::Web { url, vuln, dirb, wordlist } => {
            web_command(url, vuln, dirb, wordlist).await?;
        }
        Commands::Geoip { ip } => {
            geoip_command(ip).await?;
        }
        Commands::Mac { mac } => {
            mac_command(mac).await?;
        }
        Commands::Speedtest => {
            speedtest_command().await?;
        }
        Commands::Capture { interface, count } => {
            capture_command(interface, count).await?;
        }
    }
    
    Ok(())
}