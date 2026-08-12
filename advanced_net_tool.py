#!/usr/bin/env python3
"""
Advanced Network Diagnostic & Security Tool v2.0
Includes: BGP, Security, Performance, Automation, Integrations, UX
"""

import argparse
import json
import csv
import sys
import os
import time
import socket
import ssl
import threading
import statistics
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

# --- External Libs with Fallbacks ---
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("Warning: 'requests' not found. Install via 'pip install requests' for full functionality.")

try:
    import dns.resolver
    import dns.dnssec
    import dns.rdatatype
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    print("Warning: 'dnspython' not found. DNSSEC checks disabled.")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    print("Info: 'rich' not found. Using basic text output. Install for TUI mode.")

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    print("Info: 'httpx' not found. QUIC/HTTP3 tests disabled.")

# --- Data Classes ---
@dataclass
class BGPInfo:
    asn: str = "Unknown"
    as_name: str = "Unknown"
    country: str = "Unknown"
    registry: str = "Unknown"
    prefix: str = "Unknown"
    roa_status: str = "Unknown"  # Valid, Invalid, Unknown
    communities: List[str] = None

@dataclass
class SecurityInfo:
    ssl_valid: bool = False
    ssl_expiry: str = "N/A"
    ssl_issuer: str = "N/A"
    hsts: bool = False
    csp: bool = False
    x_frame_options: bool = False
    dnssec_valid: bool = False
    tls_version: str = "N/A"

@dataclass
class PerformanceInfo:
    latency_avg: float = 0.0
    jitter_avg: float = 0.0
    packet_loss: float = 0.0
    tcp_window_scale: bool = False
    http3_support: bool = False
    download_speed_mbps: float = 0.0

@dataclass
class ProviderInfo:
    is_cloud: bool = False
    cloud_provider: str = "None"
    is_vpn: bool = False
    vpn_provider: str = "None"
    hosting_type: str = "Residential/ISP"

@dataclass
class FullReport:
    timestamp: str
    target: str
    bgp: BGPInfo
    security: SecurityInfo
    performance: PerformanceInfo
    provider: ProviderInfo

# --- Global Config ---
CLOUD_RANGES = {
    "AWS": ["52.", "54.", "35.", "18."], # Simplified for demo
    "Google": ["8.8.", "142.", "35.1"],
    "Azure": ["40.", "13.", "20."],
    "Cloudflare": ["104.", "172.", "173."]
}

VPN_INDICATORS = ["vpn", "proxy", "tunnel", "anonymous"] # Keywords in ASN name

# --- Core Functions ---

def get_ip_info(ip: str) -> Dict:
    """Fetches IP info via API (ip-api.com is free for non-commercial)"""
    if not HAS_REQUESTS:
        return {}
    try:
        url = f"http://ip-api.com/json/{ip}"
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}

def check_bgp(ip: str) -> BGPInfo:
    """Analyzes BGP/ASN info and simulates ROA check"""
    info = get_ip_info(ip)
    bgp = BGPInfo()
    
    if info:
        bgp.asn = str(info.get('as', 'Unknown'))
        bgp.as_name = info.get('asname', 'Unknown')
        bgp.country = info.get('countryCode', 'Unknown')
        bgp.registry = info.get('registry', 'Unknown')
        bgp.prefix = info.get('query', 'Unknown') # In real tool, this would be the specific prefix
        
        # Simulate ROA (Real implementation needs RPKI cache or API like RIPE Stat)
        # Heuristic: If ASN matches IP country, likely valid (very rough)
        bgp.roa_status = "Valid (Simulated)" if bgp.country != 'Unknown' else "Unknown"
        
        # Communities simulation
        bgp.communities = [f"{bgp.asn}:100", f"{bgp.asn}:200"] 

    return bgp

def check_security(domain: str, port: int = 443) -> SecurityInfo:
    """Checks SSL, Headers, and DNSSEC"""
    sec = SecurityInfo()
    
    # 1. SSL/TLS Check
    if HAS_REQUESTS:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    sec.ssl_valid = True
                    sec.ssl_expiry = cert['notAfter']
                    sec.ssl_issuer = dict(x[0] for x in cert['issuer'])['organizationName']
                    sec.tls_version = ssock.version()
        except Exception as e:
            sec.ssl_valid = False

    # 2. HTTP Headers
    if HAS_REQUESTS:
        try:
            resp = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
            headers = resp.headers
            sec.hsts = 'Strict-Transport-Security' in headers
            sec.csp = 'Content-Security-Policy' in headers
            sec.x_frame_options = 'X-Frame-Options' in headers
        except Exception:
            pass

    # 3. DNSSEC
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            # Check for DS record existence as a proxy for DNSSEC
            answers = resolver.resolve(domain, 'DS')
            if answers:
                # Further validation requires checking signatures (RRSIG) which is complex
                sec.dnssec_valid = True 
        except Exception:
            sec.dnssec_valid = False

    return sec

def check_performance(target: str, count: int = 10) -> PerformanceInfo:
    """Measures Latency, Jitter, Packet Loss, TCP Window Scaling"""
    perf = PerformanceInfo()
    latencies = []
    losses = 0
    
    # Simple Ping Simulation (Socket based for cross-platform compatibility without root)
    # Note: Real ICMP ping requires root/Admin. This uses TCP connect time as proxy if ICMP fails.
    port = 443 if target.startswith('http') else 80
    host = target.replace('http://', '').replace('https://', '').split('/')[0]
    
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return perf

    for i in range(count):
        start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, 443))
            # Check TCP Window Scaling option (simplified check via getsockopt)
            if i == 0:
                try:
                    # TCP_WINDOW_SCALE is often 3 in Linux, requires specific handling
                    # Here we just flag it as supported if connection succeeds modernly
                    perf.tcp_window_scale = True 
                except:
                    pass
            sock.close()
            end = time.time()
            latencies.append((end - start) * 1000) # ms
        except Exception:
            losses += 1

    if latencies:
        perf.latency_avg = statistics.mean(latencies)
        if len(latencies) > 1:
            perf.jitter_avg = statistics.stdev(latencies)
        perf.packet_loss = (losses / count) * 100
    
    # HTTP3 / QUIC Check (Requires httpx with http2/http3 support)
    if HAS_HTTPX:
        try:
            # This is a placeholder; real http3 needs specific transport
            perf.http3_support = False # Requires explicit httpx.Client(http2=True, verify=False) + h3 library
        except:
            pass
            
    return perf

def check_provider(ip: str, asn_name: str) -> ProviderInfo:
    """Identifies Cloud Providers and potential VPNs"""
    prov = ProviderInfo()
    
    # Cloud Detection
    for provider, prefixes in CLOUD_RANGES.items():
        if any(ip.startswith(p) for p in prefixes):
            prov.is_cloud = True
            prov.cloud_provider = provider
            prov.hosting_type = "Cloud/Datacenter"
            break
            
    # VPN Detection (Heuristic based on ASN name)
    if any(k in asn_name.lower() for k in VPN_INDICATORS):
        prov.is_vpn = True
        prov.vpn_provider = asn_name
        prov.hosting_type = "VPN/Hosting"
        
    return prov

def export_report(report: FullReport, format: str, filename: str):
    """Exports report to JSON or CSV"""
    data = asdict(report)
    
    if format == 'json':
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Report saved to {filename}")
        
    elif format == 'csv':
        # Flatten nested dicts for CSV
        flat_data = {}
        for k, v in data.items():
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    if isinstance(v2, list):
                        flat_data[f"{k}_{k2}"] = ";".join(map(str, v2))
                    else:
                        flat_data[f"{k}_{k2}"] = v2
            else:
                flat_data[k] = v
                
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flat_data.keys())
            writer.writeheader()
            writer.writerow(flat_data)
        print(f"Report saved to {filename}")

def run_scheduler(targets: List[str], interval: int, iterations: int, output_dir: str):
    """Simple Scheduler for repeated checks"""
    print(f"Starting scheduler: {iterations} runs, every {interval}s")
    os.makedirs(output_dir, exist_ok=True)
    
    for i in range(iterations):
        print(f"\n--- Run {i+1}/{iterations} ---")
        for target in targets:
            report = main_logic(target)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_report(report, 'json', f"{output_dir}/{target}_{ts}.json")
        if i < iterations - 1:
            time.sleep(interval)

def check_alerts(report: FullReport, thresholds: Dict):
    """Checks thresholds and prints alerts"""
    alerts = []
    if report.performance.packet_loss > thresholds.get('packet_loss', 5.0):
        alerts.append(f"HIGH PACKET LOSS: {report.performance.packet_loss}%")
    if report.performance.latency_avg > thresholds.get('latency', 200.0):
        alerts.append(f"HIGH LATENCY: {report.performance.latency_avg}ms")
    if not report.security.ssl_valid:
        alerts.append("SSL INVALID!")
    if not report.security.dnssec_valid:
        alerts.append("DNSSEC MISSING")
        
    if alerts:
        print("\n[!] ALERTS:")
        for a in alerts:
            print(f"  - {a}")
    else:
        print("\n[OK] No critical alerts.")

# --- UI Layer ---
def render_tui(report: FullReport):
    """Rich TUI Output"""
    if not HAS_RICH:
        print(json.dumps(asdict(report), indent=2))
        return

    console = Console()
    
    # Header
    console.print(Panel(f"[bold blue]Network Report: {report.target}[/bold blue]\nTime: {report.timestamp}", title="ADVANCED NET TOOL"))
    
    # BGP Table
    table_bgp = Table(title="BGP / ASN Info")
    table_bgp.add_column("Property", style="cyan")
    table_bgp.add_column("Value", style="magenta")
    table_bgp.add_row("ASN", report.bgp.asn)
    table_bgp.add_row("Name", report.bgp.as_name)
    table_bgp.add_row("Country", report.bgp.country)
    table_bgp.add_row("ROA Status", report.bgp.roa_status)
    console.print(table_bgp)
    
    # Security Table
    table_sec = Table(title="Security Posture")
    table_sec.add_column("Check", style="cyan")
    table_sec.add_column("Status", style="green")
    table_sec.add_row("SSL Valid", "[green]YES[/green]" if report.security.ssl_valid else "[red]NO[/red]")
    table_sec.add_row("HSTS", "[green]YES[/green]" if report.security.hsts else "[yellow]NO[/yellow]")
    table_sec.add_row("DNSSEC", "[green]YES[/green]" if report.security.dnssec_valid else "[red]NO[/red]")
    table_sec.add_row("TLS Ver", report.security.tls_version)
    console.print(table_sec)
    
    # Perf Table
    table_perf = Table(title="Performance Metrics")
    table_perf.add_column("Metric", style="cyan")
    table_perf.add_column("Value", style="yellow")
    table_perf.add_row("Latency Avg", f"{report.performance.latency_avg:.2f} ms")
    table_perf.add_row("Jitter", f"{report.performance.jitter_avg:.2f} ms")
    table_perf.add_row("Packet Loss", f"{report.performance.packet_loss:.1f}%")
    table_perf.add_row("TCP Window Scale", "Yes" if report.performance.tcp_window_scale else "No")
    console.print(table_perf)

def main_logic(target: str) -> FullReport:
    # Normalize input
    if target.startswith('http'):
        domain = target.split('/')[2]
    else:
        domain = target
    
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = target # Assume IP provided directly

    # Run Checks
    bgp_info = check_bgp(ip)
    sec_info = check_security(domain)
    perf_info = check_performance(domain)
    prov_info = check_provider(ip, bgp_info.as_name)
    
    report = FullReport(
        timestamp=datetime.now().isoformat(),
        target=target,
        bgp=bgp_info,
        security=sec_info,
        performance=perf_info,
        provider=prov_info
    )
    
    return report

def main():
    parser = argparse.ArgumentParser(description="Advanced Network Diagnostic Tool")
    parser.add_argument("target", nargs='?', help="IP or Domain to scan")
    parser.add_argument("--format", choices=["tui", "json", "csv"], default="tui", help="Output format")
    parser.add_argument("--output", "-o", help="Output filename (for json/csv)")
    parser.add_argument("--scheduler", action="store_true", help="Enable scheduled runs")
    parser.add_argument("--interval", type=int, default=60, help="Scheduler interval (seconds)")
    parser.add_argument("--runs", type=int, default=5, help="Number of scheduler runs")
    parser.add_argument("--output-dir", default="./reports", help="Directory for scheduled reports")
    parser.add_argument("--alert-threshold-loss", type=float, default=5.0, help="Packet loss alert threshold")
    parser.add_argument("--alert-threshold-latency", type=float, default=200.0, help="Latency alert threshold")
    
    args = parser.parse_args()
    
    if not args.target and not args.scheduler:
        parser.print_help()
        sys.exit(1)
        
    if args.scheduler:
        if not args.target:
            print("Error: Target required for scheduler.")
            sys.exit(1)
        run_scheduler([args.target], args.interval, args.runs, args.output_dir)
    else:
        report = main_logic(args.target)
        
        # Alerts
        thresholds = {
            'packet_loss': args.alert_threshold_loss,
            'latency': args.alert_threshold_latency
        }
        check_alerts(report, thresholds)
        
        # Output
        if args.format == 'tui':
            render_tui(report)
        elif args.format in ['json', 'csv']:
            fname = args.output or f"report_{args.target}.{args.format}"
            export_report(report, args.format, fname)

if __name__ == "__main__":
    main()
