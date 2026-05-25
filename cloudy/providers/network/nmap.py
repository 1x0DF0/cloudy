"""
Network scanning via nmap. Returns findings in cloudy format.
"""

import subprocess
import sys
from pathlib import Path


def is_nmap_installed() -> bool:
    """Check if nmap is available in PATH."""
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def scan_host(target: str, top_ports: int = 1000) -> dict:
    """
    Scan a single host for open ports using nmap.

    Returns: {
        'host': target,
        'open_ports': [22, 80, 443, ...],
        'services': {80: 'http', 443: 'https', ...},
        'error': None or error message
    }
    """
    if not is_nmap_installed():
        return {
            'host': target,
            'open_ports': [],
            'services': {},
            'error': 'nmap not installed (required for network scanning)'
        }

    try:
        # Use --top-ports for faster scanning, -sV for version detection
        cmd = [
            'nmap',
            '-sV',  # Service version detection
            '--top-ports', str(top_ports),
            '-oG', '-',  # Greppable output to stdout
            target
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        open_ports = []
        services = {}

        # Parse greppable output
        for line in result.stdout.split('\n'):
            if line.startswith('Host:'):
                # Parse: Host: 192.168.1.1	Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
                parts = line.split('Ports:')
                if len(parts) > 1:
                    port_str = parts[1].strip()
                    for port_info in port_str.split(', '):
                        if '/open/' in port_info:
                            port_num = int(port_info.split('/')[0])
                            service = port_info.split('/')[-2] if len(port_info.split('/')) > 4 else 'unknown'
                            open_ports.append(port_num)
                            services[port_num] = service

        return {
            'host': target,
            'open_ports': sorted(open_ports),
            'services': services,
            'error': None
        }

    except subprocess.TimeoutExpired:
        return {
            'host': target,
            'open_ports': [],
            'services': {},
            'error': 'scan timeout'
        }
    except Exception as e:
        return {
            'host': target,
            'open_ports': [],
            'services': {},
            'error': str(e)
        }


def scan_hosts(targets: list[str], top_ports: int = 1000) -> dict:
    """
    Scan multiple hosts.

    Returns: {
        'scans': [scan_host results],
        'timestamp': iso timestamp
    }
    """
    import json
    from datetime import datetime, timezone

    scans = []
    for target in targets:
        result = scan_host(target, top_ports)
        scans.append(result)

    return {
        'scans': scans,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


def findings_from_scans(scan_results: dict) -> list[dict]:
    """
    Convert network scan results to cloudy findings format.

    Returns list of findings with: severity, resource, finding
    """
    findings = []

    for scan in scan_results.get('scans', []):
        host = scan['host']

        if scan['error']:
            findings.append({
                'severity': 'LOW',
                'resource': host,
                'finding': f'scan error: {scan["error"]}'
            })
            continue

        ports = scan['open_ports']
        if not ports:
            continue

        # Flag common high-risk services
        dangerous_services = {
            22: 'SSH (remote access)',
            23: 'Telnet (plaintext)',
            21: 'FTP (plaintext)',
            3389: 'RDP (remote access)',
            3306: 'MySQL (database)',
            5432: 'PostgreSQL (database)',
            27017: 'MongoDB (database)',
            6379: 'Redis (cache)',
            8080: 'HTTP-Alt (web)',
            9200: 'Elasticsearch (search)',
        }

        for port in ports:
            service = scan['services'].get(port, 'unknown')

            # Determine severity based on service
            severity = 'LOW'
            if port in dangerous_services:
                severity = 'MED'
                if port in [23, 21]:  # Plaintext protocols
                    severity = 'HIGH'

            findings.append({
                'severity': severity,
                'resource': f'{host}:{port}',
                'finding': f'{service} open (port {port})'
            })

    return findings
