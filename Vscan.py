#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VScan Pro - Full Nmap Detail Scanner
Version: 9.1 - بدون كشف الجدران
"""

import nmap
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import os
import time
import subprocess
import json
import re

init(autoreset=True)

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear()
    print(f"""
{Fore.MAGENTA}   ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
{Fore.MAGENTA}   ██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
{Fore.MAGENTA}   ██║   ██║███████╗██║     ███████║██╔██╗ ██║
{Fore.MAGENTA}   ╚██╗ ██╔╝╚════██║██║     ██╔══██║██║╚██╗██║
{Fore.MAGENTA}    ╚████╔╝ ███████║╚██████╗██║  ██║██║ ╚████║
{Fore.MAGENTA}     ╚═══╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Fore.RESET}
{Fore.CYAN}          VScan Pro - Full Nmap Detail Scanner
{Fore.YELLOW}          Optimized for Speed & Accuracy
{Fore.RED}          For Authorized Testing Only
    """)

def get_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def get_host_info(target):
    """جلب معلومات الاستضافة والـ PTR"""
    info = {}
    try:
        info['hostname'] = socket.gethostbyaddr(target)[0]
    except:
        info['hostname'] = target
    
    try:
        # WHOIS lookup سريع
        result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=5)
        whois_data = result.stdout
        # استخراج المعلومات المهمة
        org_match = re.search(r'OrgName:\s*(.+)', whois_data)
        if org_match:
            info['org'] = org_match.group(1).strip()
        country_match = re.search(r'Country:\s*(.+)', whois_data)
        if country_match:
            info['country'] = country_match.group(1).strip()
    except:
        pass
    
    return info

def fast_port_discovery(target):
    """اكتشاف سريع للبورتات المفتوحة - بدون كشف جدران"""
    print(f"\n{Fore.CYAN}[*] Phase 1: Fast port discovery on {Fore.WHITE}{target}{Fore.CYAN} ...")
    
    try:
        nm = nmap.PortScanner()
        # حذف --open عشان نعرف كل البورتات
        # حذف أي سكريبتات تكتشف الجدران
        nm.scan(target, arguments='-sS -T5 --max-retries 1 --max-rtt-timeout 300ms -p-')
        
        open_ports = []
        if target in nm.all_hosts():
            for proto in nm[target].all_protocols():
                for port in nm[target][proto]:
                    state = nm[target][proto][port]['state']
                    # نقبل أي بورت مفتوح أو قد يكون مفتوح
                    if state in ['open', 'filtered', 'open|filtered']:
                        open_ports.append(port)
        
        return sorted(open_ports)
    except Exception as e:
        print(f"{Fore.RED}[!] Fast scan error: {e}")
        return []

def detailed_service_scan(target, ports):
    """فحص تفصيلي للخدمات - بدون سكريبتات كشف الجدران"""
    if not ports:
        return []
    
    print(f"\n{Fore.CYAN}[*] Phase 2: Deep service detection on {len(ports)} ports ...")
    
    port_str = ','.join(str(p) for p in ports)
    
    try:
        nm = nmap.PortScanner()
        
        # إعدادات بدون سكريبتات كشف الجدران
        # حذف: firewall-bypass, ipidseq, tcp-seq
        arguments = (
            f'-sV -sC -A -O --version-all --version-intensity 9 '
            f'--script=banner,http-title,ssl-cert,ssl-enum-ciphers,'
            f'ssh-hostkey,mysql-info,rdp-enum-encryption '
            f'-p {port_str} -T4 --min-rate 1000'
        )
        
        print(f"{Fore.YELLOW}[*] Running: nmap {arguments}")
        
        nm.scan(target, arguments=arguments)
        
        results = []
        
        if target in nm.all_hosts():
            host_data = nm[target]
            
            # معلومات OS
            os_info = {}
            if 'osmatch' in host_data and host_data['osmatch']:
                os_info = {
                    'name': host_data['osmatch'][0].get('name', 'Unknown'),
                    'accuracy': host_data['osmatch'][0].get('accuracy', '0'),
                    'osclass': host_data['osmatch'][0].get('osclass', [])
                }
            
            for proto in host_data.all_protocols():
                if proto == 'tcp':
                    for port in host_data[proto]:
                        info = host_data[proto][port]
                        
                        if info['state'] in ['open', 'filtered', 'open|filtered']:
                            port_data = {
                                'port': port,
                                'state': info.get('state', 'open'),
                                'service': info.get('name', 'unknown'),
                                'product': info.get('product', ''),
                                'version': info.get('version', ''),
                                'extrainfo': info.get('extrainfo', ''),
                                'cpe': info.get('cpe', ''),
                                'conf': info.get('conf', ''),
                                'method': info.get('method', ''),
                                'script': info.get('script', {}),
                                'os': os_info,
                                'hostname': host_data.get('hostnames', []),
                                'mac': host_data.get('addresses', {}).get('mac', 'N/A'),
                                'vendor': host_data.get('vendor', {})
                            }
                            results.append(port_data)
        
        return results
        
    except Exception as e:
        print(f"{Fore.RED}[!] Detailed scan error: {e}")
        return []

def check_vuln_enhanced(service, product, version, port, script_results=None):
    """فحص شامل للثغرات مع قاعدة بيانات موسعة"""
    vulns = []
    level = "SAFE"
    color = Fore.GREEN
    
    service_lower = service.lower()
    product_lower = product.lower()
    version_str = str(version)
    
    # فحص نتائج سكريبتات Nmap (بدون سكريبتات الجدران)
    if script_results:
        # Vulners script results
        if 'vulners' in script_results:
            vuln_data = script_results['vulners']
            if isinstance(vuln_data, str):
                # استخراج CVEs من نتيجة vulners
                cves = re.findall(r'CVE-\d{4}-\d+', vuln_data)
                for cve in cves:
                    vulns.append(f"Vulners: {cve} found")
                    level = "CRITICAL"
                    color = Fore.RED
        
        # SSL/TLS vulnerabilities
        if 'ssl-enum-ciphers' in script_results:
            ssl_output = str(script_results['ssl-enum-ciphers'])
            if 'TLSv1.0' in ssl_output or 'SSLv3' in ssl_output or 'SSLv2' in ssl_output:
                vulns.append("Weak SSL/TLS - Deprecated protocols enabled")
                if level != "CRITICAL":
                    level = "HIGH"
                    color = Fore.RED
        
        # Banner grab vulnerabilities
        if 'banner' in script_results:
            banner = str(script_results['banner']).lower()
            if 'windows xp' in banner or 'windows 2000' in banner:
                vulns.append("Legacy OS detected in banner")
                level = "CRITICAL"
                color = Fore.RED
    
    # SSH Vulnerabilities
    if 'ssh' in service_lower:
        ver_match = re.search(r'(\d+\.\d+)', version_str)
        if ver_match:
            ver = float(ver_match.group(1))
            if ver < 7.0:
                vulns.append(f"CVE-2016-6210 - User enumeration (OpenSSH {version_str})")
                level = "HIGH"
                color = Fore.RED
            elif ver < 8.0:
                vulns.append(f"CVE-2018-15473 - User enumeration (OpenSSH {version_str})")
                level = "HIGH"
                color = Fore.RED
            elif ver < 8.8:
                vulns.append(f"CVE-2021-41617 - Privilege escalation (OpenSSH {version_str})")
                level = "MEDIUM"
                color = Fore.YELLOW
    
    # Apache Vulnerabilities
    if 'apache' in product_lower or ('http' in service_lower and 'apache' in product_lower):
        if '2.4.49' in version_str or '2.4.50' in version_str:
            vulns.append("CVE-2021-42013 - Path traversal & RCE (CRITICAL)")
            level = "CRITICAL"
            color = Fore.RED
        elif '2.4.41' in version_str or '2.4.46' in version_str:
            vulns.append("CVE-2021-44790 - Buffer overflow")
            level = "HIGH"
            color = Fore.RED
        elif '2.2' in version_str:
            vulns.append("CVE-2017-9798 - Optionsbleed (HIGH)")
            level = "HIGH"
            color = Fore.RED
    
    # Nginx Vulnerabilities
    if 'nginx' in product_lower:
        ver_match = re.search(r'(\d+\.\d+\.\d+)', version_str)
        if ver_match:
            ver = ver_match.group(1)
            if ver.startswith('1.0') or ver.startswith('1.1') or ver.startswith('1.2'):
                vulns.append("CVE-2013-2028 - Stack overflow")
                level = "HIGH"
                color = Fore.RED
            elif ver.startswith('1.6') or ver.startswith('1.7'):
                vulns.append("CVE-2016-1247 - Privilege escalation")
                level = "HIGH"
                color = Fore.RED
    
    # MySQL/MariaDB
    if 'mysql' in service_lower:
        if '5.0' in version_str or '5.1' in version_str or '5.5' in version_str:
            vulns.append("CVE-2012-2122 - Authentication bypass")
            level = "HIGH"
            color = Fore.RED
        elif '5.6' in version_str:
            vulns.append("CVE-2016-6662 - Remote code execution")
            level = "CRITICAL"
            color = Fore.RED
    
    # FTP
    if 'ftp' in service_lower:
        if 'vsftpd' in product_lower and '2.3.4' in version_str:
            vulns.append("CVE-2011-2523 - Backdoor (CRITICAL)")
            level = "CRITICAL"
            color = Fore.RED
        if '21' in str(port):
            vulns.append("FTP - Unencrypted protocol, use SFTP/FTPS")
            if level == "SAFE":
                level = "MEDIUM"
                color = Fore.YELLOW
    
    # Telnet
    if 'telnet' in service_lower:
        vulns.append("Telnet - Unencrypted, credentials in plain text (CRITICAL)")
        level = "CRITICAL"
        color = Fore.RED
    
    # RDP
    if 'rdp' in service_lower or 'ms-wbt-server' in service_lower:
        if version_str and any(v in version_str for v in ['6.0', '5.', '7.0']):
            vulns.append("CVE-2019-0708 - BlueKeep RCE (CRITICAL)")
            level = "CRITICAL"
            color = Fore.RED
        vulns.append("RDP - Ensure NLA is enabled")
        if level == "SAFE":
            level = "MEDIUM"
            color = Fore.YELLOW
    
    # SMB
    if 'smb' in service_lower or 'microsoft-ds' in service_lower:
        vulns.append("CVE-2017-0144 - EternalBlue (check MS17-010)")
        level = "HIGH"
        color = Fore.RED
    
    # Redis
    if 'redis' in service_lower:
        vulns.append("Redis - Check for AUTH and bind configuration")
        if level == "SAFE":
            level = "MEDIUM"
            color = Fore.YELLOW
    
    # Docker
    if 'docker' in service_lower:
        vulns.append("Docker API exposed - Potential container escape")
        level = "CRITICAL"
        color = Fore.RED
    
    # Unknown service
    if service_lower in ['unknown', ''] and not vulns:
        vulns.append("Unknown service - Manual review recommended")
        level = "INFO"
        color = Fore.CYAN
    
    if not vulns:
        vulns.append("No known vulnerabilities detected")
    
    return vulns, level, color

def show_results(host, ip, open_ports, host_info):
    if not open_ports:
        print(f"\n{Fore.YELLOW}[!] No open ports found on {host}")
        return
    
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║  VScan Pro Results for {Fore.WHITE}{host}")
    print(f"{Fore.CYAN}║  IP: {Fore.WHITE}{ip}")
    if host_info.get('hostname') and host_info['hostname'] != host:
        print(f"{Fore.CYAN}║  Hostname: {Fore.WHITE}{host_info['hostname']}")
    if host_info.get('org'):
        print(f"{Fore.CYAN}║  Organization: {Fore.WHITE}{host_info['org']}")
    if host_info.get('country'):
        print(f"{Fore.CYAN}║  Country: {Fore.WHITE}{host_info['country']}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════╝{Fore.RESET}")
    
    print(f"\n{Fore.GREEN}[+] Open ports found: {len(open_ports)}\n")
    
    critical = high = medium = info_count = safe = 0
    
    for i, port in enumerate(open_ports, 1):
        script_results = port.get('script', {})
        vulns, level, color = check_vuln_enhanced(
            port['service'], 
            port['product'], 
            port['version'], 
            port['port'],
            script_results
        )
        
        if level == "CRITICAL": critical += 1
        elif level == "HIGH": high += 1
        elif level == "MEDIUM": medium += 1
        elif level == "INFO": info_count += 1
        else: safe += 1
        
        print(f"{Fore.WHITE}╔══════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ [{i}] Port {Fore.WHITE}{port['port']}{Fore.CYAN}/{port.get('state', 'open').upper()}")
        print(f"{Fore.WHITE}╚══════════════════════════════════════════════════════════════════╝")
        
        print(f"{Fore.CYAN}  ┌─ Service Information")
        print(f"{Fore.CYAN}  │  Service:     {Fore.WHITE}{port['service']}")
        print(f"{Fore.CYAN}  │  Product:     {Fore.WHITE}{port['product'] if port['product'] else 'N/A'}")
        print(f"{Fore.CYAN}  │  Version:     {Fore.WHITE}{port['version'] if port['version'] else 'N/A'}")
        print(f"{Fore.CYAN}  │  Extra Info:  {Fore.WHITE}{port['extrainfo'] if port['extrainfo'] else 'N/A'}")
        print(f"{Fore.CYAN}  │  CPE:         {Fore.WHITE}{port['cpe'] if port['cpe'] else 'N/A'}")
        print(f"{Fore.CYAN}  │  Confidence:  {Fore.WHITE}{port['conf'] if port.get('conf') else 'N/A'}")
        print(f"{Fore.CYAN}  │  Method:      {Fore.WHITE}{port['method'] if port.get('method') else 'N/A'}")
        
        if port.get('os') and port['os'].get('name'):
            print(f"{Fore.CYAN}  ├─ Operating System")
            print(f"{Fore.CYAN}  │  OS Name:     {Fore.WHITE}{port['os']['name']}")
            print(f"{Fore.CYAN}  │  Accuracy:    {Fore.WHITE}{port['os']['accuracy']}%")
        
        if port.get('mac') and port['mac'] != 'N/A':
            print(f"{Fore.CYAN}  │  MAC:         {Fore.WHITE}{port['mac']}")
        
        if script_results:
            print(f"{Fore.CYAN}  ├─ Nmap Script Results")
            for script_name, script_output in script_results.items():
                output_str = str(script_output)
                if len(output_str) > 200:
                    output_str = output_str[:200] + "..."
                print(f"{Fore.CYAN}  │  {Fore.YELLOW}• {script_name}:")
                for line in output_str.split('\n')[:5]:
                    print(f"{Fore.CYAN}  │    {Fore.WHITE}{line.strip()}")
        
        print(f"{Fore.CYAN}  └─ Vulnerability Assessment")
        for vuln in vulns:
            if "No known" in vuln:
                print(f"{Fore.CYAN}     {Fore.GREEN}✓ {vuln}")
            elif "INFO" in level:
                print(f"{Fore.CYAN}     {Fore.CYAN}ℹ {vuln}")
            else:
                print(f"{Fore.CYAN}     {color}⚠ {vuln}")
        
        print(f"{Fore.CYAN}     Risk Level: {color}{level}{Fore.RESET}")
        print()
    
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║  SCAN SUMMARY")
    print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════╣")
    print(f"{Fore.CYAN}║  Total Open Ports: {Fore.WHITE}{len(open_ports)}")
    if critical > 0:
        print(f"{Fore.CYAN}║  {Fore.RED}Critical: {critical}")
    if high > 0:
        print(f"{Fore.CYAN}║  {Fore.RED}High: {high}")
    if medium > 0:
        print(f"{Fore.CYAN}║  {Fore.YELLOW}Medium: {medium}")
    if info_count > 0:
        print(f"{Fore.CYAN}║  {Fore.CYAN}Info: {info_count}")
    if safe > 0:
        print(f"{Fore.CYAN}║  {Fore.GREEN}Safe: {safe}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════╝")

def main():
    banner()
    
    target = input(f"\n{Fore.WHITE}Enter target (IP or domain): {Fore.RESET}").strip()
    
    if not target:
        print(f"\n{Fore.RED}[!] No target provided")
        sys.exit(1)
    
    print(f"\n{Fore.CYAN}[*] Resolving {target} ...")
    ip = get_ip(target)
    
    if not ip:
        print(f"\n{Fore.RED}[!] Could not resolve {target}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}[+] Resolved to: {ip}")
    
    print(f"{Fore.CYAN}[*] Gathering host information...")
    host_info = get_host_info(ip)
    
    start_time = time.time()
    
    # المرحلة 1: اكتشاف سريع
    open_ports = fast_port_discovery(target)
    
    if not open_ports:
        print(f"{Fore.YELLOW}[!] No open ports found")
        show_results(target, ip, [], host_info)
        sys.exit(0)
    
    print(f"{Fore.GREEN}[+] Found {len(open_ports)} open ports: {open_ports}")
    
    # المرحلة 2: فحص تفصيلي
    detailed_results = detailed_service_scan(target, open_ports)
    
    elapsed = time.time() - start_time
    
    show_results(target, ip, detailed_results, host_info)
    print(f"\n{Fore.CYAN}[+] Scan completed in {elapsed:.2f} seconds")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}")
        sys.exit(1)