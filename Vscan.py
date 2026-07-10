#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
VScan Pro - Full Nmap Detail Scanner
Version: 9.2 - Optimized & Fixed
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
    info = {'hostname': target, 'org': 'N/A', 'country': 'N/A'}
    try:
        info['hostname'] = socket.gethostbyaddr(target)[0]
    except:
        pass
    
    try:
        # استخدام timeout أقصر وتجنب التعليق
        result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=3)
        whois_data = result.stdout
        org_match = re.search(r'(OrgName|organization|descr):\s*(.+)', whois_data, re.IGNORECASE)
        if org_match:
            info['org'] = org_match.group(2).strip()
        country_match = re.search(r'(Country):\s*(.+)', whois_data, re.IGNORECASE)
        if country_match:
            info['country'] = country_match.group(2).strip()
    except:
        pass
    
    return info

def fast_port_discovery(target):
    """اكتشاف سريع للبورتات المفتوحة - محسن للسرعة والدقة"""
    print(f"\n{Fore.CYAN}[*] Phase 1: Fast port discovery on {Fore.WHITE}{target}{Fore.CYAN} ...")
    
    try:
        nm = nmap.PortScanner()
        # تحسين المعاملات:
        # -Pn: لتجاوز فحص التواجد (ping) إذا كان محظوراً
        # -n: لتعطيل DNS resolution لتسريع العملية
        # --min-rate 5000: لضمان سرعة إرسال الحزم
        # -p-: فحص كل المنافذ 1-65535
        # --open: فقط المنافذ المفتوحة فعلياً لتقليل الضجيج في المرحلة الثانية
        args = '-Pn -n -sS -T4 --min-rate 5000 --max-retries 1 -p- --open'
        
        nm.scan(target, arguments=args)
        
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        
        return sorted(list(set(open_ports)))
    except Exception as e:
        print(f"{Fore.RED}[!] Fast scan error: {e}")
        return []

def detailed_service_scan(target, ports):
    """فحص تفصيلي للخدمات مع تحسين استخراج الإصدارات"""
    if not ports:
        return []
    
    print(f"\n{Fore.CYAN}[*] Phase 2: Deep service detection on {len(ports)} ports ...")
    
    port_str = ','.join(str(p) for p in ports)
    
    try:
        nm = nmap.PortScanner()
        # تحسين معاملات الفحص التفصيلي:
        # -sV: فحص الإصدار
        # -sC: تشغيل سكريبتات Nmap الافتراضية
        # --version-intensity 5: توازن بين السرعة والدقة (بدل 9 التي تأخذ وقتاً طويلاً)
        # --script=vulners: إضافة سكريبت vulners للحصول على CVEs مباشرة من Nmap
        arguments = (
            f'-Pn -n -sV -sC --version-intensity 5 '
            f'--script=banner,http-title,vulners '
            f'-p {port_str} -T4'
        )
        
        nm.scan(target, arguments=arguments)
        
        results = []
        
        for host in nm.all_hosts():
            host_data = nm[host]
            
            os_info = {'name': 'Unknown', 'accuracy': '0'}
            if 'osmatch' in host_data and host_data['osmatch']:
                os_info = {
                    'name': host_data['osmatch'][0].get('name', 'Unknown'),
                    'accuracy': host_data['osmatch'][0].get('accuracy', '0')
                }
            
            for proto in host_data.all_protocols():
                for port in host_data[proto]:
                    info = host_data[proto][port]
                    
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
                        'mac': host_data.get('addresses', {}).get('mac', 'N/A')
                    }
                    results.append(port_data)
        
        return results
        
    except Exception as e:
        print(f"{Fore.RED}[!] Detailed scan error: {e}")
        return []

def check_vuln_enhanced(service, product, version, port, script_results=None):
    """فحص شامل للثغرات مع قاعدة بيانات محدثة وتدقيق CVEs"""
    vulns = []
    level = "SAFE"
    color = Fore.GREEN
    
    service_lower = service.lower()
    product_lower = product.lower()
    version_str = str(version).lower()
    
    # 1. استخراج الثغرات من سكريبت vulners الخاص بـ Nmap (الأكثر دقة)
    if script_results and 'vulners' in script_results:
        vuln_text = script_results['vulners']
        # البحث عن CVEs ودرجات الخطورة
        cve_matches = re.findall(r'(CVE-\d{4}-\d+)\s+(\d+\.\d)', vuln_text)
        if cve_matches:
            for cve, score in cve_matches[:5]: # نأخذ أول 5 فقط للترتيب
                vulns.append(f"{cve} (Score: {score})")
                score_val = float(score)
                if score_val >= 9.0:
                    level = "CRITICAL"
                    color = Fore.RED
                elif score_val >= 7.0 and level != "CRITICAL":
                    level = "HIGH"
                    color = Fore.RED
                elif score_val >= 4.0 and level not in ["CRITICAL", "HIGH"]:
                    level = "MEDIUM"
                    color = Fore.YELLOW

    if not vulns:
        # SSH
        if 'ssh' in service_lower:
            if any(v in version_str for v in ['2.3', '3.0', '4.0', '5.0', '6.0']):
                vulns.append(f"Legacy OpenSSH {version_str} - Multiple CVEs")
                level = "HIGH"; color = Fore.RED
        
        # HTTP / Apache / Nginx
        elif 'http' in service_lower or 'apache' in product_lower or 'nginx' in product_lower:
            if '2.4.49' in version_str or '2.4.50' in version_str:
                vulns.append("CVE-2021-41773 / CVE-2021-42013 Path Traversal")
                level = "CRITICAL"; color = Fore.RED
            elif '1.14.0' in version_str:
                vulns.append("Nginx 1.14.0 - Potential vulnerabilities")
                level = "MEDIUM"; color = Fore.YELLOW
        
        # SMB
        elif 'microsoft-ds' in service_lower or port == 445:
            vulns.append("SMB Service - Check for EternalBlue (MS17-010)")
            level = "HIGH"; color = Fore.RED
            
        # FTP
        elif 'ftp' in service_lower:
            if '2.3.4' in version_str and 'vsftpd' in product_lower:
                vulns.append("vsftpd 2.3.4 Backdoor (CVE-2011-2523)")
                level = "CRITICAL"; color = Fore.RED
            else:
                vulns.append("FTP - Plaintext protocol (Use SFTP)")
                level = "MEDIUM"; color = Fore.YELLOW

    if not vulns:
        if service_lower in ['unknown', '']:
            vulns.append("Unknown service - Manual check required")
            level = "INFO"; color = Fore.CYAN
        else:
            vulns.append("No common vulnerabilities detected")
    
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
    if host_info.get('org') and host_info['org'] != 'N/A':
        print(f"{Fore.CYAN}║  Organization: {Fore.WHITE}{host_info['org']}")
    if host_info.get('country') and host_info['country'] != 'N/A':
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
        
        if port.get('os') and port['os'].get('name') != 'Unknown':
            print(f"{Fore.CYAN}  ├─ Operating System")
            print(f"{Fore.CYAN}  │  OS Name:     {Fore.WHITE}{port['os']['name']}")
            print(f"{Fore.CYAN}  │  Accuracy:    {Fore.WHITE}{port['os']['accuracy']}%")
        
        if port.get('mac') and port['mac'] != 'N/A':
            print(f"{Fore.CYAN}  │  MAC:         {Fore.WHITE}{port['mac']}")
        
        if script_results:
            print(f"{Fore.CYAN}  ├─ Nmap Script Results")
            for script_name, script_output in script_results.items():
                if script_name == 'vulners': continue # نعرضه في قسم الثغرات
                output_str = str(script_output).replace('\n', ' ')
                if len(output_str) > 100:
                    output_str = output_str[:100] + "..."
                print(f"{Fore.CYAN}  │  {Fore.YELLOW}• {script_name}: {Fore.WHITE}{output_str}")
        
        print(f"{Fore.CYAN}  └─ Vulnerability Assessment")
        for vuln in vulns:
            if "No common" in vuln or "No known" in vuln:
                print(f"{Fore.CYAN}     {Fore.GREEN}✓ {vuln}")
            elif level == "INFO":
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
    
    try:
        target = input(f"\n{Fore.WHITE}Enter target (IP or domain): {Fore.RESET}").strip()
    except EOFError:
        return

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
    
    open_ports = fast_port_discovery(ip)
    
    if not open_ports:
        show_results(target, ip, [], host_info)
        sys.exit(0)
    
    print(f"{Fore.GREEN}[+] Found {len(open_ports)} open ports: {open_ports}")
    
    detailed_results = detailed_service_scan(ip, open_ports)
    
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
