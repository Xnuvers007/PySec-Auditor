import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.live import Live
import sys
import ssl
import socket
from datetime import datetime
import urllib.parse
import argparse
from pyfiglet import Figlet
import time
import os
import json 
import re 
from typing import Dict, Any, List

# Inisialisasi Console Rich
console = Console()

# --- FUNGSI UTILITY & AESTHETICS ---

def clear_screen():
    """Membersihkan layar konsol."""
    os.system('cls' if os.name == 'nt' else 'clear')

def start_spinner(text="Sedang melakukan audit..."):
    """Menjalankan spinner animasi dengan Rich."""
    spinner = Live(
        f"[bold cyan]:hourglass: {text}[/bold cyan]", 
        console=console, 
        screen=False, 
        refresh_per_second=10
    )
    spinner.start()
    return spinner

def display_ascii_art():
    """Menampilkan Teks ASCII 'PySec Auditor'."""
    f = Figlet(font='slant')
    ascii_text = f.renderText('PySec Auditor')
    console.print(Panel(
        Text(ascii_text, style="bold yellow"), 
        title="[bold cyan]--- HTTP Security Toolkit ---[/bold cyan]", 
        border_style="magenta"
    ))

def display_tool_info_panel():
    """Menampilkan panel informasi tentang tool dan fitur-fiturnya."""
    info = Table(title="Informasi Tool PySec Auditor", show_header=False, border_style="green")
    info.add_column("Fitur", style="bold cyan")
    info.add_column("Deskripsi")
    
    info.add_row("HTTP & SSL/TLS", "Memeriksa status koneksi dan sertifikat TLS.")
    info.add_row("Header Keamanan", "Audit HSTS, CSP, XFO, dan lain-lain.")
    info.add_row("Cookie Security", "Audit atribut Secure, HttpOnly, dan SameSite.")
    info.add_row("CORS Insecurity", "Mendeteksi miskonfigurasi Cross-Origin Resource Sharing.")
    info.add_row("Ekspor Data", "Simpan hasil audit ke file JSON atau HTML.")

    console.print(Panel(
        info, 
        title="[bold green]Fokus Audit (Defensif/Edukasi)[/bold green]",
        border_style="yellow"
    ))
    console.print("\n[bold dim]Penggunaan: python pysec_auditor.py -u [TARGET_URL] [-o [FILE]][/bold dim]")
    console.print("="*80, style="dim")

# --- FUNGSI EKSPOR ---

def export_results(data: Dict[str, Any], output_path: str):
    """Mengekspor hasil audit ke format JSON atau HTML."""
    try:
        if output_path.lower().endswith('.json'):
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
            console.print(f"\n[bold green]✅ Ekspor Sukses:[/bold green] Hasil disimpan ke [cyan]{output_path}[/cyan] (JSON)")
        
        elif output_path.lower().endswith('.html'):
            html_content = generate_html_report(data)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            console.print(f"\n[bold green]✅ Ekspor Sukses:[/bold green] Laporan disimpan ke [cyan]{output_path}[/cyan] (HTML)")
        
        else:
            console.print(f"\n[bold red]❌ Ekspor Gagal:[/bold red] Format file tidak didukung. Gunakan .json atau .html.")
    except Exception as e:
        console.print(f"\n[bold red]❌ Ekspor Gagal:[/bold red] Terjadi kesalahan saat menyimpan file: {e}")

def generate_html_report(data: Dict[str, Any]) -> str:
    """Membuat struktur HTML sederhana dari data audit."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PySec Auditor Report - {data.get('Target', 'N/A')}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; color: #333; }}
            .container {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }}
            h1 {{ color: #007bff; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
            h2 {{ border-bottom: 2px solid #ccc; padding-bottom: 5px; margin-top: 20px; color: #343a40; }}
            .issue {{ color: red; font-weight: bold; }}
            .ok {{ color: green; font-weight: bold; }}
            pre {{ background: #eee; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>PySec Auditor Security Report</h1>
            <p><strong>Target URL:</strong> {data.get('Target', 'N/A')}</p>
            <p><strong>Audit Time:</strong> {data.get('Audit_Time', 'N/A').split('T')[0]} | {data.get('Audit_Time', 'N/A').split('T')[1].split('.')[0]}</p>
            
            <h2>Status Koneksi</h2>
            <p>Status Code: <span class="{ 'issue' if data.get('Connection_Status', {}).get('Status_Code', 0) >= 400 else 'ok' }">{data.get('Connection_Status', {}).get('Status_Code', 'N/A')}</span></p>
            <p>Response Time: {data.get('Connection_Status', {}).get('Response_Time', 'N/A'):.3f}s</p>

            <h2>Analisis Header Keamanan Khusus</h2>
            <pre>{json.dumps(data.get('Security_Headers', {}), indent=2)}</pre>
            
            <h2>Cookie Security</h2>
            <pre>{json.dumps(data.get('Cookie_Audit', {}), indent=2)}</pre>
            
            <h2>CORS Audit</h2>
            <p>Status: {data.get('CORS_Audit', {}).get('result', 'N/A')}</p>
            <p>ACA Origin: {data.get('CORS_Audit', {}).get('aca_origin', 'N/A')}</p>

            <h2>Deteksi Eksposur File Sensitif</h2>
            <pre>{json.dumps(data.get('Exposure_Check', {}), indent=2)}</pre>

            <h2>Metode HTTP Diizinkan</h2>
            <p>Metode Berbahaya Diizinkan: <span class="{'issue' if data.get('Allowed_Methods', {}).get('dangerous_methods') else 'ok'}">{', '.join(data.get('Allowed_Methods', {}).get('dangerous_methods', [])) if data.get('Allowed_Methods', {}).get('dangerous_methods') else 'None'}</span></p>
            
            <h2>Informasi TLS/SSL</h2>
            <pre>{json.dumps(data.get('TLS_Info', {}), indent=2)}</pre>
            
        </div>
    </body>
    </html>
    """
    return html

# --- FUNGSI AUDIT INTI (MENGEMBALIKAN DICT) ---

def get_tls_info(hostname: str) -> Dict[str, Any]:
    """Mengambil informasi dasar sertifikat TLS."""
    if not hostname: return {"error": "Hostname tidak valid."}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject']).get('commonName', 'N/A')
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'N/A')
                valid_until = datetime.strptime(cert['notAfter'], r'%b %d %H:%M:%S %Y %Z')
                return {
                    "subject": subject, "issuer": issuer, 
                    "valid_until": valid_until.strftime("%Y-%m-%d"),
                    "days_remaining": (valid_until - datetime.now()).days,
                }
    except Exception as e: return {"error": f"TLS Error: {e}"}

def analyze_cookies(response) -> Dict[str, Any]:
    """
    Menganalisis atribut keamanan (Secure, HttpOnly, SameSite) dari Set-Cookie header.
    DIKOREKSI: Menggunakan response.raw.headers.getlist untuk menangani multiple Set-Cookie.
    """
    cookie_results = {}
    
    try:
        # Menggunakan response.raw.headers.getlist untuk HeaderDict yang mendukung multiple values
        cookies_raw = response.raw.headers.getlist('Set-Cookie')
    except AttributeError:
        # Fallback yang kurang akurat, tapi aman jika raw headers tidak tersedia/bermasalah
        single_cookie_str = response.headers.get('Set-Cookie')
        cookies_raw = [single_cookie_str] if single_cookie_str else []
    except Exception as e:
        return {"status": f"Gagal membaca Set-Cookie header: {e}"}

    if not any(cookies_raw): return {"status": "Tidak ada Set-Cookie header."}

    for cookie_str in cookies_raw:
        if not cookie_str: continue 
        
        # Pisahkan nama/nilai dari atribut
        parts = cookie_str.split(';', 1)
        cookie_name = parts[0].split('=', 1)[0].strip()
        attributes_part = parts[1].strip() if len(parts) > 1 else ""
        attributes_part_lower = attributes_part.lower()

        cookie_detail = {"is_secure": True, "attributes": {}}
        
        # 1. HttpOnly
        if 'httponly' in attributes_part_lower:
            cookie_detail['attributes']['HttpOnly'] = True
        else:
            cookie_detail['attributes']['HttpOnly'] = False
            cookie_detail['is_secure'] = False

        # 2. Secure
        if 'secure' in attributes_part_lower:
            cookie_detail['attributes']['Secure'] = True
        else:
            cookie_detail['attributes']['Secure'] = False
            cookie_detail['is_secure'] = False

        # 3. SameSite (Perbaikan Logika)
        samesite_match = re.search(r'SameSite=([A-Za-z]+)', attributes_part, re.IGNORECASE)
        if samesite_match:
            samesite_value = samesite_match.group(1).upper()
            cookie_detail['attributes']['SameSite'] = samesite_value
            # Warning untuk SameSite=None tanpa Secure (kritis)
            if samesite_value == 'NONE' and not cookie_detail['attributes']['Secure']:
                 cookie_detail['is_secure'] = False 
        else:
            cookie_detail['attributes']['SameSite'] = "HILANG"
            cookie_detail['is_secure'] = False 

        cookie_results[cookie_name] = cookie_detail
    return cookie_results

def check_allowed_methods(url: str) -> Dict[str, Any]:
    """Memeriksa metode HTTP yang diizinkan menggunakan permintaan OPTIONS."""
    results = {"allowed_methods": [], "dangerous_methods": []}
    try:
        response = requests.options(url, timeout=5)
        results["status_code"] = response.status_code
        allowed_methods = [m for m in response.headers.get('Allow', '').upper().replace(' ', '').split(',') if m]
        results["allowed_methods"] = sorted(list(set(allowed_methods)))
        
        for method in ['PUT', 'DELETE', 'TRACE', 'CONNECT']:
            if method in results["allowed_methods"]:
                results["dangerous_methods"].append(method)
    except requests.exceptions.RequestException:
        results["error"] = "Permintaan OPTIONS gagal."
    return results

def check_exposure(base_url: str) -> Dict[str, Any]:
    """Memeriksa keberadaan file dan direktori sensitif yang umum."""
    results = {"exposed_paths": [], "protected_paths": [], "not_found": []}
    sensitive_paths = [".git/config", ".env", "robots.txt", "sitemap.xml", "admin/"]
    
    for path in sensitive_paths:
        target_url = urllib.parse.urljoin(base_url, path)
        try:
            # Menggunakan GET untuk path direktori (admin/) dan HEAD untuk file
            method_func = requests.get if path.endswith('/') else requests.head
            method_name = method_func.__name__.upper()
            
            response = method_func(target_url, allow_redirects=False, timeout=5)
            
            if 200 <= response.status_code < 300:
                results["exposed_paths"].append({"path": path, "status": response.status_code, "method": method_name})
            elif response.status_code == 401 or response.status_code == 403:
                results["protected_paths"].append({"path": path, "status": response.status_code, "method": method_name})
            else:
                results["not_found"].append({"path": path, "status": response.status_code, "method": method_name})
        except requests.exceptions.RequestException:
            pass 

    return results

def check_caching_headers(response_headers) -> Dict[str, Any]:
    """Memeriksa header caching untuk potensi pengungkapan informasi sensitif."""
    results = {}
    results["Cache-Control"] = response_headers.get('Cache-Control', 'HILANG')
    results["Pragma"] = response_headers.get('Pragma', 'HILANG')
    results["Expires"] = response_headers.get('Expires', 'HILANG')
    
    if 'no-cache' not in results["Cache-Control"].lower() and 'no-store' not in results["Cache-Control"].lower():
        results["Warning"] = "Header Caching tidak mengandung 'no-cache' atau 'no-store'. Potensi pengungkapan data di cache perantara."
        
    return results

def check_specific_security_headers(response_headers) -> Dict[str, Any]:
    """Memeriksa header keamanan HTTP yang spesifik (X-XSS, X-CTO, HSTS, CSP, XFO)."""
    results = {}
    security_headers = {
        "X-XSS-Protection": "1; mode=block",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age", 
        "Content-Security-Policy": "script-src", 
        "X-Frame-Options": "DENY", 
    }
    
    for header, expected_part in security_headers.items():
        value = response_headers.get(header)
        
        if header in ["X-XSS-Protection", "X-Content-Type-Options"]:
            if value:
                is_valid = value.lower() == expected_part.lower()
                results[header] = {"value": value, "status": "OK" if is_valid else "INSECURE"}
            else:
                results[header] = {"value": "HILANG", "status": "CRITICAL MISSING"}
        
        elif header == "Strict-Transport-Security":
            if value and expected_part in value.lower():
                results[header] = {"value": value, "status": "OK"}
            else:
                results[header] = {"value": "HILANG/INSECURE", "status": "CRITICAL MISSING (HSTS)"}
        
        elif header == "Content-Security-Policy":
            if value and expected_part in value.lower():
                results[header] = {"value": value, "status": "OK (Ditemukan)"}
            else:
                results[header] = {"value": "HILANG", "status": "CRITICAL MISSING (CSP)"}

        elif header == "X-Frame-Options":
            if value and (value.upper() == 'DENY' or 'SAMEORIGIN' in value.upper()):
                results[header] = {"value": value, "status": "OK"}
            else:
                results[header] = {"value": "HILANG/INSECURE", "status": "CRITICAL MISSING (XFO)"}

    results["Content-Type"] = {"value": response_headers.get('Content-Type', 'HILANG'), "status": "OK" if response_headers.get('Content-Type') else "MISSING"}
    
    return results

def check_takeover_risk(response_headers: dict) -> Dict[str, Any]:
    """Menganalisis header Server untuk indikasi layanan cloud/hosting yang berisiko takeover."""
    server_value = response_headers.get('Server', '').lower()
    takeover_keywords = {
        "cloudflare": "Cloudflare", "aws": "Amazon/AWS S3", "github": "GitHub Pages",
        "netlify": "Netlify", "heroku": "Heroku", "azure": "Microsoft Azure",
    }
    
    found_risks = []
    if server_value:
        for keyword, vendor in takeover_keywords.items():
            if keyword in server_value:
                found_risks.append(f"Server teridentifikasi menggunakan {vendor}. Potensi risiko takeover jika DNS salah dikonfigurasi (misal: CNAME yang tidak terikat).")
    
    return {"server_header": server_value if server_value else "HILANG", "risks": found_risks}

def check_cors_insecurity(url: str, response_headers: dict) -> Dict[str, Any]:
    """Memeriksa miskonfigurasi CORS (wildcard atau refleksi origin)."""
    cors_audit = {"status": "Not Tested (GET Request)", "result": "OK"}
    
    aca_origin = response_headers.get('Access-Control-Allow-Origin')
    aca_credentials = response_headers.get('Access-Control-Allow-Credentials')
    
    cors_audit['aca_origin'] = aca_origin if aca_origin else 'HILANG'
    cors_audit['aca_credentials'] = aca_credentials if aca_credentials else 'HILANG'
    cors_audit['status'] = "Tested (GET Request)"

    if not aca_origin:
        cors_audit['result'] = "Access-Control-Allow-Origin HILANG (Default OK)"
        return cors_audit

    # 1. CORS Wildcard: "*"
    if aca_origin == '*':
        cors_audit['result'] = "[INSECURE] Wildcard (*) diizinkan. Ini adalah miskonfigurasi CORS SERIUS."
        return cors_audit

    # 2. Refleksi Origin Arbitrary
    test_origin = "http://evil.com"
    try:
        test_response = requests.get(url, headers={'Origin': test_origin}, timeout=5)
        test_aca_origin = test_response.headers.get('Access-Control-Allow-Origin')
        
        if test_aca_origin == test_origin:
             cors_audit['result'] = "[CRITICAL INSECURE] Origin berbahaya direfleksikan. Risiko CORS SANGAT TINGGI."
             return cors_audit
    except requests.exceptions.RequestException:
        pass 
        
    cors_audit['result'] = "Access-Control-Allow-Origin ditemukan, tetapi tidak ada risiko wildcard atau refleksi yang jelas."
    return cors_audit


# --- FUNGSI PENCETAK RICH (HANYA UNTUK TAMPILAN) ---

def analyze_cookies_rich_output(data):
    cookie_tree = Tree("[bold magenta]Audit Atribut Keamanan Cookie[/bold magenta]", guide_style="cyan")
    if data.get("status"): cookie_tree.add(Text(f"❌ {data['status']}", style="dim")); return cookie_tree
    for name, detail in data.items():
        status_icon = "✅" if detail['is_secure'] else "🚨"
        branch = cookie_tree.add(f"[bold white]{status_icon} {name}[/bold white]...")
        
        for attr, value in detail["attributes"].items():
            if attr == 'SameSite':
                style = "bold green" if value in ['LAX', 'STRICT'] else "bold yellow" if value == 'NONE' and detail['attributes']['Secure'] else "bold red"
                icon = "🔒" if value in ['LAX', 'STRICT'] else "⚠️"
            elif attr == 'Secure':
                style = "bold green" if value else "bold red"
                icon = "🔒" if value else "❌"
            else: # HttpOnly
                style = "bold green" if value else "bold red"
                icon = "✅" if value else "❌"
                
            branch.add(Text(f"{icon} {attr}: ", style=style) + Text(str(value), style="white" if value else "dim red"))
    return cookie_tree

def check_specific_security_headers_rich_output(data):
    header_tree = Tree("[bold magenta]Analisis Header Keamanan Kritis[/bold magenta]", guide_style="magenta")
    found_critical_issue = False
    
    for header, detail in data.items():
        value = detail['value']
        status = detail['status']
        
        if "CRITICAL MISSING" in status:
            style = "bold red"; icon = "❌"; found_critical_issue = True
            header_tree.add(Text(f"{icon} {header}: ", style=style) + Text("HILANG", style="dim red"))
        elif status == "INSECURE":
            style = "bold red"; icon = "❌"; found_critical_issue = True
            header_tree.add(Text(f"{icon} {header}: ", style=style) + Text(value, style="white") + Text(" (INSECURE)", style="dim red"))
        else:
            style = "bold green"; icon = "✅"
            header_tree.add(Text(f"{icon} {header}: ", style=style) + Text(value, style="white"))
            
    if found_critical_issue: console.print(Panel("Header Keamanan Kritis hilang atau salah dikonfigurasi. [bold red]Tinjau Rekomendasi![/bold red]", title="[bold red]Peringatan Header Kritis[/bold red]", border_style="red"))
    return header_tree

def check_cors_insecurity_rich_output(data):
    cors_tree = Tree("[bold yellow]Audit CORS (Cross-Origin Resource Sharing)[/bold yellow]", guide_style="yellow")
    result = data.get('result', 'N/A')
    
    if "[CRITICAL INSECURE]" in result or "[INSECURE]" in result:
        cors_tree.add(Text(f"🚨 {result}", style="bold red"))
        cors_tree.add(Text(f"Header ACAO: {data.get('aca_origin', 'N/A')}", style="dim"))
        cors_tree.add(Text(f"Header ACAC: {data.get('aca_credentials', 'N/A')}", style="dim"))
        console.print(Panel("CORS miskonfigurasi memungkinkan situs jahat mengakses sumber daya Anda.", title="[bold red]!!! RISIKO CORS SERIUS !!![/bold red]", border_style="red"))
    else:
        cors_tree.add(Text(f"✅ {result}", style="green"))
    
    return cors_tree

def check_allowed_methods_rich_output(url, data):
    # Langsung mencetak Panel dan Table
    method_panel = Panel(f"Kode Status OPTIONS: [bold blue]{data.get('status_code', 'N/A')}[/bold blue]", title="[bold white on blue]Metode HTTP yang Diizinkan[/bold white on blue]", border_style="blue")
    console.print(method_panel)

    method_table = Table(title="Daftar Metode", show_header=True, header_style="bold magenta")
    method_table.add_column("Metode", style="bold", width=15); method_table.add_column("Status", width=15); method_table.add_column("Rekomendasi Keamanan")
    
    for method in data.get("allowed_methods", []):
        if method in data["dangerous_methods"]:
            style = "bold red" if method in ['PUT', 'DELETE', 'TRACE'] else "bold yellow"
            reco = "SANGAT BERBAHAYA (Potensi Remote Code Execution/Exfiltrasi)." if method in ['PUT', 'DELETE'] else "Sebaiknya dinonaktifkan."
            method_table.add_row(Text(method, style=style), Text("Diizinkan ❌", style=style), Text(reco, style=style))
        elif method in ['GET', 'HEAD', 'POST', 'OPTIONS']:
            method_table.add_row(Text(method, style="bold green"), Text("Diizinkan ✅", style="bold green"), "Metode standar dan umumnya aman.")
        else:
            method_table.add_row(Text(method, style="bold cyan"), Text("Diizinkan", style="bold cyan"), "Metode lain, periksa dokumentasi.")
            
    console.print(method_table)

def check_exposure_rich_output(data, url):
    # Langsung mencetak Tree dan Panel
    exposure_tree = Tree("[bold red]Deteksi Eksposur File/Direktori Sensitif[/bold red]", guide_style="red")
    found_count = 0
    
    for item in data.get("exposed_paths", []):
        exposure_tree.add(Text(f"🚨 Ditemukan [red]{item['path']}[/red]: Status {item['status']} ({item['method']})", style="bold red")); found_count += 1
    for item in data.get("protected_paths", []):
        exposure_tree.add(Text(f"🔒 Terproteksi [yellow]{item['path']}[/yellow]: Status {item['status']} ({item['method']})", style="bold yellow"))
    for item in data.get("not_found", []):
        exposure_tree.add(Text(f"  Tidak Ditemukan [dim]{item['path']}[/dim]: Status {item['status']} ({item['method']})", style="dim green"))
        
    console.print("\n", exposure_tree)
    if found_count > 0: console.print(Panel(f"Ditemukan [bold red]{found_count}[/bold red] file/direktori yang terekspos. Ini adalah [bold red]RISIKO KEAMANAN SERIUS[/bold red]!", title="[bold red]!!! Peringatan Eksposur !!![/bold red]", border_style="red"))

def check_takeover_risk_rich_output(data):
    # Langsung mencetak Panel dan Text
    takeover_panel = Panel.fit("[bold yellow]Pemeriksaan Risiko Subdomain Takeover[/bold yellow]", border_style="yellow")
    console.print(takeover_panel)
    
    if data["risks"]:
        for risk in data["risks"]: console.print(f"[bold red]⚠️ PERINGATAN RISIKO TAKEOVER:[/bold red] {risk}")
        console.print(Text(f"[bold dim]Server Header:[/bold dim] {data['server_header']}", style="dim"))
        console.print(Panel("Risiko takeover terjadi jika entri DNS CNAME mengarah ke sumber daya yang tidak ada (karena salah konfigurasi).", border_style="red"))
    else:
        console.print(Text("✅ Tidak ada indikasi risiko Subdomain Takeover yang jelas dari header Server.", style="green"))

def check_caching_headers_rich_output(data):
    # Mengembalikan objek Tree
    cache_tree = Tree("[bold blue]Audit Header Caching[/bold blue]", guide_style="blue")
    
    for header, value in data.items():
        if header == 'Warning': continue
        
        style = "green"
        icon = "✅"
        
        if value == "HILANG": style = "red"; icon = "❌"
        
        cache_tree.add(Text(f"{icon} {header}: ", style="bold "+style) + Text(value, style=style))

    if data.get("Warning"): cache_tree.add(Text(f"⚠️ {data['Warning']}", style="yellow"))
    
    return cache_tree

def get_tls_info_rich_output(data):
    # Langsung mencetak Panel atau Table
    tls_table = Table(title="Informasi SSL/TLS", show_header=False)
    tls_table.add_column("Key", style="bold cyan", width=20); tls_table.add_column("Value", style="white")

    if "error" in data: console.print(Panel(data["error"], title="[bold red]TLS ERROR[/bold red]", border_style="red"))
    else:
        days = data["days_remaining"]
        days_style = "bold red" if days < 30 else "bold green"
        tls_table.add_row("Subjek (CN)", data["subject"]); tls_table.add_row("Penerbit (Issuer)", data["issuer"]); 
        tls_table.add_row("Berlaku Sampai", data["valid_until"]); tls_table.add_row("Sisa Hari", Text(f"{days} Hari", style=days_style))
        console.print(tls_table)

# --- FUNGSI UTAMA UNTUK MENJALANKAN AUDIT ---
def check_http_security(url: str, timeout: int, output_path: str = None):
    """Fungsi utama untuk menjalankan semua audit dan ekspor."""
    
    audit_data: Dict[str, Any] = {
        "Target": url,
        "Audit_Time": datetime.now().isoformat(),
        "Connection_Status": {},
        "Security_Headers": {},
        "Cookie_Audit": {},
        "CORS_Audit": {},
        "Caching_Headers": {},
        "Allowed_Methods": {},
        "Takeover_Risk": {},
        "Exposure_Check": {},
        "TLS_Info": {},
    }
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.netloc

    console.print(Panel(
        f"Target: [bold blue]{url}[/bold blue] | Host: [bold cyan]{hostname}[/bold cyan]",
        title="[bold yellow]PySec Auditor: Versi 8.2 (Fixed getlist)[/bold yellow]",
        border_style="cyan"
    ))
    
    spinner = start_spinner("Membuat permintaan koneksi...")
    try:
        session = requests.Session()
        # Menggunakan GET request agar response.raw terisi untuk audit cookie
        response = session.get(url, allow_redirects=True, timeout=timeout, stream=True) 
        spinner.stop()
        
        # 1. Status Koneksi
        audit_data["Connection_Status"] = {
            "Status_Code": response.status_code,
            "Response_Time": response.elapsed.total_seconds()
        }
        status_style = "bold green" if response.status_code < 400 else "bold red"
        console.print(Panel(
            f"Status Koneksi: [bold]HTTP {response.status_code}[/] | Waktu Respons: [dim]{response.elapsed.total_seconds():.3f}s[/dim]",
            title="[bold white on blue]Koneksi[/bold white on blue]",
            border_style=status_style
        ))
        console.print("="*80, style="dim")

        # 2. Analisis Cookie (SUDAH DIKOREKSI)
        audit_data["Cookie_Audit"] = analyze_cookies(response)
        console.print(analyze_cookies_rich_output(audit_data["Cookie_Audit"])) 
        console.print("="*80, style="dim")

        # 3. Pemeriksaan Header Keamanan Khusus
        audit_data["Security_Headers"] = check_specific_security_headers(response.headers)
        console.print(check_specific_security_headers_rich_output(audit_data["Security_Headers"])) 
        console.print("="*80, style="dim")
        
        # 4. Pemeriksaan CORS Insecurity
        audit_data["CORS_Audit"] = check_cors_insecurity(url, response.headers)
        console.print(check_cors_insecurity_rich_output(audit_data["CORS_Audit"])) 
        console.print("="*80, style="dim")

        # 5. Pemeriksaan Caching
        audit_data["Caching_Headers"] = check_caching_headers(response.headers)
        console.print(check_caching_headers_rich_output(audit_data["Caching_Headers"]))
        console.print("="*80, style="dim")

        # 6. Analisis Metode HTTP 
        audit_data["Allowed_Methods"] = check_allowed_methods(url)
        check_allowed_methods_rich_output(url, audit_data["Allowed_Methods"])
        console.print("="*80, style="dim")
        
        # 7. Deteksi Risiko Subdomain Takeover 
        audit_data["Takeover_Risk"] = check_takeover_risk(response.headers)
        check_takeover_risk_rich_output(audit_data["Takeover_Risk"])
        console.print("="*80, style="dim")
        
        # 8. Deteksi Eksposur File/Direktori 
        audit_data["Exposure_Check"] = check_exposure(url)
        check_exposure_rich_output(audit_data["Exposure_Check"], url)
        console.print("="*80, style="dim")
        
        # 9. Analisis TLS/SSL 
        if parsed_url.scheme == 'https':
            audit_data["TLS_Info"] = get_tls_info(hostname)
            get_tls_info_rich_output(audit_data["TLS_Info"])
        
        # 10. EKSPOR HASIL (JIKA DIMINTA)
        if output_path:
            export_results(audit_data, output_path)

    except requests.exceptions.RequestException as e:
        spinner.stop()
        console.print(Panel(f"ERROR: Tidak dapat terhubung ke {url}\n[dim]{e}[/dim]", title="[bold red]Kesalahan Koneksi[/bold red]", border_style="red"))
    except Exception as e:
        spinner.stop()
        console.print(f"[bold red]Kesalahan Tak Terduga:[/bold red] {e}")


# --- FUNGSI UTAMA COMMAND LINE INTERFACE ---
def main():
    clear_screen()
    display_ascii_art()
    display_tool_info_panel()
    
    parser = argparse.ArgumentParser(
        description="PySec Auditor: Alat Audit Keamanan HTTP & TLS Defensif.",
        epilog="Contoh: python pysec_auditor.py -u example.com -o report.json",
        add_help=False
    )
    
    parser.add_argument('-u', '--url', type=str, help='URL target atau nama domain yang akan diaudit (misal: google.com atau https://google.com)')
    parser.add_argument('-o', '--output', type=str, default=None, help='Jalur file untuk ekspor (misal: report.json atau laporan.html)')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Timeout koneksi dalam detik (default: 15)')
    parser.add_argument('-h', '--help', action='store_true', help='Tampilkan pesan bantuan ini dan keluar')
    
    args = parser.parse_args()
    
    if args.help:
        parser.print_help()
        sys.exit(0)
        
    if not args.url:
        console.print(Panel("[bold red]ERROR:[/bold red] Argumen -u/--url wajib. Gunakan -h untuk bantuan.", border_style="red"))
        sys.exit(1)
        
    check_http_security(args.url, args.timeout, args.output)


if __name__ == "__main__":
    main()
