#!/usr/bin/env python3
"""
Attack Surface Radar (ASR)
Harici Saldırı Yüzeyi ve Pasif OSINT Keşif Aracı.
Harici kütüphane gerektirmez (Sadece Python Standart Kütüphanesi ile çalışır).
"""

import sys
import os
import json
import time
import argparse
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Any

# SSL Doğrulama Bağlamı
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def log(msg: str, status: str = "info"):
    colors = {
        "info": "\033[94m[*]\033[0m",
        "ok": "\033[92m[+]\033[0m",
        "warn": "\033[93m[!]\033[0m",
        "error": "\033[91m[-]\033[0m",
        "bold": "\033[1m"
    }
    prefix = colors.get(status, "[*]")
    print(f"{prefix} {msg}")

def http_get_json(url: str, timeout: int = 15) -> Any:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None
    return None

def query_doh(name: str, record_type: str = "A") -> List[str]:
    """Google DNS-over-HTTPS (DoH) üzerinden DNS sorgusu yapar."""
    url = f"https://dns.google/resolve?name={name}&type={record_type}"
    data = http_get_json(url, timeout=10)
    results = []
    if data and "Answer" in data:
        for ans in data["Answer"]:
            if "data" in ans:
                val = ans["data"].strip('"')
                results.append(val)
    return results

def get_subdomains_crtsh(domain: str) -> Set[str]:
    """crt.sh üzerinden SSL/TLS sertifika kayıtlarından subdomain toplar."""
    log(f"crt.sh sertifika logları sorgulanıyor: {domain}...", "info")
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    data = http_get_json(url, timeout=25)
    subdomains = set()
    if data and isinstance(data, list):
        for entry in data:
            name_val = entry.get("name_value", "")
            for sub in name_val.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(domain) and "*" not in sub:
                    subdomains.add(sub)
    log(f"crt.sh: {len(subdomains)} adet benzersiz subdomain bulundu.", "ok")
    return subdomains

def check_email_security(domain: str) -> Dict[str, Any]:
    """SPF ve DMARC e-posta güvenlik kayıtlarını inceler."""
    log("E-posta güvenlik yapılandırması (SPF / DMARC) kontrol ediliyor...", "info")
    txt_records = query_doh(domain, "TXT")
    spf = [r for r in txt_records if r.startswith("v=spf1")]
    
    dmarc_records = query_doh(f"_dmarc.{domain}", "TXT")
    dmarc = [r for r in dmarc_records if r.startswith("v=DMARC1")]

    spf_status = "Eksik"
    if spf:
        spf_status = "Mevcut (" + ("Zayıf: ~all" if "~all" in spf[0] else "Sıkı: -all" if "-all" in spf[0] else spf[0]) + ")"

    dmarc_status = "Eksik"
    if dmarc:
        policy = "none"
        if "p=reject" in dmarc[0]:
            policy = "reject (Sıkı/Güvenli)"
        elif "p=quarantine" in dmarc[0]:
            policy = "quarantine (Karantina)"
        elif "p=none" in dmarc[0]:
            policy = "none (Sadece İzleme - Zayıf)"
        dmarc_status = f"Mevcut ({policy})"

    return {
        "spf_found": len(spf) > 0,
        "spf_record": spf[0] if spf else None,
        "spf_status": spf_status,
        "dmarc_found": len(dmarc) > 0,
        "dmarc_record": dmarc[0] if dmarc else None,
        "dmarc_status": dmarc_status
    }

def get_shodan_internetdb(ip: str) -> Dict[str, Any]:
    """Shodan InternetDB API'sinden pasif açık port ve CVE bilgilerini çeker."""
    url = f"https://internetdb.shodan.io/{ip}"
    data = http_get_json(url, timeout=8)
    if data:
        return {
            "ip": ip,
            "ports": data.get("ports", []),
            "cves": data.get("vulns", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", [])
        }
    return {"ip": ip, "ports": [], "cves": [], "hostnames": [], "tags": []}

def resolve_subdomain(sub: str) -> Dict[str, Any]:
    """Bir subdomain'in IP ve CNAME kayıtlarını çözer."""
    ips = query_doh(sub, "A")
    cnames = query_doh(sub, "CNAME")
    return {
        "subdomain": sub,
        "ips": ips,
        "cnames": cnames
    }

def run_radar(domain: str, max_workers: int = 10) -> Dict[str, Any]:
    start_time = time.time()
    domain = domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = domain.split("//")[1].split("/")[0]

    print("\n" + "="*60)
    print(f"   ATTACK SURFACE RADAR - {domain.upper()}")
    print("="*60 + "\n")

    # 1. Subdomain Toplama
    subdomains = get_subdomains_crtsh(domain)
    subdomains.add(domain) # Ana domain'i de ekle

    # 2. DNS Çözümleme (Paralel)
    log(f"{len(subdomains)} adres için DNS kayıtları çözümleniyor...", "info")
    resolved_assets = []
    unique_ips = set()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(resolve_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            res = future.result()
            if res["ips"]:
                resolved_assets.append(res)
                for ip in res["ips"]:
                    unique_ips.add(ip)

    log(f"Aktif IP'si bulunan {len(resolved_assets)} subdomain doğrulandı.", "ok")
    log(f"Toplam {len(unique_ips)} benzersiz IP tespit edildi.", "ok")

    # 3. Shodan InternetDB Pasif Port & Zafiyet Taraması
    log(f"{len(unique_ips)} IP için Shodan InternetDB pasif kayıtları taranıyor...", "info")
    ip_intel = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(get_shodan_internetdb, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            res = future.result()
            ip_intel[res["ip"]] = res

    # 4. E-posta Güvenliği (SPF & DMARC)
    mail_sec = check_email_security(domain)

    # 5. Risk Hesaplama
    risk_score = 0
    risk_factors = []

    if not mail_sec["dmarc_found"] or "none" in mail_sec["dmarc_status"]:
        risk_score += 25
        risk_factors.append("DMARC koruması eksik veya zayıf (Spoofing/Phishing riski)")

    if not mail_sec["spf_found"]:
        risk_score += 20
        risk_factors.append("SPF kaydı bulunamadı")

    dangerous_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 1433: "MSSQL", 3306: "MySQL"}
    total_open_ports = 0
    total_cves = 0

    for ip, data in ip_intel.items():
        total_open_ports += len(data["ports"])
        total_cves += len(data["cves"])
        for p in data["ports"]:
            if p in dangerous_ports:
                risk_score += 15
                risk_factors.append(f"Hassas port internete açık: IP {ip} -> Port {p} ({dangerous_ports[p]})")
        if data["cves"]:
            risk_score += len(data["cves"]) * 10
            risk_factors.append(f"IP {ip} üzerinde {len(data['cves'])} bilinen CVE zafiyeti mevcut")

    risk_score = min(risk_score, 100)

    elapsed = round(time.time() - start_time, 2)
    log(f"Tarama {elapsed} saniyede tamamlandı. Risk Skoru: {risk_score}/100", "ok")

    return {
        "domain": domain,
        "elapsed": elapsed,
        "assets": resolved_assets,
        "unique_ips": list(unique_ips),
        "ip_intel": ip_intel,
        "email_security": mail_sec,
        "risk_score": risk_score,
        "risk_factors": list(set(risk_factors)),
        "total_subdomains": len(subdomains),
        "total_active_subdomains": len(resolved_assets),
        "total_open_ports": total_open_ports,
        "total_cves": total_cves
    }

def generate_html_report(data: Dict[str, Any], output_path: str):
    """Grafik ve istatistik içeren interaktif tek sayfalık HTML raporu üretir."""
    nodes = []
    edges = []

    domain = data["domain"]
    nodes.append({"id": domain, "label": domain, "group": "domain", "size": 30})

    added_ips = set()
    added_ports = set()

    for asset in data["assets"]:
        sub = asset["subdomain"]
        if sub != domain:
            nodes.append({"id": sub, "label": sub, "group": "subdomain", "size": 20})
            edges.append({"from": domain, "to": sub})

        for ip in asset["ips"]:
            if ip not in added_ips:
                nodes.append({"id": ip, "label": ip, "group": "ip", "size": 15})
                added_ips.add(ip)
            edges.append({"from": sub, "to": ip})

            intel = data["ip_intel"].get(ip, {})
            for port in intel.get("ports", []):
                port_id = f"{ip}:{port}"
                if port_id not in added_ports:
                    nodes.append({"id": port_id, "label": f"Port {port}", "group": "port", "size": 10})
                    added_ports.add(port_id)
                edges.append({"from": ip, "to": port_id})

    nodes_json = json.dumps(nodes)
    edges_json = json.dumps(edges)

    risk_color = "#22c55e" if data["risk_score"] < 35 else "#eab308" if data["risk_score"] < 70 else "#ef4444"

    html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface Radar - {domain}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        :root {{
            --bg: #0f172a;
            --card: #1e293b;
            --text: #f8fafc;
            --muted: #94a3b8;
            --border: #334155;
            --accent: #38bdf8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; }}
        .card-title {{ color: var(--muted); font-size: 13px; text-transform: uppercase; margin-bottom: 6px; }}
        .card-val {{ font-size: 26px; font-weight: bold; color: var(--accent); }}
        .risk-badge {{ color: {risk_color}; font-size: 32px; font-weight: 800; }}
        #network {{ width: 100%; height: 550px; background: #020617; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }}
        th {{ background: #111827; color: var(--muted); }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; margin-right: 4px; }}
        .tag-port {{ background: #1e3a8a; color: #93c5fd; }}
        .tag-cve {{ background: #7f1d1d; color: #fca5a5; }}
        ul.risks {{ list-style-type: none; margin-top: 8px; }}
        ul.risks li {{ padding: 8px 12px; background: #450a0a; border-left: 4px solid #ef4444; border-radius: 4px; margin-bottom: 6px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🛡️ Attack Surface Radar</h1>
            <p style="color: var(--muted); font-size: 14px;">Hedef: <b>{domain}</b> | Tarama Süresi: {data["elapsed"]}s</p>
        </div>
        <div style="text-align: right;">
            <div class="card-title">Risk Skoru</div>
            <div class="risk-badge">{data["risk_score"]} / 100</div>
        </div>
    </div>

    <div class="stats">
        <div class="card">
            <div class="card-title">Aktif Subdomain</div>
            <div class="card-val">{data["total_active_subdomains"]}</div>
        </div>
        <div class="card">
            <div class="card-title">Benzersiz IP</div>
            <div class="card-val">{len(data["unique_ips"])}</div>
        </div>
        <div class="card">
            <div class="card-title">Açık Port Sayısı</div>
            <div class="card-val">{data["total_open_ports"]}</div>
        </div>
        <div class="card">
            <div class="card-title">Tespit Edilen CVE</div>
            <div class="card-val" style="color: {'#ef4444' if data['total_cves'] > 0 else '#22c55e'};">{data["total_cves"]}</div>
        </div>
    </div>

    <div class="card" style="margin-bottom: 24px;">
        <h3 style="margin-bottom: 8px;">📧 E-posta Güvenlik Durumu</h3>
        <p><b>SPF:</b> {data["email_security"]["spf_status"]}</p>
        <p style="margin-top: 4px;"><b>DMARC:</b> {data["email_security"]["dmarc_status"]}</p>
    </div>

    {f'''
    <div class="card" style="margin-bottom: 24px;">
        <h3 style="margin-bottom: 8px; color: #f87171;">⚠️ Tespit Edilen Risk Faktörleri</h3>
        <ul class="risks">
            {''.join([f"<li>{r}</li>" for r in data["risk_factors"]])}
        </ul>
    </div>
    ''' if data["risk_factors"] else ''}

    <div class="card" style="margin-bottom: 24px;">
        <h3 style="margin-bottom: 12px;">🌐 Dijital Varlık Grafiği (Domain ➔ Subdomain ➔ IP ➔ Port)</h3>
        <div id="network"></div>
    </div>

    <div class="card">
        <h3 style="margin-bottom: 12px;">📋 Varlık ve Servis Envanteri</h3>
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Adresleri</th>
                    <th>Açık Portlar (Shodan)</th>
                    <th>Zafiyetler (CVE)</th>
                </tr>
            </thead>
            <tbody>
                {''.join([f"""
                <tr>
                    <td><b>{a['subdomain']}</b></td>
                    <td>{', '.join(a['ips'])}</td>
                    <td>{' '.join([f'<span class="tag tag-port">{p}</span>' for p in data['ip_intel'].get(a['ips'][0], {}).get('ports', [])]) if a['ips'] else '-'}</td>
                    <td>{' '.join([f'<span class="tag tag-cve">{c}</span>' for c in data['ip_intel'].get(a['ips'][0], {}).get('cves', [])]) if a['ips'] and data['ip_intel'].get(a['ips'][0], {}).get('cves') else '<span style="color:#22c55e;">Temiz</span>'}</td>
                </tr>
                """ for a in data["assets"]])}
            </tbody>
        </table>
    </div>

    <script type="text/javascript">
        var nodes = new vis.DataSet({nodes_json});
        var edges = new vis.DataSet({edges_json});
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
            nodes: {{
                font: {{ color: '#f8fafc', size: 12 }}
            }},
            groups: {{
                domain: {{ color: {{ background: '#38bdf8', border: '#0284c7' }}, shape: 'box' }},
                subdomain: {{ color: {{ background: '#818cf8', border: '#4f46e5' }}, shape: 'ellipse' }},
                ip: {{ color: {{ background: '#f59e0b', border: '#d97706' }}, shape: 'dot' }},
                port: {{ color: {{ background: '#ef4444', border: '#dc2626' }}, shape: 'square' }}
            }},
            physics: {{
                stabilization: false,
                barnesHut: {{
                    gravitationalConstant: -3000,
                    springLength: 95
                }}
            }}
        }};
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description="Attack Surface Radar - Pasif OSINT ve Dış Saldırı Yüzeyi Taraması")
    parser.add_argument("domain", help="Taranacak hedef domain (Örn: example.com)")
    parser.add_argument("-o", "--output", help="HTML rapor dosya adı", default=None)
    parser.add_argument("-t", "--threads", help="Eşzamanlı iş parçacığı sayısı (varsayılan: 10)", type=int, default=10)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    domain = args.domain
    output_file = args.output or f"report_{domain.replace('.', '_')}.html"

    data = run_radar(domain, max_workers=args.threads)
    generate_html_report(data, output_file)

    log(f"İnteraktif HTML Raporu oluşturuldu: {os.path.abspath(output_file)}", "ok")
    print(f"\n[+] Raporu tarayıcında açmak için: start {output_file}\n")

if __name__ == "__main__":
    main()
