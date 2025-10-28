import json
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text
from .language import get_msg

console = Console()


def export_results(data: dict, output_path: str):
    """Export audit results to JSON or HTML file."""
    try:
        if output_path.lower().endswith('.json'):
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, default=str)
            console.print(f"\n[bold green]{get_msg('export_success')}[/bold green] [cyan]{output_path}[/cyan] (JSON)")
        elif output_path.lower().endswith('.html'):
            html_content = generate_html_report(data)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            console.print(f"\n[bold green]{get_msg('export_success')}[/bold green] [cyan]{output_path}[/cyan] (HTML)")
        else:
            console.print(f"\n[bold red]{get_msg('export_fail_format')}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]{get_msg('export_fail_error')}[/bold red] {e}")


def generate_html_report(data: dict) -> str:
    """Generate a polished HTML report with SVG logo and summary cards."""
    import datetime, html, json

    title = "PySec Auditor Report"
    generated = datetime.datetime.now().isoformat()

    # SVG Shield Logo
    svg_logo = (
        "<svg xmlns='http://www.w3.org/2000/svg' width='48' height='48' viewBox='0 0 24 24'>"
        "<path fill='#0ea5a4' d='M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3z'/>"
        "<path fill='#022c22' d='M12 7a5 5 0 100 10 5 5 0 000-10z'/>"
        "</svg>"
    )

    def dict_to_table(d):
        rows = []
        for k, v in d.items():
            rows.append(
                f"<tr><th>{html.escape(str(k))}</th><td><pre>{html.escape(json.dumps(v, indent=2, default=str))}</pre></td></tr>"
            )
        return "<table class='kv'>" + "".join(rows) + "</table>"

    # --- Header ---
    body = []
    body.append(
        f"<div class='header'><div class='logo'>{svg_logo}</div>"
        f"<div class='title'><h1>{html.escape(title)}</h1>"
        f"<p class='subtitle'>Developed by Sardidev — Open Source (MIT)</p></div></div>"
    )

    # --- Summary cards ---
    body.append("<div class='cards'>")
    target = html.escape(str(data.get("Target", "N/A")))
    audit_time = html.escape(str(data.get("Audit_Time", "N/A")))
    findings = 0

    headers = data.get("Security_Headers", {})
    if isinstance(headers, dict):
        for v in headers.values():
            if isinstance(v, dict) and (
                "CRITICAL" in str(v.get("status", "")) or v.get("status") == "INSECURE"
            ):
                findings += 1

    leakage = data.get("Leakage", {})
    if isinstance(leakage, dict) and leakage.get("status", "").startswith("WARNING"):
        findings += len(leakage.get("leaked_headers", {}))

    traversal = data.get("Path_Traversal_Check", {})
    if isinstance(traversal, dict) and traversal.get("status", "") != "OK":
        findings += 1

    body.append(f"<div class='card'><h3>Target</h3><p>{target}</p></div>")
    body.append(f"<div class='card'><h3>Audit Time</h3><p>{audit_time}</p></div>")
    body.append(f"<div class='card findings'><h3>Findings</h3><p>{findings}</p></div>")
    body.append("</div>")

    # --- Detailed sections ---
    for section, content in data.items():
        if section in ["Target", "Audit_Time"]:
            continue
        body.append(f"<hr/><h2>{html.escape(section)}</h2>")
        if isinstance(content, dict):
            body.append(dict_to_table(content))
        else:
            body.append(f"<pre>{html.escape(json.dumps(content, indent=2, default=str))}</pre>")

    # --- Final HTML ---
    html_page = f"""
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>{html.escape(title)}</title>
<style>
:root {{--muted:#6b7280; --accent:#0ea5a4; --text:#e6eef0;}}
body {{
  font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
  background: linear-gradient(180deg,#071426 0%, #071022 100%);
  color: var(--text);
  margin: 0;
  padding: 24px;
}}
.header {{display:flex;align-items:center;gap:16px;}}
.header .logo {{width:56px;height:56px;padding:8px;border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  background:linear-gradient(90deg,#065f46,#0ea5a4);}}
.header h1 {{margin:0;font-size:20px;}}
.subtitle {{margin:2px 0 0 0;color:var(--muted);}}
.cards {{display:flex;gap:12px;margin-top:18px;margin-bottom:18px;}}
.card {{background:rgba(255,255,255,0.03);padding:12px;border-radius:10px;
  box-shadow:0 6px 18px rgba(2,6,23,0.6);flex:1;}}
.card h3 {{margin:0;font-size:14px;color:var(--accent);}}
.card p {{margin:8px 0 0 0;color:var(--text);}}
.card.findings {{background:linear-gradient(90deg,#7c2d12,#b91c1c);color:white;}}
.kv {{width:100%;border-collapse:collapse;margin-top:6px;}}
.kv th {{text-align:left;width:28%;padding:10px;background:rgba(255,255,255,0.04);
  border-radius:6px;color:var(--muted);}}
.kv td {{padding:10px;background:rgba(255,255,255,0.02);
  border-bottom:1px solid rgba(255,255,255,0.02);}}
pre {{background:rgba(255,255,255,0.02);padding:12px;border-radius:8px;overflow:auto;color:var(--text);}}
hr {{border:none;border-top:1px solid rgba(255,255,255,0.04);margin:20px 0;}}
.footer {{margin-top:28px;color:var(--muted);font-size:0.9rem;}}
.badge {{display:inline-block;background:var(--accent);padding:6px 10px;border-radius:999px;color:#012;font-weight:700;}}
</style>
</head>
<body>
{''.join(body)}
<div class='footer'><span class='badge'>PySec Auditor</span> • Developed by Sardidev — Open Source (MIT)</div>
</body>
</html>
"""
    return html_page


def check_specific_security_headers_rich_output(data: dict) -> Tree:
    """Display rich tree output for header results."""
    header_tree = Tree(f"[bold magenta]{get_msg('audit_headers_title')}[/bold magenta]", guide_style="magenta")
    found_critical_issue = False

    for header, detail in data.items():
        value = detail.get("value", "MISSING")
        status = detail.get("status", "N/A")
        if "CRITICAL" in status or status == "INSECURE":
            style = "bold red"
            icon = "❌"
            found_critical_issue = True
        else:
            style = "bold green"
            icon = "✅"
        header_tree.add(Text(f"{icon} {header}: ", style=style) + Text(str(value), style="white"))

    if found_critical_issue:
        console.print(
            Panel(f"{get_msg('warn_critical_header')}",
                  title="[bold red]Peringatan Header Kritis[/bold red]",
                  border_style="red")
        )

    return header_tree


def analyze_cookies_rich_output(data: dict) -> Tree:
    """Display rich tree output for cookie analysis."""
    cookie_tree = Tree(f"[bold magenta]{get_msg('audit_cookies_title')}[/bold magenta]", guide_style="cyan")
    if data.get("status"):
        cookie_tree.add(Text(f"❌ {data['status']}", style="dim"))
        return cookie_tree

    for name, info in data.items():
        node = cookie_tree.add(f"{name} -> secure: {info.get('is_secure', False)}")
        for k, v in info.get("attributes", {}).items():
            node.add(f"{k}: {v}")

    return cookie_tree
