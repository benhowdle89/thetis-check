#!/usr/bin/env python3
"""Turn a Thetis report (Markdown) into a branded, self-contained HTML page.

Usage: thetis_html.py <report.md> [out.html] [--kind "Production-readiness report"] [--pdf]

Standard library only. It understands the Markdown our reports use (headings, paragraphs,
lists, tables, quotes, code, links, bold, italics) and dresses the Thetis-specific parts:
ratings become coloured chips, finding ids become references, and "Overall: RED" becomes
a rating badge. The page follows the landing page (thetis.benhowdle.im): dark on screen,
light when printed or saved as PDF, Geist and Martian Mono, Aegean and Bronze.

The same file is used by the free check and by the paid engine, so every report looks alike.
"""
import datetime
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

SITE = "https://thetis.benhowdle.im"
STATUSES = {"R", "A", "G", "OK", "NV", "—", "-"}
STATUS_CLASS = {"R": "r", "A": "a", "G": "g", "OK": "g", "NV": "nv", "—": "na", "-": "na"}
OVERALL_CLASS = {"RED": "r", "AMBER": "a", "GREEN": "g"}

# --- inline -----------------------------------------------------------------------------------

_FINDING_ID = re.compile(r"\[(\d{2}-[0-9a-f]{12})\]")
_LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+|#[^)\s]*|mailto:[^)\s]+)\)")
_URL = re.compile(r"(?<![\"'=>])\b(https?://[^\s<]+[^\s<.,;:)\]])")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_ITALIC = re.compile(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])|(?<![\w_])_(?!\s)(.+?)(?<!\s)_(?![\w_])")
_HEADLINE = re.compile(r"^(RED FLAGS FOUND|WEAK SPOTS FOUND|NO RED FLAGS FOUND)")
_PATH = re.compile(r"(?<![\w/.\x00\x01-])(\.env[\w.-]*\w|[\w.-]+(?:/[\w.\[\]-]+)+\.\w+(?::\d+(?:-\d+)?)?)(?=[\s,;)]|\.(?:\s|$)|$)")
_LABEL = re.compile(r"^(Needs fixing|Weak spot|Not checked|Not verified)\b")


def _bold(m):
    text = m.group(1)
    overall = re.match(r"^Overall:\s*(RED|AMBER|GREEN)(?:\s*→\s*(RED|AMBER|GREEN))?$", text)
    if overall:
        before, after = overall.group(1), overall.group(2)
        badge = lambda r: f'<span class="badge {OVERALL_CLASS[r]}">{r}</span>'
        return "Overall " + badge(before) + (f' <span class="arrow">→</span> {badge(after)}' if after else "")
    head = _HEADLINE.match(text)
    if head:
        tone = "r" if text.startswith("RED") else "g" if text.startswith("NO ") else "a"
        return f'<strong class="headline {tone}">{text}</strong>'
    label = _LABEL.match(text)
    if label:
        tone = {"Needs fixing": "r", "Weak spot": "a"}.get(label.group(1), "nv")
        return f'<strong class="label {tone}">{text}</strong>'
    return f"<strong>{text}</strong>"


def inline(text):
    """Escape, then apply inline Markdown. Code spans are protected from everything else."""
    codes = []

    def keep(m):
        codes.append(f"<code>{m.group(1)}</code>")
        return f"\x00{len(codes) - 1}\x00"

    out = html.escape(text, quote=False)
    out = re.sub(r"`([^`]+)`", keep, out)
    links = []

    def link(m):
        links.append(f'<a href="{html.escape(m.group(2))}">{m.group(1)}</a>')
        return f"\x01{len(links) - 1}\x01"

    out = _LINK.sub(link, out)
    out = _URL.sub(lambda m: (links.append(f'<a href="{m.group(1)}">{m.group(1)}</a>') or f"\x01{len(links) - 1}\x01"), out)
    out = _FINDING_ID.sub(r'<span class="fid">\1</span>', out)
    out = _PATH.sub(r'<span class="path">\1</span>', out)
    out = _BOLD.sub(_bold, out)
    out = _ITALIC.sub(lambda m: f"<em>{m.group(1) or m.group(2)}</em>", out)
    out = re.sub("\x01(\\d+)\x01", lambda m: links[int(m.group(1))], out)
    return re.sub("\x00(\\d+)\x00", lambda m: codes[int(m.group(1))], out)


def cell(text):
    t = text.strip()
    if t in STATUSES:
        return f'<span class="chip {STATUS_CLASS[t]}">{"—" if t == "-" else t}</span>'
    # Tables list finding ids without brackets (e.g. the proposal's Findings column).
    return re.sub(r"(?<![\w-])(\d{2}-[0-9a-f]{12})(?![\w-])", r'<span class="fid">\1</span>', inline(t))


# --- blocks -----------------------------------------------------------------------------------

_HR = re.compile(r"^\s*([-*_])(\s*\1){2,}\s*$")
_LIST = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")
_TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def _split_row(line):
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in line.split("|")]


def _table(rows):
    head, body = rows[0], rows[1:]
    statuses = sum(c in STATUSES for r in body for c in r)
    cells = sum(len(r) for r in body) or 1
    strip = statuses / cells > 0.6 and len(head) >= 7
    out = [f'<div class="table{" strip" if strip else ""}"><table>']
    if any(head):
        out.append("<thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in head) + "</tr></thead>")
    out.append("<tbody>")
    for r in body:
        out.append("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in r) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _list(items):
    """items: [(indent, ordered, text)]. One level of nesting, which is all our reports use."""
    out, i = [], 0
    ordered = items[0][1]
    out.append("<ol>" if ordered else "<ul>")
    base = items[0][0]
    while i < len(items):
        indent, _, text = items[i]
        children = []
        j = i + 1
        while j < len(items) and items[j][0] > base:
            children.append(items[j])
            j += 1
        out.append(f"<li>{inline(text)}{_list(children) if children else ''}</li>")
        i = j
    out.append("</ol>" if ordered else "</ul>")
    return "".join(out)


def blocks(md):
    md = re.sub(r"<!--.*?-->", "", md, flags=re.S)
    lines = md.replace("\r\n", "\n").split("\n")
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.lstrip().startswith("```"):
            j = i + 1
            while j < len(lines) and not lines[j].lstrip().startswith("```"):
                j += 1
            out.append("<pre><code>" + html.escape("\n".join(lines[i + 1:j])) + "</code></pre>")
            i = j + 1
            continue
        h = re.match(r"^(#{1,4})\s+(.*)$", line)
        if h:
            level = len(h.group(1))
            text = h.group(2).strip()
            rating = re.match(r"^(.*?):\s*(R|A|G|OK|NV|—)$", text)
            if rating and level >= 2:
                text_html = f'{inline(rating.group(1))} <span class="chip {STATUS_CLASS[rating.group(2)]}">{rating.group(2)}</span>'
            else:
                text_html = inline(text)
            out.append(f"<h{level}>{text_html}</h{level}>")
            i += 1
            continue
        if _HR.match(line):
            out.append("<hr>")
            i += 1
            continue
        if line.lstrip().startswith("|") and i + 1 < len(lines) and _TABLE_RULE.match(lines[i + 1]):
            rows = [_split_row(line)]
            j = i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                rows.append(_split_row(lines[j]))
                j += 1
            out.append(_table(rows))
            i = j
            continue
        if line.lstrip().startswith(">"):
            quoted = []
            while i < len(lines) and lines[i].lstrip().startswith(">"):
                quoted.append(re.sub(r"^\s*>\s?", "", lines[i]))
                i += 1
            out.append("<blockquote>" + blocks("\n".join(quoted)) + "</blockquote>")
            continue
        if _LIST.match(line):
            items = []
            while i < len(lines):
                m = _LIST.match(lines[i])
                if m:
                    items.append([len(m.group(1)), m.group(2)[0].isdigit(), m.group(3)])
                elif lines[i].strip() and items and (lines[i].startswith("  ") or not _starts_block(lines[i])):
                    items[-1][2] += " " + lines[i].strip()  # a wrapped list item
                else:
                    break
                i += 1
            out.append(_list([tuple(x) for x in items]))
            continue
        para = [line.strip()]
        i += 1
        while i < len(lines) and lines[i].strip() and not _starts_block(lines[i]):
            para.append(lines[i].strip())
            i += 1
        out.append(f"<p>{inline(' '.join(para))}</p>")
    return "\n".join(out)


def _starts_block(line):
    s = line.lstrip()
    return bool(re.match(r"^(#{1,4}\s|```|>|\|)", s) or _LIST.match(line) or _HR.match(line))


# --- page -------------------------------------------------------------------------------------

MARK = ('<svg class="mark" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="var(--mark-bg)"/>'
        '<path d="M8.5 9.5h15M16 9.5v14" stroke="var(--mark-fg)" stroke-width="3.4" stroke-linecap="round" fill="none"/>'
        '<circle cx="23.2" cy="23.2" r="3.4" fill="var(--bronze)"/></svg>')

CSS = """
:root{color-scheme:dark;
--bg:oklch(0.135 0.004 260);--card:oklch(0.17 0.005 260);--panel:oklch(0.11 0.004 260);--fg:oklch(0.985 0 0);
--muted:oklch(0.68 0.01 260);--border:oklch(1 0 0 / 9%);--aegean:oklch(0.74 0.085 215);--bronze:oklch(0.72 0.115 58);
--r:oklch(0.72 0.17 27);--r-bg:oklch(0.72 0.17 27 / 14%);--a:oklch(0.82 0.14 80);--a-bg:oklch(0.82 0.14 80 / 13%);
--g:oklch(0.78 0.13 150);--g-bg:oklch(0.78 0.13 150 / 12%);--nv:oklch(0.72 0.01 260);--nv-bg:oklch(1 0 0 / 7%);
--mark-bg:#f4f4f5;--mark-fg:#14171c;
--sans:"Geist","Geist Variable",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
--mono:"Martian Mono","Martian Mono Variable",ui-monospace,SFMono-Regular,Menlo,monospace}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--muted);font:16px/1.65 var(--sans);font-feature-settings:"ss01"}
.page{max-width:860px;margin:0 auto;padding:40px 24px 64px}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-bottom:20px;border-bottom:1px solid var(--border);margin-bottom:36px}
.brand{display:flex;align-items:center;gap:10px;color:var(--fg);text-decoration:none;font:600 15px/1 var(--mono);font-stretch:87.5%;letter-spacing:-0.01em}
.mark{width:26px;height:26px;flex:none}
.kind{font-size:13px;color:var(--muted)}
h1,h2,h3,h4{color:var(--fg);line-height:1.2;letter-spacing:-0.02em;text-wrap:balance}
h1{font-size:clamp(30px,5vw,44px);font-weight:500;letter-spacing:-0.035em;margin:0 0 10px}
h1+p{margin-top:0}
h2{font-size:24px;font-weight:500;margin:44px 0 14px;padding-top:28px;border-top:1px solid var(--border)}
h3{font-size:18px;font-weight:500;margin:30px 0 10px}
h4{font-size:16px;font-weight:600;margin:22px 0 8px}
p,li{max-width:72ch;text-wrap:pretty}
p{margin:0 0 14px}
strong{color:var(--fg);font-weight:600}
em{color:var(--fg);font-style:italic}
a{color:var(--aegean);text-underline-offset:3px;text-decoration-color:color-mix(in oklch,var(--aegean) 45%,transparent)}
ul,ol{margin:0 0 16px;padding-left:22px;display:grid;gap:7px}
li::marker{color:var(--muted)}
hr{border:0;border-top:1px solid var(--border);margin:36px 0}
blockquote{margin:0 0 16px;padding:14px 18px;border-left:2px solid var(--aegean);background:var(--card);border-radius:0 10px 10px 0}
blockquote p:last-child{margin:0}
code,pre,.fid,.chip,.badge{font-family:var(--mono);font-stretch:87.5%}
code{font-size:.86em;font-weight:300;color:var(--fg);background:var(--panel);border:1px solid var(--border);border-radius:5px;padding:1px 5px;overflow-wrap:anywhere}
pre{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px;overflow:auto;margin:0 0 16px}
pre code{background:none;border:0;padding:0;font-size:12.5px;line-height:1.6}
.path{font-family:var(--mono);font-stretch:87.5%;font-size:.86em;font-weight:300;color:var(--bronze);overflow-wrap:anywhere}
.fid{font-size:.78em;font-weight:300;color:var(--aegean);white-space:nowrap}
.table{overflow-x:auto;margin:0 0 18px;border:1px solid var(--border);border-radius:12px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th,td{text-align:left;vertical-align:top;padding:10px 14px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:500;font-size:12.5px}
td{color:var(--fg)}
tr:last-child td{border-bottom:0}
.strip table{table-layout:fixed}
.strip th,.strip td{padding:8px 6px;text-align:center;font-size:12px;line-height:1.3}
.strip th{font-weight:400}
.strip td:first-child:not(:has(.chip)){text-align:left;color:var(--muted);font-size:12px}
.chip{display:inline-block;min-width:2.4em;padding:3px 7px;border-radius:6px;font-size:12px;font-weight:500;text-align:center;line-height:1.3}
.chip.r{color:var(--r);background:var(--r-bg)}.chip.a{color:var(--a);background:var(--a-bg)}
.chip.g{color:var(--g);background:var(--g-bg)}.chip.nv,.chip.na{color:var(--nv);background:var(--nv-bg)}
h2 .chip,h3 .chip{vertical-align:.15em;margin-left:4px}
h2:has(> .chip){font-size:19px;margin:30px 0 8px;padding-top:22px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:13px;font-weight:500;letter-spacing:.02em}
.badge.r{color:var(--r);background:var(--r-bg)}.badge.a{color:var(--a);background:var(--a-bg)}.badge.g{color:var(--g);background:var(--g-bg)}
.arrow{color:var(--muted)}
.headline{font-family:var(--mono);font-stretch:87.5%;font-weight:500;letter-spacing:-0.01em}
.headline.r,.label.r{color:var(--r)}.headline.a,.label.a{color:var(--a)}.headline.g{color:var(--g)}.label.nv{color:var(--nv)}
.foot{margin-top:56px;padding-top:20px;border-top:1px solid var(--border);display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px 20px;font-size:13px}
.foot .tag{color:var(--fg)}.foot .tag b{color:var(--bronze);font-weight:600}
@media (max-width:560px){.page{padding:28px 16px 48px}.strip .table,.strip{font-size:11px}.strip th,.strip td{padding:6px 3px}.chip{min-width:0;padding:2px 4px}}
@page{size:A4;margin:16mm 14mm}
@media print{:root{color-scheme:light;
--bg:#fff;--card:#fff;--panel:oklch(0.97 0.003 260);--fg:oklch(0.145 0 0);--muted:oklch(0.45 0.01 260);--border:oklch(0.88 0.004 260);
--aegean:oklch(0.45 0.09 225);--bronze:oklch(0.6 0.12 55);--r:oklch(0.5 0.2 27);--r-bg:oklch(0.95 0.03 27);--a:oklch(0.52 0.13 70);
--a-bg:oklch(0.96 0.04 85);--g:oklch(0.45 0.12 150);--g-bg:oklch(0.95 0.04 150);--nv:oklch(0.45 0.01 260);--nv-bg:oklch(0.95 0.005 260);
--mark-bg:#14171c;--mark-fg:#f4f4f5}
body{font-size:11pt;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.page{max-width:none;padding:0}
h2{break-after:avoid}h3,h4{break-after:avoid}tr,li,blockquote,.chip{break-inside:avoid}
a{text-decoration:none}}
"""

FONTS = ('<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
         '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600'
         '&family=Martian+Mono:wdth,wght@87.5,300;87.5,400;87.5,500&display=swap">')


def page(md, kind="Report", title=None):
    """The whole HTML document for a Markdown report."""
    first = re.search(r"^#\s+(.+)$", md, re.M)
    title = title or (re.sub(r"[*_`]", "", first.group(1)).strip() if first else "Thetis report")
    body = blocks(md)
    today = datetime.date.today().strftime("%-d %B %Y") if os.name != "nt" else datetime.date.today().isoformat()
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · Thetis</title>
<meta name="generator" content="Thetis">
{FONTS}
<style>{CSS}</style></head>
<body><div class="page">
<header class="top"><a class="brand" href="{SITE}">{MARK}thetis</a><span class="kind">{html.escape(kind)}</span></header>
<main>
{body}
</main>
<footer class="foot"><span class="tag">Every app has a heel<b>.</b></span><span><a href="{SITE}">thetis.benhowdle.im</a> · {today}</span></footer>
</div></body></html>
"""


def find_chrome():
    for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "/Applications/Chromium.app/Contents/MacOS/Chromium",
              "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"):
        if os.path.exists(c):
            return c
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"):
        p = shutil.which(name)
        if p:
            return p
    return None


def to_pdf(html_path, pdf_path):
    """Print the HTML to PDF with a local Chrome or Chromium. Returns the PDF path, or None if no browser is found."""
    chrome = find_chrome()
    if not chrome:
        return None
    if os.path.exists(pdf_path):
        os.remove(pdf_path)
    # Headless Chrome sometimes keeps running after writing the PDF, so wait for the file, not for Chrome.
    with tempfile.TemporaryDirectory() as profile:
        proc = subprocess.Popen([chrome, "--headless=new", "--disable-gpu", f"--user-data-dir={profile}",
                                 "--no-pdf-header-footer", "--virtual-time-budget=4000", f"--print-to-pdf={pdf_path}",
                                 "file://" + os.path.abspath(html_path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        size, deadline = -1, time.time() + 90
        try:
            while time.time() < deadline:
                if os.path.exists(pdf_path):
                    now = os.path.getsize(pdf_path)
                    if now and now == size:
                        break
                    size = now
                elif proc.poll() is not None:
                    break
                time.sleep(0.5)
        finally:
            proc.kill()
            proc.wait()
    return pdf_path if os.path.exists(pdf_path) else None


def write(md_path, html_path=None, kind="Report", pdf=False):
    """Render md_path next to itself (or to html_path). Returns (html_path, pdf_path or None)."""
    with open(md_path, encoding="utf-8") as f:
        md = f.read()
    html_path = html_path or os.path.splitext(md_path)[0] + ".html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(page(md, kind=kind))
    pdf_path = to_pdf(html_path, os.path.splitext(html_path)[0] + ".pdf") if pdf else None
    return html_path, pdf_path


def main(argv):
    args, kind, pdf = [], "Report", False
    it = iter(argv)
    for a in it:
        if a == "--kind":
            kind = next(it, kind)
        elif a == "--pdf":
            pdf = True
        else:
            args.append(a)
    if not args:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    html_path, pdf_path = write(args[0], args[1] if len(args) > 1 else None, kind=kind, pdf=pdf)
    print(html_path)
    if pdf:
        print(pdf_path or "No Chrome or Chromium found, so no PDF. Open the HTML and print it instead.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
