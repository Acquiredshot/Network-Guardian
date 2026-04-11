"""Probe: direct passwordrecovered.cgi + SOAP auth with Basic on every call."""
import urllib.request
import urllib.error
import http.cookiejar
import ssl
import re
import time
from base64 import b64encode

ip = "192.168.1.1"
password = "Family10130120"
serial = "6YN3477TD0A60"
creds = b64encode(f"admin:{password}".encode()).decode()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=ctx),
)

def do(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data.encode() if isinstance(data, str) else data)
    req.add_header("Authorization", f"Basic {creds}")
    req.add_header("User-Agent", "Mozilla/5.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace"), e.code

def soap(action, service, body_xml):
    """SOAP request over HTTPS."""
    envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
 s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>{body_xml}</s:Body>
</s:Envelope>"""
    req = urllib.request.Request(
        f"https://{ip}/soap/server_sa/",
        data=envelope.encode(),
    )
    req.add_header("Content-Type", "text/xml; charset=utf-8")
    req.add_header("SOAPAction", f"urn:NETGEAR-ROUTER:service:{service}#{action}")
    req.add_header("Authorization", f"Basic {creds}")
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace"), e.code

# ===== TEST 1: Direct passwordrecovered.cgi (Netgear CVE-2017-5521) =====
print("=" * 60)
print("TEST 1: Direct passwordrecovered.cgi access")
print("=" * 60)
body, code = do(f"https://{ip}/passwordrecovered.cgi")
print(f"  code={code}, len={len(body)}")
# Look for password in response
if "password" in body.lower() or "admin" in body.lower():
    # Strip scripts/styles and show text
    text = re.sub(r'<script[^>]*>.*?</script>', '', body, flags=re.DOTALL|re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL|re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    print(f"  Text: {text[:500]}")
inputs = re.findall(r'<input[^>]*name="([^"]*)"[^>]*>', body, re.IGNORECASE)
print(f"  Inputs: {inputs[:10]}")

# ===== TEST 2: Full SOAP sequence with Basic auth on every call =====
print("\n" + "=" * 60)
print("TEST 2: SOAP Authenticate -> ConfigurationStarted -> GetInfo")
print("=" * 60)

# 2a: Authenticate
print("\n  2a: Authenticate (ParentalControl:1)")
body, code = soap("Authenticate", "ParentalControl:1",
    "<m:Authenticate xmlns:m='urn:NETGEAR-ROUTER:service:ParentalControl:1'></m:Authenticate>")
resp_code = re.search(r'<ResponseCode>(.*?)</ResponseCode>', body)
print(f"  code={code}, ResponseCode={resp_code.group(1) if resp_code else 'N/A'}")

# 2b: Authenticate with DeviceConfig
print("\n  2b: Authenticate (DeviceConfig:1)")
body, code = soap("Authenticate", "DeviceConfig:1",
    "<m:Authenticate xmlns:m='urn:NETGEAR-ROUTER:service:DeviceConfig:1'></m:Authenticate>")
resp_code = re.search(r'<ResponseCode>(.*?)</ResponseCode>', body)
print(f"  code={code}, ResponseCode={resp_code.group(1) if resp_code else 'N/A'}")

# 2c: ConfigurationStarted
print("\n  2c: ConfigurationStarted (DeviceConfig:1)")
body, code = soap("ConfigurationStarted", "DeviceConfig:1",
    "<m:ConfigurationStarted xmlns:m='urn:NETGEAR-ROUTER:service:DeviceConfig:1'>"
    "<NewSessionID>1234567890</NewSessionID></m:ConfigurationStarted>")
resp_code = re.search(r'<ResponseCode>(.*?)</ResponseCode>', body)
print(f"  code={code}, ResponseCode={resp_code.group(1) if resp_code else 'N/A'}")
print(f"  Body: {body[:300]}")

# 2d: GetWLANSSIDBroadcast for 2.4GHz
print("\n  2d: GetSSIDBroadcast (WLANConfiguration:1)")
body, code = soap("GetWLANSSIDBroadcast", "WLANConfiguration:1",
    "<m:GetWLANSSIDBroadcast xmlns:m='urn:NETGEAR-ROUTER:service:WLANConfiguration:1'>"
    "</m:GetWLANSSIDBroadcast>")
print(f"  code={code}")
print(f"  Body: {body[:300]}")

# ===== TEST 3: Try DeviceInfo for login =====
print("\n" + "=" * 60)
print("TEST 3: SOAP DeviceInfo + Login")
print("=" * 60)

# 3a: GetInfo
print("\n  3a: GetInfo (DeviceInfo:1)")
body, code = soap("GetInfo", "DeviceInfo:1",
    "<m:GetInfo xmlns:m='urn:NETGEAR-ROUTER:service:DeviceInfo:1'></m:GetInfo>")
print(f"  code={code}")
if code == 200:
    # Parse out useful fields
    for tag in ["ModelName", "Description", "SerialNumber", "Firmwareversion", "FirewallVersion"]:
        m = re.search(f'<{tag}>(.*?)</{tag}>', body)
        if m:
            print(f"  {tag}: {m.group(1)}")

# 3b: Login via DeviceConfig
print("\n  3b: Login (DeviceConfig:1)")
body, code = soap("Login", "DeviceConfig:1",
    f"<m:Login xmlns:m='urn:NETGEAR-ROUTER:service:DeviceConfig:1'>"
    f"<Username>admin</Username>"
    f"<Password>{password}</Password>"
    f"<Url>WLG_wireless.htm</Url>"
    f"</m:Login>")
print(f"  code={code}")
print(f"  Body: {body[:500]}")

# ===== TEST 4: SetPassword via SOAP =====
print("\n" + "=" * 60)
print("TEST 4: SOAP SetPassword (change to same password)")
print("=" * 60)
body, code = soap("SetPassword", "DeviceConfig:1",
    f"<m:SetPassword xmlns:m='urn:NETGEAR-ROUTER:service:DeviceConfig:1'>"
    f"<NewPassword>{password}</NewPassword>"
    f"</m:SetPassword>")
resp_code = re.search(r'<ResponseCode>(.*?)</ResponseCode>', body)
print(f"  code={code}, ResponseCode={resp_code.group(1) if resp_code else 'N/A'}")
print(f"  Body: {body[:300]}")
"""Explore MNU_access_setRecovery_index.htm and try to set new security answers."""
import urllib.request
import urllib.error
import http.cookiejar
import ssl
import re
import time
from base64 import b64encode
from urllib.parse import urlencode

ip = "192.168.1.1"
password = "Family10130120"
creds = b64encode(f"admin:{password}".encode()).decode()

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=ctx),
)

def do(url, data=None):
    if data and isinstance(data, dict):
        data = urlencode(data).encode()
    req = urllib.request.Request(url, data=data)
    req.add_header("Authorization", f"Basic {creds}")
    req.add_header("User-Agent", "Mozilla/5.0")
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.read().decode("utf-8", errors="replace"), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", errors="replace"), e.code

# Step 1: GET / -> auto-submit
print("=== Step 1: GET / ===")
body, code = do(f"https://{ip}/")
print(f"  code={code}")

# Step 2: POST to unauth.cgi (auto-submit target)
auto = re.search(r'action="([^"]*)"', body)
if auto:
    print(f"\n=== Step 2: POST {auto.group(1)[:40]} ===")
    time.sleep(0.3)
    body, code = do(f"https://{ip}/{auto.group(1)}", data=b"")
    print(f"  code={code}")
    redir = re.search(r'location\.href\s*=\s*"([^"]*)"', body)
    if redir:
        print(f"  redirect -> {redir.group(1)}")

# Step 3: GET the recovery setup page
print(f"\n=== Step 3: GET MNU_access_setRecovery_index.htm ===")
time.sleep(0.3)
body, code = do(f"https://{ip}/MNU_access_setRecovery_index.htm")
print(f"  code={code}, len={len(body)}")

# Dump full HTML
print(f"\n--- FULL HTML ---")
print(body)

# Parse forms, inputs, selects
forms = re.findall(r'<form([^>]*)>', body, re.IGNORECASE)
inputs = re.findall(r'<input([^>]*)>', body, re.IGNORECASE)
selects = re.findall(r'<select([^>]*)>(.*?)</select>', body, re.DOTALL|re.IGNORECASE)
print(f"\n--- FORMS ---")
for f in forms:
    print(f"  {f}")
print(f"\n--- INPUTS ---")
for inp in inputs:
    print(f"  {inp}")
print(f"\n--- SELECTS ---")
for s_attrs, s_body in selects:
    opts = re.findall(r'<option[^>]*value="([^"]*)"[^>]*>(.*?)</option>', s_body, re.IGNORECASE)
    name = re.search(r'name="([^"]*)"', s_attrs)
    print(f"  Select: {name.group(1) if name else '?'}, Options: {opts[:5]}")

# Also try some other known Netgear management URLs
print(f"\n=== Other pages ===")
for page in [
    "MNU_access_setRecovery.htm",
    "MNU_access_password.htm",
    "PWD_password.htm",
    "BAS_basic.htm",
    "start.htm",
    "index.htm",
    "currentsetting.htm",
]:
    time.sleep(0.3)
    body2, code2 = do(f"https://{ip}/{page}")
    title = re.search(r"<title>(.*?)</title>", body2, re.IGNORECASE)
    inputs2 = re.findall(r'<input[^>]*name="([^"]*)"[^>]*>', body2, re.IGNORECASE)
    print(f"  {page}: code={code2}, title={title.group(1) if title else 'N/A'}, inputs={inputs2[:10]}")
    if page == "currentsetting.htm" and code2 == 200 and len(body2) > 100:
        print(f"    Body: {body2[:500]}")
