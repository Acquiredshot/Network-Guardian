#!/usr/bin/env python3
"""SOAP probe - try every possible auth path to get WLAN access."""
import urllib3, requests
urllib3.disable_warnings()

GW = "https://192.168.1.1"
AUTH = ("admin", "Family10130120")
SOAP_URL = GW + "/soap/server_sa/"

ENVELOPE = (
    '<?xml version="1.0" encoding="utf-8" ?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
    ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    '<s:Body>{body}</s:Body>'
    '</s:Envelope>'
)

def soap(action, ns, body_xml, auth=None, session=None):
    data = ENVELOPE.format(body=body_xml)
    h = {
        "SOAPAction": f"urn:NETGEAR-ROUTER:service:{ns}#{action}",
        "Content-Type": "text/xml; charset=utf-8",
    }
    client = session or requests
    kw = dict(headers=h, verify=False, timeout=10)
    if auth:
        kw["auth"] = auth
    return client.post(SOAP_URL, data=data, **kw)


# ── A: SOAPLogin ──
print("=== A: SOAPLogin (DeviceConfig) ===")
body = (
    '<m:SOAPLogin xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1">'
    "<Username>admin</Username>"
    "<Password>Family10130120</Password>"
    "</m:SOAPLogin>"
)
r = soap("SOAPLogin", "DeviceConfig:1", body, auth=AUTH)
print(f"  code={r.status_code}")
print(f"  body={r.text[:600]}")
print()

# ── B: SetSSIDBroadcast NO AUTH ──
print("=== B: SetSSIDBroadcast NO AUTH ===")
body = (
    '<m:SetWLANSSIDBroadcast xmlns:m="urn:NETGEAR-ROUTER:service:WLANConfiguration:1">'
    "<NewSSIDBroadcast>0</NewSSIDBroadcast>"
    "</m:SetWLANSSIDBroadcast>"
)
r = soap("SetWLANSSIDBroadcast", "WLANConfiguration:1", body)
print(f"  code={r.status_code}")
print(f"  body={r.text[:600]}")
print()

# ── C: Session-based auth chain ──
print("=== C: Auth + session cookie chain ===")
s = requests.Session()
s.verify = False

# Step 1: ParentalControl Authenticate
body = '<m:Authenticate xmlns:m="urn:NETGEAR-ROUTER:service:ParentalControl:1"></m:Authenticate>'
r1 = soap("Authenticate", "ParentalControl:1", body, auth=AUTH, session=s)
print(f"  PC Auth: code={r1.status_code}, cookies={dict(s.cookies)}")
# extract response code
if "ResponseCode" in r1.text:
    import re
    m = re.search(r"<ResponseCode>(\d+)</ResponseCode>", r1.text)
    if m:
        print(f"  ResponseCode={m.group(1)}")

# Step 2: ConfigurationStarted with session
body = '<m:ConfigurationStarted xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1"><NewSessionID>11111111</NewSessionID></m:ConfigurationStarted>'
r2 = soap("ConfigurationStarted", "DeviceConfig:1", body, auth=AUTH, session=s)
print(f"  ConfigStarted: code={r2.status_code}")
if "ResponseCode" in r2.text:
    m = re.search(r"<ResponseCode>(\d+)</ResponseCode>", r2.text)
    if m:
        print(f"  ResponseCode={m.group(1)}")

# Step 3: GetSSIDBroadcast with session
body = '<m:GetWLANSSIDBroadcast xmlns:m="urn:NETGEAR-ROUTER:service:WLANConfiguration:1"></m:GetWLANSSIDBroadcast>'
r3 = soap("GetWLANSSIDBroadcast", "WLANConfiguration:1", body, auth=AUTH, session=s)
print(f"  GetSSID: code={r3.status_code}")
print(f"  body={r3.text[:600]}")
print()

# ── D: DeviceInfo GetInfo (no auth) ──
print("=== D: GetInfo NO AUTH ===")
body = '<m:GetInfo xmlns:m="urn:NETGEAR-ROUTER:service:DeviceInfo:1"></m:GetInfo>'
r = soap("GetInfo", "DeviceInfo:1", body)
print(f"  code={r.status_code}")
print(f"  body={r.text[:1000]}")
print()

# ── E: LANConfigSecurity ──
print("=== E: LANConfigSecurity GetInfo ===")
body = '<m:GetInfo xmlns:m="urn:NETGEAR-ROUTER:service:LANConfigSecurity:1"></m:GetInfo>'
r = soap("GetInfo", "LANConfigSecurity:1", body, auth=AUTH)
print(f"  code={r.status_code}")
print(f"  body={r.text[:1000]}")
print()

# ── F: Try web login flow then SOAP ──
print("=== F: Web login → SOAP ===")
s2 = requests.Session()
s2.verify = False
# Hit the root with Basic auth to get the recovery page
r_root = s2.get(GW + "/", auth=AUTH, timeout=10)
print(f"  GET /: code={r_root.status_code}, cookies={dict(s2.cookies)}")

# Now try SOAP with whatever cookies we got
body = '<m:GetWLANSSIDBroadcast xmlns:m="urn:NETGEAR-ROUTER:service:WLANConfiguration:1"></m:GetWLANSSIDBroadcast>'
r_soap = soap("GetWLANSSIDBroadcast", "WLANConfiguration:1", body, auth=AUTH, session=s2)
print(f"  GetSSID: code={r_soap.status_code}")
print(f"  body={r_soap.text[:600]}")
print()

# ── G: Try SetWLANSSIDBroadcast with just Basic auth (no prior SOAP auth) ──
print("=== G: Direct SetSSIDBroadcast with Basic auth ===")
body = (
    '<m:SetWLANSSIDBroadcast xmlns:m="urn:NETGEAR-ROUTER:service:WLANConfiguration:1">'
    "<NewSSIDBroadcast>0</NewSSIDBroadcast>"
    "</m:SetWLANSSIDBroadcast>"
)
r = soap("SetWLANSSIDBroadcast", "WLANConfiguration:1", body, auth=AUTH)
print(f"  code={r.status_code}")
print(f"  body={r.text[:600]}")
print()

# ── H: Try default password "password" ──
print("=== H: Try default password ===")
body = '<m:Authenticate xmlns:m="urn:NETGEAR-ROUTER:service:ParentalControl:1"></m:Authenticate>'
r = soap("Authenticate", "ParentalControl:1", body, auth=("admin", "password"))
print(f"  code={r.status_code}")
if "ResponseCode" in r.text:
    import re
    m = re.search(r"<ResponseCode>(\d+)</ResponseCode>", r.text)
    if m:
        print(f"  ResponseCode={m.group(1)}")

# If default password works, try ConfigStarted + GetSSID
body2 = '<m:ConfigurationStarted xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1"><NewSessionID>22222222</NewSessionID></m:ConfigurationStarted>'
r2 = soap("ConfigurationStarted", "DeviceConfig:1", body2, auth=("admin", "password"))
print(f"  ConfigStarted: code={r2.status_code}")
if "ResponseCode" in r2.text:
    m = re.search(r"<ResponseCode>(\d+)</ResponseCode>", r2.text)
    if m:
        print(f"  ResponseCode={m.group(1)}")
print()

print("=== DONE ===")
