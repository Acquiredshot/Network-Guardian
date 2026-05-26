import urllib.request
import urllib.error
import json

BASE = "http://127.0.0.1:8081"

# Login
data = json.dumps({"username": "admin", "password": "<password>"}).encode()
req = urllib.request.Request(
    BASE + "/api/auth/login", data=data,
    headers={
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
    }
)
resp = urllib.request.urlopen(req)
cookie = resp.headers.get("Set-Cookie", "").split(";")[0]
print(f"AUTH: {resp.status} | Cookie: {cookie}\n")

ENDPOINTS = [
    # HTML pages
    "/", "/ids", "/ips", "/wifi", "/cloaking", "/explorer",
    "/auditor", "/ai", "/fleet", "/reports", "/incidents", "/security",
    # Core APIs
    "/api/status", "/api/health", "/api/findings", "/api/hosts",
    "/api/events", "/api/tasks",
    # IDS APIs
    "/api/ids/stats", "/api/ids/alerts", "/api/ids/rules",
    # IPS APIs
    "/api/ips/stats", "/api/ips/blocklist", "/api/ips/ratelimits",
    "/api/ips/quarantine", "/api/ips/history", "/api/ips/allowlist",
    # WiFi / Cloaking APIs
    "/api/wifi/networks", "/api/wifi/status",
    "/api/cloaking/status", "/api/cloaking/networks",
    # Explorer API
    "/api/explorer/topology",
    # AI API
    "/api/ai/metrics",
    # Fleet APIs
    "/api/fleet/list", "/api/fleet/threats", "/api/fleet/reports",
    "/api/fleet/incidents",
    # Misc
    "/api/wolfpak/clients", "/api/malware/results", "/api/ransomware/status",
]

pass_count = 0
fail_count = 0

for path in ENDPOINTS:
    try:
        r = urllib.request.Request(BASE + path, headers={"Cookie": cookie})
        res = urllib.request.urlopen(r)
        body = res.read()
        print(f"  200 PASS  {path}  ({len(body)}b)")
        pass_count += 1
    except urllib.error.HTTPError as e:
        label = "REDIR" if e.code == 302 else "FAIL"
        print(f"  {e.code} {label}  {path}")
        if e.code == 200:
            pass_count += 1
        else:
            fail_count += 1
    except Exception as e:
        print(f"  ERR   {path}  ({e})")
        fail_count += 1

print(f"\nRESULT: {pass_count} PASS / {fail_count} FAIL out of {len(ENDPOINTS)} endpoints")
