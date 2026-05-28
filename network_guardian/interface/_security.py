# Copyright (c) 2026 Wolf-Pak Innovations LLC. All Rights Reserved.
# Proprietary and confidential. Unauthorized use, reproduction,
# or distribution is strictly prohibited. See LICENSE for terms.
"""
Wolfpak Security Module — Network Guardian

Team-based authentication with password rotation, session management,
CSRF protection, and input sanitisation.
Ensures exclusive access to authorised Wolfpak operators only.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("network_guardian.security")

# Session token lifetime (seconds)
SESSION_LIFETIME = 3600
# Password rotation period (seconds) — 60 days
PASSWORD_MAX_AGE = 60 * 86400


# ---------------------------------------------------------------------------
# Password hashing (SHA-256 + per-user salt — zero external deps)
# ---------------------------------------------------------------------------

def _hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hash a password with a random salt. Returns (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return h.hex(), salt


def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verify a password against stored hash using constant-time compare."""
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return hmac.compare_digest(h.hex(), stored_hash)


_SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{}|;':,./<>?")


def _validate_password_complexity(password: str) -> None:
    """Enforce minimum complexity: length, uppercase, digit, special char."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one number")
    if not any(c in _SPECIAL_CHARS for c in password):
        raise ValueError("Password must contain at least one special character (!@#$%^&* etc.)")


# ---------------------------------------------------------------------------
# Team store — JSON file in data_dir
# ---------------------------------------------------------------------------

class TeamStore:
    """Manages Wolfpak team member accounts with password rotation.

    Data file: <data_dir>/wolfpak_team.json
    Format:
    {
      "members": {
        "username": {
          "display_name": "...",
          "password_hash": "...",
          "salt": "...",
          "created_at": <epoch>,
          "password_set_at": <epoch>,
          "role": "operator" | "admin",
          "active": true|false
        }
      },
      "server_secret": "..."
    }
    """

    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / "wolfpak_team.json"
        self._data: dict[str, Any] = {"members": {}, "server_secret": ""}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                with open(self._path, "r") as f:
                    self._data = json.load(f)
                logger.info("Loaded %d team members from %s",
                            len(self._data.get("members", {})), self._path)
            except (json.JSONDecodeError, OSError) as e:
                logger.error("Failed to load team file: %s", e)
                self._data = {"members": {}, "server_secret": ""}
        if not self._data.get("server_secret"):
            self._data["server_secret"] = secrets.token_urlsafe(32)
            self._save()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(self._data, f, indent=2)
        tmp.replace(self._path)

    @property
    def server_secret(self) -> str:
        return self._data["server_secret"]

    @property
    def members(self) -> dict[str, Any]:
        return self._data.get("members", {})

    def has_members(self) -> bool:
        return bool(self._data.get("members"))

    def add_member(self, username: str, display_name: str, password: str,
                   role: str = "operator") -> None:
        """Add a new team member."""
        username = username.lower().strip()
        if not username or not password:
            raise ValueError("Username and password required")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        pw_hash, salt = _hash_password(password)
        now = int(time.time())
        self._data.setdefault("members", {})[username] = {
            "display_name": display_name or username,
            "password_hash": pw_hash,
            "salt": salt,
            "created_at": now,
            "password_set_at": now,
            "role": role,
            "active": True,
        }
        self._save()
        logger.info("Team member added: %s (%s)", username, role)

    def remove_member(self, username: str) -> bool:
        username = username.lower().strip()
        if username in self._data.get("members", {}):
            del self._data["members"][username]
            self._save()
            logger.info("Team member removed: %s", username)
            return True
        return False

    def authenticate(self, username: str, password: str) -> dict | None:
        """Verify credentials. Returns member dict or None."""
        username = username.lower().strip()
        member = self._data.get("members", {}).get(username)
        if not member or not member.get("active"):
            return None
        if not _verify_password(password, member["password_hash"], member["salt"]):
            return None
        return member

    def password_expired(self, username: str) -> bool:
        """Check if password is older than 60 days."""
        username = username.lower().strip()
        member = self._data.get("members", {}).get(username)
        if not member:
            return False
        age = time.time() - member.get("password_set_at", 0)
        return age > PASSWORD_MAX_AGE

    def days_until_expiry(self, username: str) -> int:
        """Days remaining before password expires."""
        username = username.lower().strip()
        member = self._data.get("members", {}).get(username)
        if not member:
            return 0
        age = time.time() - member.get("password_set_at", 0)
        remaining = PASSWORD_MAX_AGE - age
        return max(0, int(remaining / 86400))

    def change_password(self, username: str, new_password: str) -> bool:
        """Set a new password for a team member."""
        username = username.lower().strip()
        member = self._data.get("members", {}).get(username)
        if not member:
            return False
        _validate_password_complexity(new_password)
        pw_hash, salt = _hash_password(new_password)
        member["password_hash"] = pw_hash
        member["salt"] = salt
        member["password_set_at"] = int(time.time())
        self._save()
        logger.info("Password changed for %s", username)
        return True

    def list_members(self) -> list[dict]:
        """Return a summary of all members (no secrets)."""
        result = []
        for uname, m in self._data.get("members", {}).items():
            result.append({
                "username": uname,
                "display_name": m.get("display_name", uname),
                "role": m.get("role", "operator"),
                "active": m.get("active", True),
                "created_at": m.get("created_at", 0),
                "password_set_at": m.get("password_set_at", 0),
                "days_until_expiry": self.days_until_expiry(uname),
                "expired": self.password_expired(uname),
            })
        return result


# ---------------------------------------------------------------------------
# Session tokens (HMAC-SHA256, timestamped, per-user)
# ---------------------------------------------------------------------------

def create_session_token(username: str, server_secret: str, server_nonce: str) -> str:
    """Create a timestamped HMAC session token for a user."""
    ts = str(int(time.time()))
    payload = f"{username}.{ts}.{server_nonce}".encode()
    sig = hmac.new(server_secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"{username}.{ts}.{sig}"


def verify_session_token(token: str, server_secret: str, server_nonce: str,
                         team_store: TeamStore | None = None) -> str | None:
    """Verify a session token. Returns the username if valid, else None."""
    if not token or not server_secret:
        return None
    try:
        parts = token.split(".", 2)
        if len(parts) != 3:
            return None
        username, ts_str, sig = parts
        ts = int(ts_str)
    except (ValueError, AttributeError):
        return None
    if time.time() - ts > SESSION_LIFETIME:
        return None
    payload = f"{username}.{ts_str}.{server_nonce}".encode()
    expected = hmac.new(server_secret.encode(), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    # Verify user still exists and is active
    if team_store and team_store.has_members():
        member = team_store.members.get(username)
        if not member or not member.get("active"):
            return None
    return username


# ---------------------------------------------------------------------------
# Data sanitisation — prevents stored XSS via innerHTML
# ---------------------------------------------------------------------------

def sanitize_data(obj: Any) -> Any:
    """Recursively HTML-escape all string values in API response data."""
    if isinstance(obj, str):
        return html.escape(obj, quote=True)
    if isinstance(obj, dict):
        return {k: sanitize_data(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_data(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Login page — Wolfpak branded (username + password)
# ---------------------------------------------------------------------------

_LOGIN_PAGE = '''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Network Guardian</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style nonce="{{NONCE}}">
:root{
  --bg:#000810;--bg2:#010d1a;--card:rgba(0,18,36,0.92);
  --border:rgba(0,200,255,0.15);--text:#cce8ff;--dim:#3d7a9a;
  --blue:#0094d4;--green:#00ff88;--yellow:#ffcc00;--orange:#ff8c00;
  --red:#ff2244;--purple:#aa44ff;--cyan:#00d4ff;--pink:#ff00aa}
@keyframes pulse-ring{0%{transform:scale(0.8);opacity:0.8}100%{transform:scale(2);opacity:0}}
@keyframes scan-h{0%{left:-100%;opacity:0}50%{opacity:1}100%{left:100%;opacity:0}}
@keyframes pulse-glow{0%,100%{opacity:.5}50%{opacity:1}}
@keyframes hud-boot{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
*{margin:0;padding:0;box-sizing:border-box}
body{
  background:var(--bg);
  background-image:
    radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.04) 0%,transparent 50%),
    radial-gradient(ellipse at 80% 20%,rgba(0,100,255,.05) 0%,transparent 50%),
    linear-gradient(rgba(0,200,255,.015) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,200,255,.015) 1px,transparent 1px);
  background-size:auto,auto,50px 50px,50px 50px;
  color:var(--text);
  font-family:'Rajdhani','Segoe UI',sans-serif;
  display:flex;align-items:center;justify-content:center;min-height:100vh;
  overflow:hidden;position:relative}
.pulse-ring{
  position:fixed;border-radius:50%;border:1px solid rgba(0,212,255,0.25);
  pointer-events:none;top:50%;left:50%;transform:translate(-50%,-50%)}
.pulse-ring-1{width:300px;height:300px;animation:pulse-ring 4s ease-out infinite}
.pulse-ring-2{width:300px;height:300px;animation:pulse-ring 4s ease-out infinite 2s}
.login-box{
  position:relative;z-index:10;
  background:linear-gradient(135deg,rgba(0,22,44,.9),rgba(0,8,22,.95));
  border:1px solid rgba(0,200,255,.2);border-radius:4px;
  padding:40px;max-width:420px;width:90%;text-align:center;
  box-shadow:0 0 40px rgba(0,212,255,.06),inset 0 1px 0 rgba(0,212,255,.08);
  animation:hud-boot .6s ease both}
.login-box::before{
  content:'';position:absolute;top:-1px;left:-1px;
  width:18px;height:18px;
  border-top:2px solid var(--cyan);border-left:2px solid var(--cyan);
  box-shadow:-2px -2px 8px rgba(0,212,255,.3)}
.login-box::after{
  content:'';position:absolute;bottom:-1px;right:-1px;
  width:18px;height:18px;
  border-bottom:2px solid var(--cyan);border-right:2px solid var(--cyan);
  box-shadow:2px 2px 8px rgba(0,212,255,.3)}
.logo{
  width:60px;height:60px;margin:0 auto 14px;
  border:2px solid var(--cyan);border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  box-shadow:0 0 30px rgba(0,212,255,.4),inset 0 0 20px rgba(0,212,255,.05);
  font-size:1.6rem;
  animation:pulse-glow 3s ease-in-out infinite}
.title{
  font-family:'Orbitron',sans-serif;font-size:1.1rem;font-weight:700;
  letter-spacing:4px;text-transform:uppercase;
  color:var(--cyan);text-shadow:0 0 20px rgba(0,212,255,.5);
  margin-bottom:6px}
.badge{
  display:inline-block;padding:3px 12px;font-size:.65rem;font-weight:700;
  letter-spacing:1.5px;text-transform:uppercase;margin-bottom:14px;
  font-family:'Share Tech Mono',monospace;
  clip-path:polygon(6px 0%,100% 0%,calc(100% - 6px) 100%,0% 100%);
  background:rgba(0,212,255,.1);color:var(--cyan);
  border-top:1px solid rgba(0,212,255,.3)}
.subtitle{
  color:var(--dim);font-size:.78rem;margin-bottom:24px;
  font-family:'Share Tech Mono',monospace;letter-spacing:.5px}
.input-group{margin-bottom:16px;text-align:left}
.input-group label{
  display:block;font-size:.65rem;color:var(--cyan);
  text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;
  font-family:'Share Tech Mono',monospace}
.input-group input{
  width:100%;padding:10px 14px;border-radius:2px;
  border:1px solid rgba(0,200,255,.2);
  background:rgba(0,10,25,.8);color:#cce8ff;
  font-size:.88rem;font-family:'Share Tech Mono',monospace;
  outline:none;transition:.2s;position:relative}
.input-group input:focus{
  border-color:var(--cyan);
  box-shadow:0 0 15px rgba(0,212,255,.2),inset 0 0 8px rgba(0,212,255,.04)}
.input-group input::placeholder{color:rgba(61,122,154,.6)}
.btn{
  width:100%;padding:12px;border:1px solid var(--cyan);
  background:rgba(0,212,255,.15);color:var(--cyan);
  font-family:'Orbitron',sans-serif;font-size:.78rem;font-weight:600;
  letter-spacing:2px;text-transform:uppercase;
  clip-path:polygon(8px 0%,100% 0%,calc(100% - 8px) 100%,0% 100%);
  border-radius:0;cursor:pointer;transition:.2s;margin-top:8px;
  box-shadow:0 0 20px rgba(0,212,255,.2)}
.btn:hover{
  background:rgba(0,212,255,.25);
  box-shadow:0 0 30px rgba(0,212,255,.4);color:#fff}
.btn:disabled{opacity:.3;cursor:not-allowed;box-shadow:none}
.error{
  color:var(--red);font-size:.78rem;margin-top:12px;display:none;
  font-family:'Share Tech Mono',monospace;letter-spacing:.5px}
.warn{
  color:var(--yellow);font-size:.78rem;margin-top:12px;display:none;
  font-family:'Share Tech Mono',monospace;letter-spacing:.5px}
.footer{
  color:var(--dim);font-size:.65rem;margin-top:22px;letter-spacing:3px;
  font-family:'Share Tech Mono',monospace;text-transform:uppercase}
.pw-box{
  display:none;margin-top:16px;text-align:left;padding:16px;
  border:1px solid rgba(0,200,255,.15);border-radius:2px;
  background:rgba(0,8,20,.6)}
.pw-box h4{
  font-size:.78rem;margin-bottom:12px;color:var(--yellow);
  font-family:'Share Tech Mono',monospace;letter-spacing:1px;text-transform:uppercase}
</style></head><body>
<div class="pulse-ring pulse-ring-1"></div>
<div class="pulse-ring pulse-ring-2"></div>
<div class="login-box">
  <div class="logo">&#128737;</div>
  <div class="title">Wolfpak Systems</div>
  <div class="badge">Wolfpak Exclusive</div>
  <div class="subtitle">Authorised personnel only.</div>
  <form id="loginForm" autocomplete="off">
    <div class="input-group">
      <label>Username</label>
      <input type="text" id="user" placeholder="Enter username" autofocus required>
    </div>
    <div class="input-group">
      <label>Password</label>
      <input type="password" id="pass" placeholder="Enter password" required>
    </div>
    <button type="submit" class="btn" id="loginBtn">Authenticate</button>
    <div class="error" id="err"></div>
    <div class="warn" id="wrn"></div>
  </form>
  <div class="pw-box" id="pwBox">
    <h4>&#9888; Password Expired — Set New Password</h4>
    <div class="input-group"><label>New Password (min 8 chars)</label>
      <input type="password" id="newPw" placeholder="New password">
    </div>
    <div class="input-group"><label>Confirm Password</label>
      <input type="password" id="newPw2" placeholder="Confirm password">
    </div>
    <button class="btn" id="pwBtn" style="border-color:var(--yellow);background:rgba(255,204,0,.12);color:var(--yellow);box-shadow:0 0 15px rgba(255,204,0,.2)">Update Password</button>
    <div class="error" id="pwErr" style="display:none"></div>
  </div>
  <div class="footer">&#128274; Wolfpak Security &mdash; All Access Logged</div>
</div>
<script nonce="{{NONCE}}">
(function(){
  var form=document.getElementById('loginForm'),
      btn=document.getElementById('loginBtn'),
      err=document.getElementById('err'),
      wrn=document.getElementById('wrn'),
      pwBox=document.getElementById('pwBox');

  function doLogin(){
    var user=document.getElementById('user').value.trim();
    var pass=document.getElementById('pass').value;
    if(!user||!pass)return;
    btn.disabled=true; err.style.display='none'; wrn.style.display='none';
    fetch('/api/auth/login',{
      method:'POST',
      headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
      body:JSON.stringify({username:user,password:pass})
    }).then(function(r){return r.json()}).then(function(d){
      if(d.ok){
        if(d.warning){wrn.textContent=d.warning;wrn.style.display='block';}
        var p=new URLSearchParams(window.location.search);
        var next=p.get('next')||'/';
        if(!next.startsWith('/')||next.startsWith('//'))next='/';
        window.location.href=next;
      } else if(d.expired){
        pwBox.style.display='block';
        err.textContent='Password expired. Set a new password below.';
        err.style.display='block'; btn.disabled=false;
      } else {
        err.textContent=d.message||'Access denied';
        err.style.display='block'; btn.disabled=false;
      }
    }).catch(function(){
      err.textContent='Connection error';
      err.style.display='block'; btn.disabled=false;
    });
  }
  form.addEventListener('submit',function(e){e.preventDefault();doLogin()});

  document.getElementById('pwBtn').addEventListener('click',function(){
    var user=document.getElementById('user').value.trim();
    var oldPw=document.getElementById('pass').value;
    var np=document.getElementById('newPw').value;
    var np2=document.getElementById('newPw2').value;
    var pe=document.getElementById('pwErr');
    if(np.length<8){pe.textContent='Min 8 characters';pe.style.display='block';return;}
    if(np!==np2){pe.textContent='Passwords do not match';pe.style.display='block';return;}
    pe.style.display='none';
    fetch('/api/auth/change-password',{
      method:'POST',
      headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
      body:JSON.stringify({username:user,old_password:oldPw,new_password:np})
    }).then(function(r){return r.json()}).then(function(d){
      if(d.ok){doLogin();}
      else{pe.textContent=d.message||'Failed';pe.style.display='block';}
    }).catch(function(){pe.textContent='Connection error';pe.style.display='block';});
  });
})();
</script></body></html>'''


def get_login_page(nonce: str) -> str:
    """Return the login page HTML with nonce substituted."""
    return _LOGIN_PAGE.replace("{{NONCE}}", nonce)
