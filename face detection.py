"""
Network Guardian — Two-Factor Authentication (Password + Face)
==============================================================
Flow: Enter username & password → Face scan → Grant/Deny access

Requires: opencv-python, face_recognition, numpy, Pillow, bcrypt
Install:  pip install opencv-python face_recognition numpy Pillow bcrypt
"""

import cv2
import face_recognition
import numpy as np
import os
import json
import time
import datetime
import hashlib
import bcrypt
import getpass
import sys
from pathlib import Path


# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
BASE_DIR          = Path(__file__).parent
KNOWN_FACES_DIR   = BASE_DIR / "known_faces"       # registered face images
USERS_DB_FILE     = BASE_DIR / "users_db.json"     # hashed passwords + roles
ACCESS_LOG_FILE   = BASE_DIR / "access_log.json"   # audit log

CONFIDENCE_THRESHOLD = 0.40   # face match sensitivity (lower = stricter)
FRAME_SCALE          = 0.5    # resize factor for faster detection
FACE_SCAN_TIMEOUT    = 30     # seconds to wait for face before failing
MAX_LOGIN_ATTEMPTS   = 3      # lockout after N failed password attempts
DETECT_EVERY_N       = 3      # process every Nth frame

WINDOW_TITLE = "Network Guardian — 2FA Access Control"

# UI colours (BGR)
COLOR_AUTHORIZED   = (0, 220, 80)
COLOR_UNAUTHORIZED = (0, 60, 220)
COLOR_ACCENT       = (0, 200, 160)
COLOR_PANEL_BG     = (20, 20, 20)
COLOR_TEXT_PRIMARY = (240, 240, 240)
COLOR_TEXT_MUTED   = (140, 140, 140)
COLOR_WARNING      = (0, 165, 255)


# ─────────────────────────────────────────────
#  User Database Helpers
# ─────────────────────────────────────────────
def load_users_db() -> dict:
    """Load or create the user database."""
    if USERS_DB_FILE.exists():
        with open(USERS_DB_FILE) as f:
            return json.load(f)
    return {}


def save_users_db(db: dict):
    with open(USERS_DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def register_user(username: str, password: str, role: str = "User"):
    """Hash & store a new user's password. Run once during setup."""
    db = load_users_db()
    if username in db:
        print(f"[WARN] User '{username}' already exists. Updating password.")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db[username] = {"password_hash": hashed, "role": role, "failed_attempts": 0, "locked": False}
    save_users_db(db)
    print(f"[INFO] Registered user: {username} (role: {role})")


def verify_password(username: str, password: str) -> tuple[bool, str, str]:
    """
    Returns (success, role, message).
    Handles lockout and failed-attempt counting.
    """
    db = load_users_db()
    if username not in db:
        return False, "", "User not found."

    user = db[username]

    if user.get("locked"):
        return False, "", f"Account '{username}' is locked. Contact administrator."

    if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        # Reset failed attempts on success
        user["failed_attempts"] = 0
        save_users_db(db)
        return True, user.get("role", "User"), "Password accepted."
    else:
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        if user["failed_attempts"] >= MAX_LOGIN_ATTEMPTS:
            user["locked"] = True
            log_event(username, "LOCKED", 0.0, "password_lockout")
            print(f"[ALERT] Account '{username}' locked after {MAX_LOGIN_ATTEMPTS} failed attempts.")
        save_users_db(db)
        remaining = MAX_LOGIN_ATTEMPTS - user["failed_attempts"]
        return False, "", f"Wrong password. {max(remaining,0)} attempt(s) remaining."


# ─────────────────────────────────────────────
#  Face Recognition Helpers
# ─────────────────────────────────────────────
def load_known_faces() -> tuple[list, list]:
    """Load and encode face images from KNOWN_FACES_DIR."""
    encodings, names = [], []
    if not KNOWN_FACES_DIR.exists():
        KNOWN_FACES_DIR.mkdir(parents=True)
        print(f"[INFO] Created '{KNOWN_FACES_DIR}' — add face images named 'Username.jpg'.")
        return encodings, names

    for img_path in KNOWN_FACES_DIR.glob("*"):
        if img_path.suffix.lower() not in (".jpg", ".jpeg", ".png"):
            continue
        name = img_path.stem
        image = face_recognition.load_image_file(str(img_path))
        encs = face_recognition.face_encodings(image)
        if encs:
            encodings.append(encs[0])
            names.append(name)
            print(f"[INFO] Loaded face: {name}")
        else:
            print(f"[WARN] No face found in {img_path.name} — skipping.")

    print(f"[INFO] {len(names)} registered face(s) loaded.\n")
    return encodings, names


def scan_face_for_user(username: str,
                        known_encodings: list,
                        known_names: list) -> tuple[bool, float]:
    """
    Open webcam, scan until the expected username's face is detected
    or FACE_SCAN_TIMEOUT seconds elapse.
    Returns (match_found, confidence).
    """
    # Check that a face image exists for this user
    user_in_db = any(n.lower() == username.lower() for n in known_names)
    if not user_in_db:
        print(f"[ERROR] No face registered for '{username}'. Add {username}.jpg to known_faces/")
        return False, 0.0

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Cannot open webcam.")
        return False, 0.0

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

    start_time = time.time()
    frame_count = 0
    result_match = False
    result_conf  = 0.0
    face_locations = []
    face_names_det = []
    face_confs_det = []

    print(f"[INFO] Face scan started. Look at the camera…  (timeout: {FACE_SCAN_TIMEOUT}s)")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        elapsed = time.time() - start_time
        remaining = max(0, FACE_SCAN_TIMEOUT - elapsed)

        frame_count += 1

        # ── Detection every N frames ────────────────────────────────────
        if frame_count % DETECT_EVERY_N == 0:
            small = cv2.resize(frame, (0, 0), fx=FRAME_SCALE, fy=FRAME_SCALE)
            rgb_small = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
            face_locations = face_recognition.face_locations(rgb_small, model="hog")
            encodings = face_recognition.face_encodings(rgb_small, face_locations)

            face_names_det = []
            face_confs_det = []

            for enc in encodings:
                det_name, conf = "Unknown", 0.0
                if known_encodings:
                    distances = face_recognition.face_distance(known_encodings, enc)
                    best_idx  = int(np.argmin(distances))
                    conf      = 1.0 - distances[best_idx]
                    if conf >= (1.0 - CONFIDENCE_THRESHOLD):
                        det_name = known_names[best_idx]
                face_names_det.append(det_name)
                face_confs_det.append(conf)

            # Check if expected user matched
            for det_name, conf in zip(face_names_det, face_confs_det):
                print(f"[SCAN] Detected: {det_name}  confidence: {conf*100:.1f}%  (need >={( 1.0 - CONFIDENCE_THRESHOLD)*100:.0f}%)")
                if det_name.lower() == username.lower():
                    result_match = True
                    result_conf  = conf
                    break

        # ── Draw boxes ──────────────────────────────────────────────────
        scale_inv = 1.0 / FRAME_SCALE
        for (top, right, bottom, left), det_name, conf in zip(
                face_locations, face_names_det, face_confs_det):
            top    = int(top    * scale_inv)
            right  = int(right  * scale_inv)
            bottom = int(bottom * scale_inv)
            left   = int(left   * scale_inv)

            match = det_name.lower() == username.lower()
            color = COLOR_AUTHORIZED if match else COLOR_UNAUTHORIZED
            cv2.rectangle(frame, (left, top), (right, bottom), color, 2)
            label = f"{det_name}  {conf*100:.0f}%"
            cv2.rectangle(frame, (left, bottom), (right, bottom + 22), color, -1)
            cv2.putText(frame, label, (left + 6, bottom + 15),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.42, (255, 255, 255), 1, cv2.LINE_AA)

        # ── HUD overlay ─────────────────────────────────────────────────
        h, w = frame.shape[:2]
        _draw_face_scan_hud(frame, username, remaining, result_match)

        cv2.imshow(WINDOW_TITLE, frame)

        if result_match:
            cv2.waitKey(800)   # brief pause to show success
            break

        if elapsed >= FACE_SCAN_TIMEOUT:
            break

        if cv2.waitKey(1) & 0xFF == ord("q"):
            print("[INFO] Scan cancelled by user.")
            break

    cap.release()
    cv2.destroyAllWindows()
    return result_match, result_conf


def _draw_face_scan_hud(frame, username: str, remaining: float, matched: bool):
    """Overlay face-scan status on the frame."""
    h, w = frame.shape[:2]

    # Top banner
    banner_color = COLOR_AUTHORIZED if matched else COLOR_ACCENT
    cv2.rectangle(frame, (0, 0), (w, 52), COLOR_PANEL_BG, -1)
    cv2.putText(frame, "NETWORK GUARDIAN — BIOMETRIC VERIFICATION",
                (14, 22), cv2.FONT_HERSHEY_SIMPLEX, 0.55, banner_color, 1, cv2.LINE_AA)
    status_text = f"Verifying: {username}   Time remaining: {remaining:.0f}s"
    cv2.putText(frame, status_text,
                (14, 44), cv2.FONT_HERSHEY_SIMPLEX, 0.40, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)

    # Bottom status
    if matched:
        msg = f"FACE MATCHED — Access Granted to {username}"
        color = COLOR_AUTHORIZED
    else:
        msg = "Please look directly at the camera…"
        color = COLOR_WARNING
    cv2.rectangle(frame, (0, h - 36), (w, h), COLOR_PANEL_BG, -1)
    cv2.putText(frame, msg, (14, h - 12),
                cv2.FONT_HERSHEY_SIMPLEX, 0.48, color, 1, cv2.LINE_AA)


# ─────────────────────────────────────────────
#  Audit Logging
# ─────────────────────────────────────────────
def log_event(username: str, status: str, confidence: float, stage: str):
    """Append a structured event to the JSON access log."""
    event = {
        "timestamp":      datetime.datetime.now().isoformat(),
        "username":       username,
        "stage":          stage,           # 'password' | 'face' | 'final' | 'password_lockout'
        "status":         status,          # 'SUCCESS' | 'FAILED' | 'LOCKED'
        "confidence_pct": round(confidence * 100, 1),
    }
    log = []
    if ACCESS_LOG_FILE.exists():
        with open(ACCESS_LOG_FILE) as f:
            try:
                log = json.load(f)
            except json.JSONDecodeError:
                log = []
    log.append(event)
    with open(ACCESS_LOG_FILE, "w") as f:
        json.dump(log, f, indent=2)


# ─────────────────────────────────────────────
#  Main 2FA Login Flow
# ─────────────────────────────────────────────
def login(known_encodings: list, known_names: list) -> tuple[bool, str, str]:
    """
    Perform two-factor authentication:
      1. Username + password
      2. Facial recognition

    Returns (success, username, role).
    """
    print("\n" + "="*52)
    print("  NETWORK GUARDIAN — Secure Login")
    print("="*52)

    # ── Step 1: Password ────────────────────────────────────────────────
    print("\n[STEP 1/2]  Password Authentication\n")
    username = input("  Username: ").strip()
    if not username:
        print("[ERROR] Username cannot be empty.")
        return False, "", ""

    password = getpass.getpass("  Password: ")
    pwd_ok, role, msg = verify_password(username, password)
    log_event(username, "SUCCESS" if pwd_ok else "FAILED", 0.0, "password")

    if not pwd_ok:
        print(f"\n  ✗  {msg}\n")
        return False, username, ""

    print(f"\n  ✓  {msg}  (Role: {role})")

    # ── Step 2: Face scan ───────────────────────────────────────────────
    print(f"\n[STEP 2/2]  Biometric Face Verification for '{username}'")
    print("           A camera window will open. Look at the camera.\n")

    face_ok, confidence = scan_face_for_user(username, known_encodings, known_names)
    log_event(username,
              "SUCCESS" if face_ok else "FAILED",
              confidence,
              "face")

    if face_ok:
        log_event(username, "SUCCESS", confidence, "final")
        print(f"\n  ✓  Face matched ({confidence*100:.1f}% confidence)")
        print(f"\n  ╔══════════════════════════════════╗")
        print(f"  ║   ACCESS GRANTED — Welcome, {username[:10]:<10} ║")
        print(f"  ║   Role: {role:<26} ║")
        print(f"  ╚══════════════════════════════════╝\n")
        return True, username, role
    else:
        log_event(username, "FAILED", confidence, "final")
        print(f"\n  ✗  Face verification failed. Access denied.\n")
        return False, username, ""


# ─────────────────────────────────────────────
#  Setup / Registration CLI
# ─────────────────────────────────────────────
def setup_wizard():
    """Interactive setup: register a new user account."""
    print("\n[SETUP]  Register a new Network Guardian user")
    print("-"*46)
    username = input("  Username  : ").strip()
    role     = input("  Role      : ").strip() or "User"
    password = getpass.getpass("  Password  : ")
    confirm  = getpass.getpass("  Confirm   : ")
    if password != confirm:
        print("[ERROR] Passwords do not match.")
        return
    register_user(username, password, role)
    print(f"\n[INFO] Now add a face image:")
    print(f"       {KNOWN_FACES_DIR / (username + '.jpg')}")
    print("       (clear, front-facing, single face)\n")


# ─────────────────────────────────────────────
#  Dashboard Launcher (post-login)
# ─────────────────────────────────────────────
def _launch_dashboard(username: str, role: str):
    """Start the web dashboard and open it in the browser."""
    import subprocess
    import webbrowser
    import threading

    dashboard_url = "http://127.0.0.1:8080"
    script = str(BASE_DIR / "_start_dashboard.py")

    proc = subprocess.Popen(
        [sys.executable, script],
        cwd=str(BASE_DIR),
    )

    print(f"[INFO] Dashboard starting at {dashboard_url}")
    print(f"[INFO] Operator: {username}  |  Role: {role}")
    print("[INFO] Press Ctrl+C to stop.\n")

    # Give the server a moment to start then open browser
    def _open():
        import time
        time.sleep(2)
        webbrowser.open(dashboard_url)

    threading.Thread(target=_open, daemon=True).start()

    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\n[INFO] Dashboard stopped.")


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        setup_wizard()
        return

    # Load registered faces once at startup
    known_encodings, known_names = load_known_faces()

    # 2FA login loop (retry up to MAX_LOGIN_ATTEMPTS times)
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        if attempt > 1:
            print(f"\n[INFO] Login attempt {attempt}/{MAX_LOGIN_ATTEMPTS}")

        success, username, role = login(known_encodings, known_names)

        if success:
            # ── Post-login: launch the web dashboard ──────────────────
            print("[INFO] Launching Network Guardian dashboard…\n")
            _launch_dashboard(username, role)
            break
        else:
            if attempt < MAX_LOGIN_ATTEMPTS:
                retry = input("  Try again? [Y/n]: ").strip().lower()
                if retry == "n":
                    break
            else:
                print("\n[ALERT] Maximum login attempts reached. Exiting.\n")


# ─────────────────────────────────────────────
#  Guardian Monitor (post-login dashboard)
# ─────────────────────────────────────────────
def draw_rounded_rect(frame, x1, y1, x2, y2, color, thickness=2, r=12):
    cv2.line(frame,  (x1+r, y1), (x2-r, y1), color, thickness)
    cv2.line(frame,  (x1+r, y2), (x2-r, y2), color, thickness)
    cv2.line(frame,  (x1, y1+r), (x1, y2-r), color, thickness)
    cv2.line(frame,  (x2, y1+r), (x2, y2-r), color, thickness)
    cv2.ellipse(frame, (x1+r, y1+r), (r, r), 180, 0, 90, color, thickness)
    cv2.ellipse(frame, (x2-r, y1+r), (r, r), 270, 0, 90, color, thickness)
    cv2.ellipse(frame, (x1+r, y2-r), (r, r),  90, 0, 90, color, thickness)
    cv2.ellipse(frame, (x2-r, y2-r), (r, r),   0, 0, 90, color, thickness)


def draw_hud(frame, stats: dict, session_user: str, session_role: str):
    h, w = frame.shape[:2]
    panel_w = 270
    overlay = frame.copy()
    cv2.rectangle(overlay, (w - panel_w, 0), (w, h), COLOR_PANEL_BG, -1)
    cv2.addWeighted(overlay, 0.75, frame, 0.25, 0, frame)

    x, y = w - panel_w + 14, 30
    cv2.putText(frame, "NETWORK GUARDIAN", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.45, COLOR_ACCENT, 1, cv2.LINE_AA)
    y += 18
    cv2.putText(frame, "Live Monitor", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.38, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)
    y += 18
    cv2.line(frame, (x, y), (w - 14, y), COLOR_ACCENT, 1)
    y += 18

    # Session info
    cv2.putText(frame, f"Operator: {session_user}", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_AUTHORIZED, 1, cv2.LINE_AA)
    y += 18
    cv2.putText(frame, f"Role    : {session_role}", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_TEXT_PRIMARY, 1, cv2.LINE_AA)
    y += 22
    cv2.line(frame, (x, y), (w - 14, y), (50, 50, 50), 1)
    y += 18

    rows = [
        ("Status",  stats.get("status", "Scanning…")),
        ("Faces",   str(stats.get("faces", 0))),
        ("Auth'd",  str(stats.get("authorized", 0))),
        ("Unknown", str(stats.get("unknown", 0))),
        ("FPS",     f"{stats.get('fps', 0):.1f}"),
    ]
    for label, value in rows:
        cv2.putText(frame, label, (x, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)
        cv2.putText(frame, value, (x + 110, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_TEXT_PRIMARY, 1, cv2.LINE_AA)
        y += 20

    y += 6
    cv2.line(frame, (x, y), (w - 14, y), (50, 50, 50), 1)
    y += 18
    cv2.putText(frame, "Last event", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)
    y += 18
    last = stats.get("last_event", "—")
    for chunk in [last[i:i+28] for i in range(0, len(last), 28)]:
        cv2.putText(frame, chunk, (x, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.34, COLOR_TEXT_PRIMARY, 1, cv2.LINE_AA)
        y += 16

    ts = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    cv2.putText(frame, ts, (x, h - 14),
                cv2.FONT_HERSHEY_SIMPLEX, 0.33, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)
    cv2.putText(frame, "Q: quit   R: reload   S: screenshot",
                (8, h - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.33, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)


def run_guardian_monitor(known_encodings, known_names, session_user, session_role):
    """Full live-monitoring dashboard (same as original guardian, now with session info)."""
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Cannot open webcam.")
        return

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

    frame_count = 0
    face_locations, face_names_det, face_confs_det, face_statuses = [], [], [], []
    fps_timer, fps = time.time(), 0.0
    last_logged: dict[str, float] = {}
    stats = {"status": "Scanning…", "faces": 0, "authorized": 0,
             "unknown": 0, "fps": 0.0, "last_event": "—"}

    print("[INFO] Monitor running. Press Q to quit.\n")

    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frame_count += 1

        if frame_count % DETECT_EVERY_N == 0:
            small = cv2.resize(frame, (0, 0), fx=FRAME_SCALE, fy=FRAME_SCALE)
            rgb   = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
            face_locations = face_recognition.face_locations(rgb, model="hog")
            encodings = face_recognition.face_encodings(rgb, face_locations)

            face_names_det, face_confs_det, face_statuses = [], [], []
            for enc in encodings:
                name, conf, status = "Unknown", 0.0, "unauthorized"
                if known_encodings:
                    dists    = face_recognition.face_distance(known_encodings, enc)
                    best     = int(np.argmin(dists))
                    conf     = 1.0 - dists[best]
                    if conf >= (1.0 - CONFIDENCE_THRESHOLD):
                        name   = known_names[best]
                        status = "authorized"
                face_names_det.append(name)
                face_confs_det.append(conf)
                face_statuses.append(status)

            for name, conf, status in zip(face_names_det, face_confs_det, face_statuses):
                now = time.time()
                if now - last_logged.get(name, 0) > 5:
                    last_logged[name] = now
                    log_event(name, status.upper(), conf, "monitor")
                    stats["last_event"] = f"{name} — {status.upper()}"

            auth  = sum(1 for s in face_statuses if s == "authorized")
            unkn  = sum(1 for s in face_statuses if s == "unauthorized")
            stats.update({"faces": len(face_locations), "authorized": auth, "unknown": unkn,
                          "status": "CLEAR" if unkn == 0 and len(face_locations) > 0
                                    else ("ALERT" if unkn > 0 else "Scanning…")})

        scale_inv = 1.0 / FRAME_SCALE
        for (top, right, bottom, left), name, conf, status in zip(
                face_locations, face_names_det, face_confs_det, face_statuses):
            top, right, bottom, left = (int(v * scale_inv) for v in (top, right, bottom, left))
            color = COLOR_AUTHORIZED if status == "authorized" else COLOR_UNAUTHORIZED
            draw_rounded_rect(frame, left, top, right, bottom, color)
            cv2.rectangle(frame, (left, bottom), (right, bottom + 22), color, -1)
            cv2.putText(frame, f"{name}  {conf*100:.0f}%",
                        (left + 6, bottom + 15), cv2.FONT_HERSHEY_SIMPLEX, 0.42,
                        (255, 255, 255), 1, cv2.LINE_AA)
            badge = "AUTH" if status == "authorized" else "DENY"
            cv2.putText(frame, badge, (right - 48, top - 6),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.42, color, 1, cv2.LINE_AA)

        now = time.time()
        fps = 0.9 * fps + 0.1 * (1.0 / max(now - fps_timer, 1e-6))
        fps_timer = now
        stats["fps"] = fps

        draw_hud(frame, stats, session_user, session_role)
        cv2.imshow(WINDOW_TITLE, frame)

        key = cv2.waitKey(1) & 0xFF
        if key == ord("q"):
            break
        elif key == ord("r"):
            known_encodings, known_names = load_known_faces()
        elif key == ord("s"):
            fname = f"screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            cv2.imwrite(fname, frame)
            print(f"[INFO] Screenshot saved: {fname}")

    cap.release()
    cv2.destroyAllWindows()
    print("[INFO] Monitor closed. Session ended.")


if __name__ == "__main__":
    main()
