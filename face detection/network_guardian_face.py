"""
Network Guardian - Facial Detection Access Control System
=========================================================
Requires: opencv-python, face_recognition, numpy, Pillow
Install:  pip install opencv-python face_recognition numpy Pillow
"""

import cv2
import face_recognition
import numpy as np
import os
import json
import time
import datetime
from pathlib import Path


# ─────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────
KNOWN_FACES_DIR = "known_faces"          # folder with registered user images
ACCESS_LOG_FILE = "access_log.json"      # JSON log of all access attempts
CONFIDENCE_THRESHOLD = 0.50             # lower = stricter (0.0–1.0)
FRAME_SCALE = 0.5                        # downscale for faster detection
WINDOW_TITLE = "Network Guardian — Facial Access Control"

# UI colours (BGR)
COLOR_AUTHORIZED   = (0, 220, 80)
COLOR_UNAUTHORIZED = (0, 60, 220)
COLOR_UNKNOWN      = (0, 180, 255)
COLOR_PANEL_BG     = (20, 20, 20)
COLOR_TEXT_PRIMARY = (240, 240, 240)
COLOR_TEXT_MUTED   = (140, 140, 140)
COLOR_ACCENT       = (0, 200, 160)


# ─────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────
def load_known_faces(directory: str):
    """Load and encode every .jpg/.png in the known_faces directory."""
    known_encodings = []
    known_names = []
    known_roles = {}

    path = Path(directory)
    if not path.exists():
        path.mkdir(parents=True)
        print(f"[INFO] Created '{directory}' — add face images named 'Name.jpg'.")
        return known_encodings, known_names, known_roles

    # optional roles file: roles.json  {"Alice": "Admin", "Bob": "Engineer"}
    roles_file = path / "roles.json"
    if roles_file.exists():
        with open(roles_file) as f:
            known_roles = json.load(f)

    for img_path in path.glob("*"):
        if img_path.suffix.lower() not in (".jpg", ".jpeg", ".png"):
            continue
        name = img_path.stem                        # filename without extension
        image = face_recognition.load_image_file(str(img_path))
        encodings = face_recognition.face_encodings(image)
        if encodings:
            known_encodings.append(encodings[0])
            known_names.append(name)
            print(f"[INFO] Registered: {name} ({known_roles.get(name, 'User')})")
        else:
            print(f"[WARN] No face found in {img_path.name} — skipping.")

    print(f"[INFO] Loaded {len(known_names)} registered face(s).\n")
    return known_encodings, known_names, known_roles


def log_event(name: str, status: str, confidence: float, log_file: str):
    """Append an access event to the JSON log."""
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "name": name,
        "status": status,
        "confidence_pct": round(confidence * 100, 1),
    }
    log = []
    if os.path.exists(log_file):
        with open(log_file) as f:
            try:
                log = json.load(f)
            except json.JSONDecodeError:
                log = []
    log.append(event)
    with open(log_file, "w") as f:
        json.dump(log, f, indent=2)


def draw_rounded_rect(frame, x1, y1, x2, y2, color, thickness=2, r=12):
    """Draw a rounded rectangle (face box)."""
    cv2.line(frame, (x1 + r, y1), (x2 - r, y1), color, thickness)
    cv2.line(frame, (x1 + r, y2), (x2 - r, y2), color, thickness)
    cv2.line(frame, (x1, y1 + r), (x1, y2 - r), color, thickness)
    cv2.line(frame, (x2, y1 + r), (x2, y2 - r), color, thickness)
    cv2.ellipse(frame, (x1 + r, y1 + r), (r, r), 180, 0, 90,  color, thickness)
    cv2.ellipse(frame, (x2 - r, y1 + r), (r, r), 270, 0, 90,  color, thickness)
    cv2.ellipse(frame, (x1 + r, y2 - r), (r, r), 90,  0, 90,  color, thickness)
    cv2.ellipse(frame, (x2 - r, y2 - r), (r, r), 0,   0, 90,  color, thickness)


def draw_hud(frame, stats: dict):
    """Overlay the status panel on the right side."""
    h, w = frame.shape[:2]
    panel_w = 260
    overlay = frame.copy()
    cv2.rectangle(overlay, (w - panel_w, 0), (w, h), COLOR_PANEL_BG, -1)
    cv2.addWeighted(overlay, 0.75, frame, 0.25, 0, frame)

    x = w - panel_w + 14
    y = 30

    # Title
    cv2.putText(frame, "NETWORK GUARDIAN", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.45, COLOR_ACCENT, 1, cv2.LINE_AA)
    y += 18
    cv2.putText(frame, "Facial Access Control", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.38, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)
    y += 22
    cv2.line(frame, (x, y), (w - 14, y), COLOR_ACCENT, 1)
    y += 18

    # Stats
    rows = [
        ("Status",    stats.get("status", "Scanning…")),
        ("Faces",     str(stats.get("faces", 0))),
        ("Auth'd",    str(stats.get("authorized", 0))),
        ("Unknown",   str(stats.get("unknown", 0))),
        ("FPS",       f"{stats.get('fps', 0):.1f}"),
    ]
    for label, value in rows:
        cv2.putText(frame, label, (x, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)
        cv2.putText(frame, value, (x + 100, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_TEXT_PRIMARY, 1, cv2.LINE_AA)
        y += 20

    y += 6
    cv2.line(frame, (x, y), (w - 14, y), (50, 50, 50), 1)
    y += 18

    # Last event
    cv2.putText(frame, "Last event", (x, y),
                cv2.FONT_HERSHEY_SIMPLEX, 0.37, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)
    y += 18
    last = stats.get("last_event", "—")
    # Word-wrap at ~28 chars
    for chunk in [last[i:i+28] for i in range(0, len(last), 28)]:
        cv2.putText(frame, chunk, (x, y),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.34, COLOR_TEXT_PRIMARY, 1, cv2.LINE_AA)
        y += 16

    # Timestamp bottom
    ts = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    cv2.putText(frame, ts, (x, h - 14),
                cv2.FONT_HERSHEY_SIMPLEX, 0.33, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)

    # Controls hint bottom-left
    cv2.putText(frame, "Q: quit   R: reload faces   S: screenshot",
                (8, h - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.33, COLOR_TEXT_MUTED, 1, cv2.LINE_AA)


# ─────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────
def main():
    known_encodings, known_names, known_roles = load_known_faces(KNOWN_FACES_DIR)

    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Cannot open webcam. Check that a camera is connected.")
        return

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)

    # Throttle: only re-detect every N frames for performance
    DETECT_EVERY_N = 3
    frame_count = 0
    face_locations = []
    face_names = []
    face_confidences = []
    face_statuses = []

    fps_timer = time.time()
    fps = 0.0

    # Cooldown: don't log the same person within 5 s
    last_logged: dict[str, float] = {}

    stats = {"status": "Scanning…", "faces": 0, "authorized": 0,
             "unknown": 0, "fps": 0.0, "last_event": "—"}

    print("[INFO] Network Guardian is running. Press Q to quit.\n")

    while True:
        ret, frame = cap.read()
        if not ret:
            print("[ERROR] Lost camera feed.")
            break

        frame_count += 1

        # ── Detection pass (every N frames) ──────────────────────────────
        if frame_count % DETECT_EVERY_N == 0:
            small = cv2.resize(frame, (0, 0), fx=FRAME_SCALE, fy=FRAME_SCALE)
            rgb_small = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)

            face_locations = face_recognition.face_locations(rgb_small, model="hog")
            encodings = face_recognition.face_encodings(rgb_small, face_locations)

            face_names = []
            face_confidences = []
            face_statuses = []

            for enc in encodings:
                name, confidence, status = "Unknown", 0.0, "unauthorized"

                if known_encodings:
                    distances = face_recognition.face_distance(known_encodings, enc)
                    best_idx = int(np.argmin(distances))
                    best_dist = distances[best_idx]
                    confidence = 1.0 - best_dist        # convert distance → score

                    if confidence >= (1.0 - CONFIDENCE_THRESHOLD):
                        name = known_names[best_idx]
                        status = "authorized"

                face_names.append(name)
                face_confidences.append(confidence)
                face_statuses.append(status)

            # Log new events
            for name, conf, status in zip(face_names, face_confidences, face_statuses):
                now = time.time()
                if now - last_logged.get(name, 0) > 5:
                    last_logged[name] = now
                    log_event(name, status, conf, ACCESS_LOG_FILE)
                    role = known_roles.get(name, "User")
                    stats["last_event"] = f"{name} ({role}) — {status.upper()}"

            # Update stats
            auth_count = sum(1 for s in face_statuses if s == "authorized")
            unk_count  = sum(1 for s in face_statuses if s == "unauthorized")
            stats.update({
                "faces": len(face_locations),
                "authorized": auth_count,
                "unknown": unk_count,
                "status": "CLEAR" if unk_count == 0 and len(face_locations) > 0
                          else ("ALERT" if unk_count > 0 else "Scanning…"),
            })

        # ── Draw face boxes ───────────────────────────────────────────────
        scale_inv = 1.0 / FRAME_SCALE
        for (top, right, bottom, left), name, conf, status in zip(
                face_locations, face_names, face_confidences, face_statuses):

            top    = int(top    * scale_inv)
            right  = int(right  * scale_inv)
            bottom = int(bottom * scale_inv)
            left   = int(left   * scale_inv)

            color = COLOR_AUTHORIZED if status == "authorized" else COLOR_UNAUTHORIZED

            draw_rounded_rect(frame, left, top, right, bottom, color, thickness=2)

            # Label background
            label_h = 22
            cv2.rectangle(frame, (left, bottom), (right, bottom + label_h), color, -1)

            role = known_roles.get(name, "")
            label = f"{name}  {role}  {conf*100:.0f}%"
            cv2.putText(frame, label, (left + 6, bottom + 15),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.42, (255, 255, 255), 1, cv2.LINE_AA)

            # Status badge top-right of box
            badge = "AUTH" if status == "authorized" else "DENY"
            badge_color = COLOR_AUTHORIZED if status == "authorized" else COLOR_UNAUTHORIZED
            cv2.putText(frame, badge, (right - 48, top - 6),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.42, badge_color, 1, cv2.LINE_AA)

        # ── FPS ───────────────────────────────────────────────────────────
        now = time.time()
        fps = 0.9 * fps + 0.1 * (1.0 / max(now - fps_timer, 1e-6))
        fps_timer = now
        stats["fps"] = fps

        # ── HUD panel ────────────────────────────────────────────────────
        draw_hud(frame, stats)

        cv2.imshow(WINDOW_TITLE, frame)

        # ── Key handling ─────────────────────────────────────────────────
        key = cv2.waitKey(1) & 0xFF
        if key == ord("q"):
            break
        elif key == ord("r"):
            known_encodings, known_names, known_roles = load_known_faces(KNOWN_FACES_DIR)
            print("[INFO] Faces reloaded.")
        elif key == ord("s"):
            fname = f"screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            cv2.imwrite(fname, frame)
            print(f"[INFO] Screenshot saved: {fname}")

    cap.release()
    cv2.destroyAllWindows()
    print("\n[INFO] Network Guardian shut down. Access log saved to", ACCESS_LOG_FILE)


if __name__ == "__main__":
    main()
