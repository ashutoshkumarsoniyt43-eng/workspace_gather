"""Gather team workspace: small, local-first Python/SQLite application server."""
from __future__ import annotations

import hashlib
import html
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "gather.sqlite3"
PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("GATHER_HOST", "127.0.0.1")
DEFAULT_ADMIN_EMAIL = "ashutosh@lockin.com"
DEFAULT_ADMIN_PASSWORD = "ashuonly"
SESSION_DAYS = 7
MAX_UPLOAD = 20 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "txt", "md", "csv", "json", "js", "ts", "jsx", "tsx", "py", "html", "css", "sql", "java", "go", "rs", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png", "jpg", "jpeg", "gif", "webp", "zip"}
KINDS = {"tasks", "reminders", "meetings", "updates", "goals"}

class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()

def connect():
    DATA_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=15, factory=ClosingConnection)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db

def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return salt.hex() + ":" + digest.hex()

def password_matches(password: str, stored: str) -> bool:
    try:
        salt, expected = stored.split(":", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310_000).hex()
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, avatar_path TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner_id TEXT NOT NULL REFERENCES users(id), data TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS records_kind_created ON records(kind, created_at DESC);
        CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id), filename TEXT NOT NULL, stored_name TEXT NOT NULL, size INTEGER NOT NULL, content_type TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "avatar_path" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN avatar_path TEXT NOT NULL DEFAULT ''")
        db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('workspace_name','Studio North')")
        admin_email = os.environ.get("GATHER_ADMIN_EMAIL", DEFAULT_ADMIN_EMAIL).strip().lower()
        admin_password = os.environ.get("GATHER_ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
        if not db.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
            db.execute("INSERT INTO users(id,name,email,password,role,active,created_at) VALUES(?,?,?,?,?,?,?)", ("user-admin", os.environ.get("GATHER_ADMIN_NAME", "Ashutosh"), admin_email, password_hash(admin_password), "admin", 1, datetime.now(timezone.utc).isoformat()))
        else:
            legacy = db.execute("SELECT id FROM users WHERE email='admin@studionorth.local'").fetchone()
            if legacy:
                db.execute("UPDATE users SET name='Ashutosh',email=?,password=? WHERE id=?", (admin_email, password_hash(admin_password), legacy["id"]))
            db.execute("UPDATE users SET name='Ashutosh' WHERE email=? AND name='Riya Shah'", (admin_email,))

def now_iso():
    return datetime.now(timezone.utc).isoformat()

class Handler(BaseHTTPRequestHandler):
    server_version = "GatherWorkspace/1.0"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def send_json(self, value, status=200, headers=None):
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        if headers:
            for key, val in headers.items(): self.send_header(key, val)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_000_000: raise ValueError("That request is too large.")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def user(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        morsel = jar.get("gather_session")
        if not morsel: return None
        token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
        with connect() as db:
            row = db.execute("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1", (token_hash, time.time())).fetchone()
            if row: return dict(row)
        return None

    def require_user(self):
        user = self.user()
        if not user:
            self.send_json({"error": "Please sign in to continue."}, 401)
        return user

    def same_origin(self):
        origin = self.headers.get("Origin")
        if not origin: return True
        return urlparse(origin).netloc == self.headers.get("Host")

    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        if path == "/api/health": return self.send_json({"ok": True})
        if path == "/api/me":
            user = self.user()
            return self.send_json({"user": self.public_user(user) if user else None})
        if path == "/api/bootstrap":
            user = self.require_user()
            if not user: return
            with connect() as db:
                team = [self.public_user(r) for r in db.execute("SELECT * FROM users WHERE active=1 ORDER BY created_at")]
                records = {k: [] for k in KINDS}
                for row in db.execute("SELECT * FROM records ORDER BY created_at DESC"):
                    if row["kind"] in records:
                        records[row["kind"]].append({**json.loads(row["data"]), "id": row["id"], "owner_id": row["owner_id"], "created_at": row["created_at"]})
                files = [dict(r) for r in db.execute("SELECT id,owner_id,filename,size,content_type,description,created_at FROM files ORDER BY created_at DESC")]
                workspace = {r["key"]: r["value"] for r in db.execute("SELECT key,value FROM settings")}
            return self.send_json({"user": self.public_user(user), "team": team, "workspace": workspace, **records, "files": files})
        if path.startswith("/api/avatar/"):
            viewer = self.require_user()
            if not viewer: return
            avatar_id = path.rsplit("/", 1)[-1]
            with connect() as db: row = db.execute("SELECT avatar_path FROM users WHERE id=? AND active=1", (avatar_id,)).fetchone()
            if not row or not row["avatar_path"]: return self.send_json({"error": "Profile photo not found."}, 404)
            target = UPLOAD_DIR / row["avatar_path"]
            if not target.is_file(): return self.send_json({"error": "Profile photo not found."}, 404)
            body = target.read_bytes(); ctype = mimetypes.guess_type(target.name)[0] or "image/jpeg"
            self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "private, no-store"); self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(body); return
        if (path.startswith("/api/files/") and path.endswith("/download")) or path == "/api/file-download":
            user = self.require_user()
            if not user: return
            file_id = parse_qs(urlparse(self.path).query).get("id", [""])[0] if path == "/api/file-download" else path.split("/")[3]
            with connect() as db: row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
            if not row: return self.send_json({"error": "File not found."}, 404)
            target = UPLOAD_DIR / row["stored_name"]
            if not target.is_file(): return self.send_json({"error": "File is no longer available."}, 404)
            body = target.read_bytes()
            filename = re.sub(r"[^A-Za-z0-9._ -]", "_", row["filename"]).replace('"', "")[:160]
            self.send_response(200)
            self.send_header("Content-Type", row["content_type"] or "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "private, no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers(); self.wfile.write(body); return
        if path.startswith("/api/"):
            return self.send_json({"error": "Not found."}, 404)
        return self.serve_static(path)

    @staticmethod
    def public_user(user):
        if not user: return None
        user = dict(user)
        return {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"], "active": bool(user["active"]), "avatar": f"/api/avatar/{user['id']}" if user.get("avatar_path") else ""}

    def serve_static(self, path):
        rel = "index.html" if path == "/" else path.lstrip("/")
        if rel not in {"index.html", "styles.css", "theme.css", "app.js"}: return self.send_json({"error": "Not found."}, 404)
        target = (ROOT / rel).resolve()
        if ROOT not in target.parents and target != ROOT: return self.send_json({"error": "Not found."}, 404)
        if target == DATA_DIR or DATA_DIR in target.parents: return self.send_json({"error": "Not found."}, 404)
        if not target.is_file(): return self.send_json({"error": "Not found."}, 404)
        body = target.read_bytes()
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200); self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith(("text/", "application/javascript")) else "")); self.send_header("Content-Length", str(len(body))); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; img-src 'self' data: https://images.unsplash.com; connect-src 'self'; frame-ancestors 'none'"); self.end_headers(); self.wfile.write(body)

    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        if not self.same_origin(): return self.send_json({"error": "Request origin was rejected."}, 403)
        if path == "/api/login": return self.login()
        if path == "/api/logout":
            jar = cookies.SimpleCookie(self.headers.get("Cookie", "")); morsel = jar.get("gather_session")
            if morsel:
                with connect() as db: db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(morsel.value.encode()).hexdigest(),))
            return self.send_json({"ok": True}, headers={"Set-Cookie": "gather_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
        if path == "/api/change-password":
            user = self.require_user()
            if not user: return
            try: data = self.read_json()
            except Exception: return self.send_json({"error": "Please enter valid details."}, 400)
            old, new = str(data.get("old_password", "")), str(data.get("new_password", ""))
            if not password_matches(old, user["password"]): return self.send_json({"error": "Your current password does not match."}, 400)
            if len(new) < 10: return self.send_json({"error": "Use at least 10 characters for your new password."}, 400)
            with connect() as db: db.execute("UPDATE users SET password=? WHERE id=?", (password_hash(new), user["id"])); db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
            return self.send_json({"ok": True}, headers={"Set-Cookie": "gather_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
        if path == "/api/invite": return self.invite()
        if path == "/api/settings": return self.update_settings()
        if path == "/api/profile-photo": return self.profile_photo()
        if path == "/api/upload": return self.upload()
        reset_match = re.fullmatch(r"/api/members/([\w-]+)/reset-password", path)
        if reset_match: return self.reset_password(reset_match.group(1))
        match = re.fullmatch(r"/api/(tasks|reminders|meetings|updates|goals)", path)
        if match: return self.create_record(match.group(1))
        return self.send_json({"error": "Not found."}, 404)

    def login(self):
        try: data = self.read_json()
        except Exception: return self.send_json({"error": "Please enter your email and password."}, 400)
        email = str(data.get("email", "")).strip().lower(); password = str(data.get("password", ""))
        with connect() as db: user = db.execute("SELECT * FROM users WHERE email=? AND active=1", (email,)).fetchone()
        if not user or not password_matches(password, user["password"]):
            return self.send_json({"error": "Those sign-in details didn’t work. Check them and try again."}, 401)
        token = secrets.token_urlsafe(40); digest = hashlib.sha256(token.encode()).hexdigest(); expiry = time.time() + SESSION_DAYS * 86400
        with connect() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<?", (time.time(),))
            db.execute("INSERT INTO sessions VALUES(?,?,?)", (digest, user["id"], expiry))
        cookie = f"gather_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_DAYS * 86400}"
        if os.environ.get("HTTPS", "").lower() in {"1", "true"}: cookie += "; Secure"
        return self.send_json({"user": self.public_user(user)}, headers={"Set-Cookie": cookie})

    def invite(self):
        admin = self.require_user()
        if not admin: return
        if admin["role"] != "admin": return self.send_json({"error": "Only admins can invite team members."}, 403)
        try: data = self.read_json()
        except Exception: return self.send_json({"error": "Please enter valid details."}, 400)
        name = str(data.get("name", "")).strip()[:80]; email = str(data.get("email", "")).strip().lower(); password = str(data.get("password", ""))
        if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): return self.send_json({"error": "Enter a name and valid email address."}, 400)
        if len(password) < 10: return self.send_json({"error": "Set a temporary password with at least 10 characters."}, 400)
        try:
            with connect() as db: db.execute("INSERT INTO users(id,name,email,password,role,active,created_at) VALUES(?,?,?,?,?,?,?)", ("user-"+uuid.uuid4().hex[:14], name, email, password_hash(password), "member", 1, now_iso()))
        except sqlite3.IntegrityError: return self.send_json({"error": "That email already has workspace access."}, 409)
        return self.send_json({"ok": True}, 201)

    def reset_password(self, member_id):
        admin = self.require_user()
        if not admin: return
        if admin["role"] != "admin": return self.send_json({"error": "Only admins can reset team passwords."}, 403)
        try: data = self.read_json()
        except Exception: return self.send_json({"error": "Please enter a new password."}, 400)
        password = str(data.get("password", ""))
        if len(password) < 10: return self.send_json({"error": "Use at least 10 characters for the new password."}, 400)
        with connect() as db:
            cur = db.execute("UPDATE users SET password=? WHERE id=? AND role!='admin'", (password_hash(password), member_id))
            db.execute("DELETE FROM sessions WHERE user_id=?", (member_id,))
        if not cur.rowcount: return self.send_json({"error": "That team member was not found."}, 404)
        return self.send_json({"ok": True})

    def update_settings(self):
        admin = self.require_user()
        if not admin: return
        if admin["role"] != "admin": return self.send_json({"error": "Only admins can manage workspace settings."}, 403)
        try: data = self.read_json()
        except Exception: return self.send_json({"error": "Please enter a workspace name."}, 400)
        name = str(data.get("workspace_name", "")).strip()[:80]
        if not name: return self.send_json({"error": "Workspace name can’t be empty."}, 400)
        with connect() as db: db.execute("INSERT INTO settings(key,value) VALUES('workspace_name',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (name,))
        return self.send_json({"workspace_name": name})

    def create_record(self, kind):
        user = self.require_user()
        if not user: return
        try: data = self.read_json()
        except Exception: return self.send_json({"error": "Please enter valid details."}, 400)
        clean = {k: v for k, v in data.items() if k in {"title", "description", "notes", "due", "assignee", "status", "priority", "visibility", "date", "time", "attendees", "meet_link", "completed", "body", "progress", "label"}}
        if kind in {"tasks", "reminders", "meetings", "goals"} and not str(clean.get("title", "")).strip(): return self.send_json({"error": "A title is required."}, 400)
        if kind == "meetings" and clean.get("meet_link"):
            link = str(clean["meet_link"])
            if not re.match(r"^https://", link): return self.send_json({"error": "Meeting links must use https."}, 400)
        rid = "rec-" + uuid.uuid4().hex[:14]; created = now_iso()
        with connect() as db: db.execute("INSERT INTO records VALUES(?,?,?,?,?)", (rid, kind, user["id"], json.dumps(clean, ensure_ascii=False), created))
        return self.send_json({"id": rid, "owner_id": user["id"], "created_at": created, **clean}, 201)

    def upload(self):
        user = self.require_user()
        if not user: return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_UPLOAD + 1_000_000: return self.send_json({"error": "Files must be smaller than 20 MB."}, 413)
        raw = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")
        try:
            message = BytesParser(policy=policy.default).parsebytes((f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + raw))
            fields = {}
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                if name == "file": fields["file"] = (part.get_filename() or "upload.bin", part.get_payload(decode=True) or b"", part.get_content_type())
                elif name == "description": fields[name] = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            filename, blob, mime = fields["file"]
        except Exception: return self.send_json({"error": "Choose a file to upload."}, 400)
        extension = Path(filename).suffix.lower().lstrip(".")
        if extension not in ALLOWED_EXTENSIONS: return self.send_json({"error": "That file type is not supported."}, 400)
        if len(blob) > MAX_UPLOAD: return self.send_json({"error": "Files must be smaller than 20 MB."}, 413)
        safe_name = Path(filename).name[:180]
        stored = uuid.uuid4().hex + "." + extension
        (UPLOAD_DIR / stored).write_bytes(blob)
        fid = "file-" + uuid.uuid4().hex[:14]; created = now_iso()
        with connect() as db: db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?)", (fid, user["id"], safe_name, stored, len(blob), mime, str(fields.get("description", ""))[:300], created))
        return self.send_json({"id": fid, "owner_id": user["id"], "filename": safe_name, "size": len(blob), "content_type": mime, "description": str(fields.get("description", ""))[:300], "created_at": created}, 201)

    def profile_photo(self):
        user = self.require_user()
        if not user: return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 5 * 1024 * 1024 + 500_000: return self.send_json({"error": "Profile photos must be smaller than 5 MB."}, 413)
        raw = self.rfile.read(length)
        try:
            message = BytesParser(policy=policy.default).parsebytes((f"Content-Type: {self.headers.get('Content-Type','')}\r\nMIME-Version: 1.0\r\n\r\n".encode() + raw))
            photo = next((part for part in message.iter_parts() if part.get_param("name", header="content-disposition") == "photo"), None)
            if photo is None: raise ValueError("Choose an image to upload.")
            filename = Path(photo.get_filename() or "profile.jpg").name
            blob = photo.get_payload(decode=True) or b""
            mime = photo.get_content_type()
        except Exception:
            return self.send_json({"error": "Choose a JPG, PNG, or WebP image."}, 400)
        extension = Path(filename).suffix.lower()
        supported = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}
        if extension not in supported or mime not in {supported.get(extension), "application/octet-stream"}:
            return self.send_json({"error": "Choose a JPG, PNG, or WebP image."}, 400)
        if not blob or len(blob) > 5 * 1024 * 1024: return self.send_json({"error": "Profile photos must be smaller than 5 MB."}, 413)
        stored = f"avatar-{uuid.uuid4().hex}.{extension.lstrip('.')}"
        (UPLOAD_DIR / stored).write_bytes(blob)
        with connect() as db:
            old = db.execute("SELECT avatar_path FROM users WHERE id=?", (user["id"],)).fetchone()
            db.execute("UPDATE users SET avatar_path=? WHERE id=?", (stored, user["id"]))
        if old and old["avatar_path"]:
            try: (UPLOAD_DIR / old["avatar_path"]).unlink(missing_ok=True)
            except OSError: pass
        user["avatar_path"] = stored
        return self.send_json({"user": self.public_user(user)})

    def do_PATCH(self):
        if not self.same_origin(): return self.send_json({"error": "Request origin was rejected."}, 403)
        path = unquote(urlparse(self.path).path)
        user = self.require_user()
        if not user: return
        if path == "/api/members" or path.startswith("/api/members/"):
            if user["role"] != "admin": return self.send_json({"error": "Only admins can manage team access."}, 403)
            member_id = path.rsplit("/",1)[1] if path != "/api/members" else parse_qs(urlparse(self.path).query).get("id", [""])[0]
            if member_id == user["id"]: return self.send_json({"error": "You can’t deactivate your own account."}, 400)
            try: data=self.read_json()
            except Exception: return self.send_json({"error":"Please enter valid details."},400)
            active = 1 if data.get("active") else 0
            with connect() as db: cur=db.execute("UPDATE users SET active=? WHERE id=? AND role!='admin'",(active,member_id)); db.execute("DELETE FROM sessions WHERE user_id=?",(member_id,)) if not active else None
            if not cur.rowcount: return self.send_json({"error":"That team member was not found."},404)
            return self.send_json({"ok":True})
        match = re.fullmatch(r"/api/(tasks|reminders|meetings|updates|goals)(?:/([\w-]+))?", path)
        if not match: return self.send_json({"error":"Not found."},404)
        kind,rid=match.groups()
        rid = rid or parse_qs(urlparse(self.path).query).get("id", [""])[0]
        try: patch=self.read_json()
        except Exception: return self.send_json({"error":"Please enter valid details."},400)
        if kind == "meetings" and patch.get("meet_link") and not str(patch["meet_link"]).startswith("https://"):
            return self.send_json({"error": "Meeting links must use https."}, 400)
        with connect() as db:
            row=db.execute("SELECT * FROM records WHERE id=? AND kind=?",(rid,kind)).fetchone()
            if not row: return self.send_json({"error":"That item was not found."},404)
            data=json.loads(row["data"]); data.update({k:v for k,v in patch.items() if k in {"title","description","notes","due","assignee","status","priority","visibility","date","time","attendees","meet_link","completed","body","progress","label"}})
            db.execute("UPDATE records SET data=? WHERE id=?",(json.dumps(data,ensure_ascii=False),rid))
        return self.send_json({"id":rid,"owner_id":row["owner_id"],"created_at":row["created_at"],**data})

    def do_DELETE(self):
        if not self.same_origin(): return self.send_json({"error":"Request origin was rejected."},403)
        path=unquote(urlparse(self.path).path); user=self.require_user()
        if not user:return
        match=re.fullmatch(r"/api/(tasks|reminders|meetings|updates|goals|files)(?:/([\w-]+))?",path)
        if not match:return self.send_json({"error":"Not found."},404)
        kind,rid=match.groups()
        rid = rid or parse_qs(urlparse(self.path).query).get("id", [""])[0]
        with connect() as db:
            table="files" if kind=="files" else "records"
            row=db.execute(f"SELECT owner_id{',stored_name' if kind=='files' else ''} FROM {table} WHERE id=?"+(" AND kind=?" if kind!="files" else ""),(rid,kind) if kind!="files" else (rid,)).fetchone()
            if not row:return self.send_json({"error":"That item was not found."},404)
            if kind in {"files", "updates"} and row["owner_id"]!=user["id"] and user["role"]!="admin":return self.send_json({"error":"Only the person who added this item or an admin can remove it."},403)
            db.execute(f"DELETE FROM {table} WHERE id=?"+(" AND kind=?" if kind!="files" else ""),(rid,kind) if kind!="files" else (rid,))
        if kind=="files":
            try:(UPLOAD_DIR/row["stored_name"]).unlink(missing_ok=True)
            except OSError:pass
        return self.send_json({"ok":True})

    def do_HEAD(self):
        return self.send_json({"ok":True})

if __name__ == "__main__":
    init_db()
    print(f"Gather workspace is ready at http://localhost:{PORT}")
    print("Set GATHER_ADMIN_EMAIL and GATHER_ADMIN_PASSWORD before first start to configure the initial admin login.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
