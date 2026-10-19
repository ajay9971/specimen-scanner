import json, os, sqlite3, tempfile, time
from collections import defaultdict, deque
from flask import Flask, redirect, render_template, request, url_for, abort
from werkzeug.utils import secure_filename
import scanner

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB upload limit
DB = os.environ.get("DB_PATH", "scans.db")
HITS = defaultdict(deque)


def limited(ip, limit=20, window=3600):
    """Allow `limit` scans per IP per hour (in-memory, resets on restart)."""
    now = time.time()
    q = HITS[ip]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY, sha256 TEXT, filename TEXT, size INTEGER,
        verdict TEXT, score INTEGER, report TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    return con


def home(error=None):
    with db() as con:
        recent = con.execute("SELECT id, filename, verdict, score, created FROM scans "
                             "ORDER BY id DESC LIMIT 10").fetchall()
    return render_template("index.html", recent=recent, error=error)


@app.get("/")
def index():
    return home()


@app.post("/scan")
def scan():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if limited(ip):
        return home("Rate limit reached: 20 scans per hour. Try again later."), 429
    f = request.files.get("file")
    if not f or not f.filename:
        return home("Choose a file to scan."), 400
    name = secure_filename(f.filename) or "upload"
    fd, tmp = tempfile.mkstemp(suffix=".sample")
    os.close(fd)
    try:
        f.save(tmp)
        rep = scanner.scan_file(tmp, name)
    finally:
        os.remove(tmp)  # the uploaded file is never kept or executed
    with db() as con:
        cur = con.execute("INSERT INTO scans(sha256, filename, size, verdict, score, report) "
                          "VALUES (?,?,?,?,?,?)",
                          (rep["hashes"]["sha256"], name, rep["size"], rep["verdict"],
                           rep["score"], json.dumps(rep)))
    return redirect(url_for("report", scan_id=cur.lastrowid))


@app.get("/report/<int:scan_id>")
def report(scan_id):
    with db() as con:
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        abort(404)
    return render_template("report.html", r=json.loads(row["report"]), scanned=row["created"])


@app.get("/lookup")
def lookup():
    q = request.args.get("q", "").strip().lower()
    with db() as con:
        row = con.execute("SELECT id FROM scans WHERE sha256=? ORDER BY id DESC LIMIT 1", (q,)).fetchone()
    if row:
        return redirect(url_for("report", scan_id=row["id"]))
    return home("No scan on record for that SHA-256. Upload the file to scan it."), 404


@app.errorhandler(413)
def too_big(_):
    return home("That file is over the 20 MB limit."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
