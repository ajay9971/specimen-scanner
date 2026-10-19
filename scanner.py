"""Static analysis engine. Files are only read as bytes and never executed."""
import hashlib, json, math, os, re, shutil, subprocess, urllib.error, urllib.request
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))

MAGIC = [
    (b"MZ", "exe"), (b"\x7fELF", "elf"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"),
    (b"\xff\xd8\xff", "jpg"), (b"\x89PNG", "png"), (b"GIF8", "gif"),
    (b"Rar!", "rar"), (b"\xd0\xcf\x11\xe0", "ole"),
]
EXEC_TYPES = {"exe", "elf"}
EXEC_EXT = {"exe", "dll", "sys", "scr", "so", "elf", "bin", "ocx", ""}
EXT_TYPE = {"jpg": "jpg", "jpeg": "jpg", "png": "png", "gif": "gif", "pdf": "pdf",
            "zip": "zip", "rar": "rar", "doc": "ole", "xls": "ole"}
RISKY_IMPORTS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookExA",
    "SetWindowsHookExW", "URLDownloadToFileA", "URLDownloadToFileW", "WinExec",
    "IsDebuggerPresent", "GetAsyncKeyState", "AdjustTokenPrivileges", "NtUnmapViewOfSection",
}
KEYWORDS = ["powershell", "cmd.exe", "wscript", "regsvr32", "mimikatz", "keylog", "ransom", "bitcoin"]


def hashes(data):
    return {n: hashlib.new(n, data).hexdigest() for n in ("md5", "sha1", "sha256")}


def detect_type(data):
    for sig, name in MAGIC:
        if data.startswith(sig):
            return name
    return "unknown/text"


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in Counter(data).values()), 2)


def extract_iocs(data):
    blob = b" ".join(re.findall(rb"[\x20-\x7e]{6,}", data[:5_000_000]))
    urls = sorted({u.decode(errors="ignore") for u in re.findall(rb"https?://[^\s\"'<>]+", blob)})[:25]
    ips = sorted({i.decode() for i in re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob)})[:25]
    low = blob.lower()
    words = [k for k in KEYWORDS if k.encode() in low]
    return {"urls": urls, "ips": ips, "keywords": words}


def analyze_pe(path):
    try:
        import pefile
    except ImportError:
        return {"available": False, "note": "pefile not installed"}
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        return {"available": True, "valid": False}
    imports = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name:
                imports.add(imp.name.decode(errors="ignore"))
    sections = [{"name": s.Name.rstrip(b"\x00").decode(errors="ignore"),
                 "entropy": round(s.get_entropy(), 2)} for s in pe.sections]
    return {"available": True, "valid": True, "import_count": len(imports),
            "risky_imports": sorted(imports & RISKY_IMPORTS), "sections": sections}


def clamav(path):
    exe = shutil.which("clamscan")
    if not exe:
        return {"available": False}
    try:
        r = subprocess.run([exe, "--no-summary", path], capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return {"available": True, "infected": False, "error": "timeout"}
    sig = None
    if r.returncode == 1 and "FOUND" in r.stdout:
        sig = r.stdout.split(":", 1)[1].replace("FOUND", "").strip()
    return {"available": True, "infected": r.returncode == 1, "signature": sig}


_rules = None
def yara_scan(path):
    global _rules
    try:
        import yara
    except ImportError:
        return {"available": False, "matches": []}
    if _rules is None:
        _rules = yara.compile(filepath=os.path.join(HERE, "rules", "sample.yar"))
    return {"available": True, "matches": [m.rule for m in _rules.match(path)]}


def virustotal(sha256):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return {"available": False}
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                 headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
        return {"available": True, "found": True, "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0), "total": sum(stats.values())}
    except urllib.error.HTTPError as e:
        return {"available": True, "found": False, "error": None if e.code == 404 else f"HTTP {e.code}"}
    except Exception as e:
        return {"available": True, "found": False, "error": str(e)}


def score(rep, filename):
    """Combine every signal into a 0-100 risk score with human-readable reasons."""
    s = []
    if rep["clamav"].get("infected"):
        s.append((100, f"ClamAV detected {rep['clamav'].get('signature')}"))
    if rep["yara"]["matches"]:
        s.append((60, "YARA rules matched: " + ", ".join(rep["yara"]["matches"])))
    vt = rep["virustotal"]
    if vt.get("found") and vt["malicious"] >= 5:
        s.append((100, f"VirusTotal: {vt['malicious']}/{vt['total']} engines flag this file"))
    elif vt.get("found") and vt["malicious"] > 0:
        s.append((25, f"VirusTotal: {vt['malicious']}/{vt['total']} engines flag this file"))
    ext = os.path.splitext(filename)[1].lower().lstrip(".")
    t = rep["type"]
    if t in EXEC_TYPES and ext not in EXEC_EXT:
        s.append((40, f"Executable disguised as .{ext}"))
    elif ext in EXT_TYPE and EXT_TYPE[ext] != t:
        s.append((15, f"Extension .{ext} does not match detected type ({t})"))
    if rep["entropy"] > 7.2 and rep["size"] > 2048:
        s.append((20, f"Very high entropy ({rep['entropy']}), possibly packed or encrypted"))
    pe = rep.get("pe", {})
    if pe.get("risky_imports"):
        s.append((min(10 * len(pe["risky_imports"]), 30), "Risky API imports: " + ", ".join(pe["risky_imports"])))
    packed = [x["name"] for x in pe.get("sections", []) if x["entropy"] > 7.2]
    if packed:
        s.append((15, "Packed sections: " + ", ".join(packed)))
    if rep["iocs"]["keywords"]:
        s.append((10, "Suspicious keywords: " + ", ".join(rep["iocs"]["keywords"])))
    total = min(sum(p for p, _ in s), 100)
    verdict = "Malicious" if total >= 70 else "Suspicious" if total >= 30 else "Clean"
    return total, verdict, [reason for _, reason in s]


def scan_file(path, filename):
    with open(path, "rb") as f:
        data = f.read()
    rep = {"filename": filename, "size": len(data), "hashes": hashes(data),
           "type": detect_type(data), "entropy": entropy(data), "iocs": extract_iocs(data),
           "clamav": clamav(path), "yara": yara_scan(path)}
    rep["pe"] = analyze_pe(path) if rep["type"] == "exe" else {}
    rep["virustotal"] = virustotal(rep["hashes"]["sha256"])
    rep["score"], rep["verdict"], rep["reasons"] = score(rep, filename)
    return rep
