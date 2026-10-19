# Specimen: a mini VirusTotal

A web app that scans an uploaded file without ever running it and returns a risk-scored report.

## What it checks
- MD5 / SHA-1 / SHA-256 hashes
- Real file type from magic bytes (catches an .exe renamed to .jpg)
- Shannon entropy (packed or encrypted data scores near 8.0)
- Strings: URLs, IP addresses, suspicious keywords
- Windows PE analysis: risky API imports, high-entropy sections (pefile)
- ClamAV signatures (if `clamscan` is installed)
- YARA rules in `rules/sample.yar` (if yara-python is installed)
- VirusTotal hash lookup (if `VT_API_KEY` is set)
- A combined 0-100 score: Clean (<30), Suspicious (30-69), Malicious (70+)

ClamAV, YARA and VirusTotal are optional. The app works without them and says so in the report.

## Run it
```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install flask pefile            # add yara-python for YARA
python app.py                       # open http://127.0.0.1:5000
```
Optional extras:
```bash
sudo apt install clamav && sudo freshclam   # ClamAV
export VT_API_KEY=your_key                  # free key from virustotal.com
```
Or with Docker: `docker build -t specimen . && docker run -p 5000:5000 specimen`

## Test safely
Save this single line as `eicar.txt` (a harmless test string every antivirus flags on purpose) and upload it:
```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
Also try renaming any `.exe` to `.jpg` and uploading it.
For real malware samples, use MalwareBazaar inside an isolated VM only.

## Safety
- Uploaded files are read as bytes, never executed, and deleted right after the scan.
- 20 MB upload limit. Keep the app on localhost, or inside Docker with auth and rate limits before exposing it.

## Ideas for next steps
URL/domain scanning (URLhaus, AbuseIPDB), user accounts, more YARA rules, CAPE sandbox, background job queue.

## Deploy on Render
1. Push this folder to a GitHub repository (the folder contents must be at the repo root).
2. On render.com: New + > Blueprint (or Web Service) > connect the repo.
3. If you choose Web Service: Build `pip install -r requirements.txt`, Start `gunicorn app:app --bind 0.0.0.0:$PORT --timeout 120`.
4. Optional: add an environment variable `VT_API_KEY` to enable VirusTotal lookups.
5. Open the `.onrender.com` link Render gives you.

Notes: on the free plan the app sleeps when idle (first load is slow) and scan history resets on redeploy.
ClamAV and YARA are not installed on Render's Python runtime, so reports show them as "not installed".
