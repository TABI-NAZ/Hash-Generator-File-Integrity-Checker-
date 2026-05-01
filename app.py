from flask import Flask, render_template, request, jsonify
import hashlib
import hmac
import os
import time
import json
import math
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# ─── KNOWN SAFE HASHES (famous software) ───────────────────────────
KNOWN_SAFE = {
    # Python 3.12.0 installer SHA256 (example)
    "b8dd4d2e5946f3dc4e9b9a0a8b5d9f3e7c1a2b4d6e8f0a2c4e6f8a0b2d4e6f8": "Python 3.12.0 Installer",
}

# Known malware signatures (educational examples)
KNOWN_MALWARE = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Malware (MD5)",
    "cf8bd9dfddff007f75adf4c2be48005c": "Known Ransomware Signature",
    "e3b0c44298fc1c149afbf4c8996fb924": "Suspicious Empty Payload",
}

def compute_hashes(data: bytes) -> dict:
    return {
        "md5":      hashlib.md5(data).hexdigest(),
        "sha1":     hashlib.sha1(data).hexdigest(),
        "sha256":   hashlib.sha256(data).hexdigest(),
        "sha512":   hashlib.sha512(data).hexdigest(),
        "sha3_256": hashlib.sha3_256(data).hexdigest(),
        "blake2b":  hashlib.blake2b(data).hexdigest(),
    }

def compute_hmac(data: bytes, key: str) -> str:
    if not key:
        return ""
    return hmac.new(key.encode(), data, hashlib.sha256).hexdigest()

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def detect_file_type(filename: str, data: bytes) -> str:
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    magic = {
        b'\x89PNG': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'PK\x03\x04': 'ZIP Archive',
        b'\x1f\x8b': 'GZIP Archive',
        b'%PDF': 'PDF Document',
        b'MZ': 'Windows Executable',
        b'\x7fELF': 'Linux Executable',
        b'<!DOC': 'HTML Document',
        b'<?xml': 'XML Document',
    }
    for sig, ftype in magic.items():
        if data[:len(sig)] == sig:
            return ftype
    ext_map = {
        'py': 'Python Script', 'js': 'JavaScript', 'php': 'PHP Script',
        'txt': 'Text File', 'json': 'JSON File', 'csv': 'CSV File',
        'zip': 'ZIP Archive', 'pdf': 'PDF Document', 'exe': 'Executable',
        'sh': 'Shell Script', 'sql': 'SQL File', 'xml': 'XML File',
    }
    return ext_map.get(ext, 'Unknown File Type')

def check_threat_level(hashes: dict, entropy: float, filename: str) -> dict:
    threat = "CLEAN"
    reason = "No known threats detected"
    
    # Check malware DB
    for h in hashes.values():
        if h in KNOWN_MALWARE:
            return {"level": "DANGER", "reason": f"Known malware: {KNOWN_MALWARE[h]}"}
    
    # Check safe DB
    for h in hashes.values():
        if h in KNOWN_SAFE:
            return {"level": "VERIFIED", "reason": f"Verified safe: {KNOWN_SAFE[h]}"}
    
    # Entropy analysis
    if entropy > 7.5:
        threat = "SUSPICIOUS"
        reason = "Very high entropy — possible encrypted/packed malware"
    elif entropy > 6.8:
        threat = "WARNING"
        reason = "High entropy — possible compressed or encoded content"
    
    # Dangerous extensions
    dangerous_ext = ['exe', 'bat', 'cmd', 'vbs', 'ps1', 'jar', 'msi', 'dll']
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext in dangerous_ext and threat == "CLEAN":
        threat = "WARNING"
        reason = f"Executable file type (.{ext}) — verify source before running"
    
    return {"level": threat, "reason": reason}

def analyze_file(data: bytes, filename: str, hmac_key: str = "") -> dict:
    start = time.time()
    
    hashes = compute_hashes(data)
    entropy = shannon_entropy(data)
    file_type = detect_file_type(filename, data)
    threat = check_threat_level(hashes, entropy, filename)
    hmac_val = compute_hmac(data, hmac_key) if hmac_key else None
    
    # Strength ratings
    strength = {
        "md5":      {"rating": "Weak",   "bits": 128, "color": "danger", "note": "Cryptographically broken — collision attacks exist"},
        "sha1":     {"rating": "Weak",   "bits": 160, "color": "danger", "note": "Deprecated — collision demonstrated (SHAttered attack)"},
        "sha256":   {"rating": "Strong", "bits": 256, "color": "safe",   "note": "Industry standard — recommended for most uses"},
        "sha512":   {"rating": "Strong", "bits": 512, "color": "safe",   "note": "Maximum security — used in high-security systems"},
        "sha3_256": {"rating": "Strong", "bits": 256, "color": "safe",   "note": "Next-gen — resistant to length extension attacks"},
        "blake2b":  {"rating": "Strong", "bits": 512, "color": "safe",   "note": "Fastest secure hash — used in cryptocurrency"},
    }
    
    duration = round((time.time() - start) * 1000, 2)
    
    return {
        "filename": filename,
        "file_size": len(data),
        "file_size_fmt": f"{len(data)/1024:.2f} KB" if len(data) < 1024*1024 else f"{len(data)/(1024*1024):.2f} MB",
        "file_type": file_type,
        "scanned_at": datetime.now().strftime("%b %d, %Y at %H:%M:%S"),
        "duration_ms": duration,
        "hashes": hashes,
        "strength": strength,
        "entropy": entropy,
        "entropy_label": "High (suspicious)" if entropy > 6.8 else "Normal" if entropy > 3 else "Low",
        "threat": threat,
        "hmac": hmac_val,
        "byte_count": len(data),
        "unique_bytes": len(set(data)),
    }

# ─── TEXT HASHING ──────────────────────────────────────────────────
def hash_text(text: str) -> dict:
    data = text.encode('utf-8')
    hashes = compute_hashes(data)
    strength = {
        "md5":      {"rating": "Weak",   "bits": 128, "color": "danger", "note": "Cryptographically broken"},
        "sha1":     {"rating": "Weak",   "bits": 160, "color": "danger", "note": "Deprecated — SHAttered attack"},
        "sha256":   {"rating": "Strong", "bits": 256, "color": "safe",   "note": "Industry standard"},
        "sha512":   {"rating": "Strong", "bits": 512, "color": "safe",   "note": "Maximum security"},
        "sha3_256": {"rating": "Strong", "bits": 256, "color": "safe",   "note": "Next-gen Keccak"},
        "blake2b":  {"rating": "Strong", "bits": 512, "color": "safe",   "note": "Fastest secure hash"},
    }
    return {
        "input": text[:100] + ("..." if len(text) > 100 else ""),
        "length": len(text),
        "hashes": hashes,
        "strength": strength,
        "scanned_at": datetime.now().strftime("%b %d, %Y at %H:%M:%S"),
    }

# ─── INTEGRITY VERIFY ──────────────────────────────────────────────
def verify_integrity(data: bytes, filename: str, expected_hash: str, algorithm: str) -> dict:
    algos = {
        "md5": hashlib.md5, "sha1": hashlib.sha1,
        "sha256": hashlib.sha256, "sha512": hashlib.sha512,
        "sha3_256": hashlib.sha3_256, "blake2b": hashlib.blake2b,
    }
    fn = algos.get(algorithm.lower())
    if not fn:
        return {"error": "Unknown algorithm"}
    
    computed = fn(data).hexdigest()
    match = hmac.compare_digest(computed.lower(), expected_hash.lower().strip())
    
    return {
        "filename": filename,
        "algorithm": algorithm.upper(),
        "expected": expected_hash.lower().strip(),
        "computed": computed,
        "match": match,
        "file_size": f"{len(data)/1024:.2f} KB",
        "scanned_at": datetime.now().strftime("%b %d, %Y at %H:%M:%S"),
    }

# ─── ROUTES ────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/hash-file', methods=['POST'])
def hash_file_route():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        f = request.files['file']
        if not f.filename:
            return jsonify({"error": "No file selected"}), 400
        data = f.read()
        hmac_key = request.form.get('hmac_key', '')
        result = analyze_file(data, f.filename, hmac_key)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/hash-text', methods=['POST'])
def hash_text_route():
    try:
        body = request.json
        text = body.get('text', '')
        if not text:
            return jsonify({"error": "No text provided"}), 400
        return jsonify(hash_text(text))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verify', methods=['POST'])
def verify_route():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        f = request.files['file']
        data = f.read()
        expected = request.form.get('expected_hash', '').strip()
        algorithm = request.form.get('algorithm', 'sha256')
        if not expected:
            return jsonify({"error": "Please provide the expected hash"}), 400
        return jsonify(verify_integrity(data, f.filename, expected, algorithm))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/compare', methods=['POST'])
def compare_route():
    try:
        files = request.files.getlist('files')
        if len(files) < 2:
            return jsonify({"error": "Please upload at least 2 files to compare"}), 400
        
        results = []
        for f in files[:4]:  # max 4 files
            data = f.read()
            hashes = compute_hashes(data)
            results.append({
                "filename": f.filename,
                "size": f"{len(data)/1024:.2f} KB",
                "sha256": hashes["sha256"],
                "md5": hashes["md5"],
            })
        
        # Check if any files are identical
        sha256s = [r["sha256"] for r in results]
        identical_pairs = []
        for i in range(len(sha256s)):
            for j in range(i+1, len(sha256s)):
                if sha256s[i] == sha256s[j]:
                    identical_pairs.append([results[i]["filename"], results[j]["filename"]])
        
        return jsonify({
            "files": results,
            "identical_pairs": identical_pairs,
            "all_unique": len(identical_pairs) == 0,
            "scanned_at": datetime.now().strftime("%b %d, %Y at %H:%M:%S"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
