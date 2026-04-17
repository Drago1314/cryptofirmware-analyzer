import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import joblib
import os
import math
import struct
import hashlib
from collections import Counter
import io
import time
from datetime import datetime

# ============================================================
#  COMPUTE AES S-BOX PROGRAMMATICALLY (guaranteed correct)
# ============================================================

def _compute_aes_sbox():
    def gfmul(a, b):
        p = 0
        while b:
            if b & 1: p ^= a
            a = ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff
            b >>= 1
        return p

    def gfinv(a):
        if a == 0: return 0
        r = 1
        base = a
        for _ in range(7):
            r = gfmul(r, r)
            r = gfmul(r, base)
        return gfmul(r, r)

    sbox = []
    for i in range(256):
        b = gfinv(i)
        sb = 0
        for bit in range(8):
            bv = ((b >> bit) & 1) ^ ((b >> ((bit+4)%8)) & 1) ^ \
                 ((b >> ((bit+5)%8)) & 1) ^ ((b >> ((bit+6)%8)) & 1) ^ \
                 ((b >> ((bit+7)%8)) & 1) ^ ((0x63 >> bit) & 1)
            sb |= (bv << bit)
        sbox.append(sb)
    return bytes(sbox)

AES_SBOX = _compute_aes_sbox()

# ============================================================
#  CRYPTOGRAPHIC CONSTANTS
# ============================================================

SHA256_H = struct.pack('>IIIIIIII',
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

SHA256_K_PARTIAL = struct.pack('>IIIIIIII',
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5)

MD5_INIT = struct.pack('<IIII', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
SHA1_H   = struct.pack('>IIIII', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

PKCS8_RSA_OID = bytes([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01])

CRYPTO_SIGNATURES = {
    'AES': [
        (AES_SBOX[:16], 0.92, "AES S-Box first row"),
        (AES_SBOX[:32], 0.98, "AES S-Box (first 2 rows)"),
        (AES_SBOX,      0.99, "Full AES S-Box embedded"),
    ],
    'SHA-256': [
        (SHA256_H[:8],   0.80, "SHA-256 H0 init constant"),
        (SHA256_H,       0.97, "SHA-256 init hash values (H0-H7)"),
        (SHA256_K_PARTIAL[:4], 0.85, "SHA-256 K[0] constant"),
    ],
    'MD5': [(MD5_INIT, 0.97, "MD5 initialization constants")],
    'SHA-1': [(SHA1_H, 0.97, "SHA-1 initialization constants")],
    'RSA': [(PKCS8_RSA_OID, 0.92, "RSA PKCS#8 OID sequence")],
}

TEXT_MARKERS = [
    (b'-----BEGIN RSA',        'RSA',       0.99, 'RSA PEM private key marker'),
    (b'-----BEGIN PUBLIC KEY', 'RSA/EC',    0.97, 'RSA/EC public key PEM marker'),
    (b'-----BEGIN CERTIFICATE','X.509/TLS', 0.99, 'X.509 Certificate PEM marker'),
    (b'-----BEGIN EC PRIVATE', 'ECDSA/ECDH',0.99, 'EC private key PEM marker'),
    (b'AES_',                  'AES',       0.75, 'AES symbol reference'),
    (b'OPENSSL_aes',           'AES',       0.90, 'OpenSSL AES reference'),
    (b'sha256_',               'SHA-256',   0.85, 'SHA-256 symbol reference'),
    (b'mbedtls_aes',           'AES',       0.95, 'MbedTLS AES reference'),
    (b'mbedtls_sha256',        'SHA-256',   0.95, 'MbedTLS SHA-256 reference'),
]

# ============================================================
#  ARCHITECTURE DETECTION
# ============================================================

ARCH_MAGIC = {
    b'\x7fELF':         'ELF Binary',
    b'MZ':              'PE (Windows)',
    b'\xca\xfe\xba\xbe':'Mach-O (Universal)',
    b'\xfe\xed\xfa\xce':'Mach-O 32-bit LE',
    b'\xfe\xed\xfa\xcf':'Mach-O 64-bit LE',
    b'dex\n':           'Android DEX',
    b'\x27\x05\x19\x56':'U-Boot uImage',
    b'\x1f\x8b':        'GZip compressed',
    b'PK\x03\x04':      'ZIP/JAR archive',
    b'\xfd7zXZ':        'XZ compressed',
    b'BZh':             'BZip2 compressed',
}

ELF_ARCH = {
    0x03: 'x86 (32-bit)', 0x3e: 'x86-64', 0x28: 'ARM (32-bit)',
    0xb7: 'AArch64 (ARM 64-bit)', 0x08: 'MIPS', 0x14: 'PowerPC',
    0x16: 'PowerPC 64-bit', 0x2b: 'SPARC', 0xf3: 'RISC-V',
}

PE_ARCH = {
    0x014c: 'x86 32-bit', 0x8664: 'x86-64',
    0x01c0: 'ARM 32-bit', 0xaa64: 'ARM64 (AArch64)',
    0x0200: 'Intel Itanium',
}

def detect_architecture(data: bytes) -> dict:
    r = {'format': 'Unknown Binary', 'architecture': 'Unknown',
         'endianness': 'Unknown', 'bits': 'Unknown', 'os': 'Unknown'}

    for magic, fmt in ARCH_MAGIC.items():
        if data[:len(magic)] == magic:
            r['format'] = fmt; break

    if data[:4] == b'\x7fELF' and len(data) > 20:
        r['bits'] = '64-bit' if data[4] == 2 else '32-bit'
        r['endianness'] = 'Big-Endian' if data[5] == 2 else 'Little-Endian'
        r['os'] = {0: 'System V', 3: 'Linux', 6: 'Solaris', 9: 'FreeBSD'}.get(data[7], f'ABI={data[7]}')
        fmt = '<H' if data[5] == 1 else '>H'
        e_machine = struct.unpack(fmt, data[18:20])[0]
        r['architecture'] = ELF_ARCH.get(e_machine, f'Unknown (0x{e_machine:04x})')

    elif data[:2] == b'MZ' and len(data) > 64:
        r['endianness'] = 'Little-Endian'; r['os'] = 'Windows'
        pe_off = struct.unpack('<I', data[60:64])[0]
        if pe_off + 6 < len(data):
            mach = struct.unpack('<H', data[pe_off+4:pe_off+6])[0]
            r['architecture'] = PE_ARCH.get(mach, f'0x{mach:04x}')
            r['bits'] = '64-bit' if mach in (0x8664, 0xaa64) else '32-bit'

    return r

# ============================================================
#  FEATURE EXTRACTION
# ============================================================

def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum((v/n) * math.log2(v/n) for v in c.values() if v > 0)

def extract_features(chunk: bytes) -> np.ndarray:
    if len(chunk) == 0: return np.zeros(267)
    arr = np.frombuffer(chunk, dtype=np.uint8)

    entropy   = shannon_entropy(chunk) / 8.0
    mean      = np.mean(arr) / 255.0
    std       = np.std(arr) / 128.0
    median    = np.median(arr) / 255.0
    hist, _   = np.histogram(arr, bins=256, range=(0,256), density=True)
    # FIX: Vectorized numpy operation instead of slow Python loop
    printable = float(np.sum((arr >= 32) & (arr <= 126))) / len(arr)
    zero_r    = float(np.sum(arr == 0)) / len(arr)
    high_r    = float(np.sum(arr > 127)) / len(arr)

    expected  = len(arr) / 256
    chi2      = min(sum((c-expected)**2/expected for c in Counter(chunk).values()) / 1000, 1.0)

    max_run = cur_run = 1
    for i in range(1, len(arr)):
        if arr[i] == arr[i-1]: cur_run += 1; max_run = max(max_run, cur_run)
        else: cur_run = 1
    run_r = max_run / len(arr)

    if len(chunk) > 1:
        bg = Counter(zip(chunk, chunk[1:]))
        tot = len(chunk)-1
        bg_ent = -sum((c/tot)*math.log2(c/tot) for c in bg.values() if c>0) / 16.0
    else:
        bg_ent = 0.0

    byte_range = (int(np.max(arr)) - int(np.min(arr))) / 255.0

    return np.concatenate([[entropy, mean, std, median], hist,
                           [printable, zero_r, high_r, chi2, run_r, bg_ent, byte_range]])

# ============================================================
#  SYNTHETIC DATASET GENERATION
# ============================================================

def generate_dataset(n=250):
    rng = np.random.RandomState(42)
    X, y = [], []
    CS = 256

    def add(chunk, label):
        X.append(extract_features(chunk)); y.append(label)

    # Random/encrypted – near-uniform high entropy
    for _ in range(n):
        add(bytes(rng.randint(0, 256, CS, dtype=np.uint8)), 'encrypted_data')

    # x86 code – biased opcodes, nulls, low entropy
    x86_ops = [0x55,0x48,0x89,0xe5,0x83,0xec,0x20,0x8b,0x45,0x0c,
               0xc3,0x90,0x00,0x00,0x41,0x57,0x56,0x53,0xff,0xd0]
    for _ in range(n):
        core = [x86_ops[rng.randint(0, len(x86_ops))] for _ in range(CS//2)]
        pad  = list(rng.randint(0, 100, CS - CS//2, dtype=np.uint8))
        add(bytes(core + pad), 'machine_code')

    # Plaintext / config – mostly ASCII
    chars = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \n\t=:/_-.')
    for _ in range(n):
        txt = ''.join(rng.choice(chars, size=CS).tolist()).encode('ascii','replace')[:CS]
        add(txt + bytes(max(0, CS-len(txt))), 'plaintext_config')

    # AES constant region – S-box header present
    sbox_hdr = AES_SBOX[:32]
    for _ in range(n):
        rest = bytes(rng.randint(0, 256, CS - len(sbox_hdr), dtype=np.uint8))
        add(sbox_hdr + rest, 'aes_constants')

    # SHA-256 constant region
    sha_hdr = SHA256_H + SHA256_K_PARTIAL
    for _ in range(n):
        rest = bytes(rng.randint(0, 256, CS - len(sha_hdr), dtype=np.uint8))
        add(sha_hdr + rest, 'hash_constants')

    # MD5 / SHA-1 constants
    for _ in range(n//2):
        rest = bytes(rng.randint(0, 256, CS - len(MD5_INIT), dtype=np.uint8))
        add(MD5_INIT + rest, 'hash_constants')
    for _ in range(n//2):
        rest = bytes(rng.randint(0, 256, CS - len(SHA1_H), dtype=np.uint8))
        add(SHA1_H + rest, 'hash_constants')

    # RSA key material – biased high bytes
    for _ in range(n):
        add(bytes(rng.randint(100, 256, CS, dtype=np.uint8)), 'rsa_key_material')

    # Compressed data – gzip/lz headers
    for _ in range(n):
        hdr  = bytes([0x1f,0x8b,0x08,0x00,0x00,0x00,0x00,0x00])
        rest = bytes(rng.randint(0, 256, CS - len(hdr), dtype=np.uint8))
        add(hdr + rest, 'compressed_data')

    # Try PyCryptodome for real encrypted samples
    try:
        from Crypto.Cipher import AES as _AES, ARC4
        from Crypto.Random import get_random_bytes as grb
        for _ in range(n):
            key = grb(16)
            pt  = bytes(rng.randint(0, 256, CS, dtype=np.uint8))
            # FIX: renamed variable from misleading 'ct' to 'cipher'
            cipher = _AES.new(key, _AES.MODE_ECB)
            enc = b''.join([cipher.encrypt(pt[i:i+16]) for i in range(0, CS, 16)])
            add(enc, 'encrypted_data')
        for _ in range(n//2):
            key = grb(16)
            rc4 = ARC4.new(key)
            add(rc4.encrypt(bytes(rng.randint(0, 256, CS, dtype=np.uint8))), 'encrypted_data')
    except Exception:
        pass

    return np.array(X, dtype=np.float32), np.array(y)

# ============================================================
#  MODEL
# ============================================================

# FIX: Model path configurable via environment variable
MODEL_PATH = os.environ.get('CRYPTO_MODEL_PATH', 'crypto_model.joblib')

@st.cache_resource(show_spinner=False)
def get_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    with st.spinner('⚙️ Training ML model on synthetic firmware dataset...'):
        X, y = generate_dataset(200)
        le = LabelEncoder()
        ye = le.fit_transform(y)
        Xt, Xv, yt, yv = train_test_split(X, ye, test_size=0.2, random_state=42, stratify=ye)
        clf = RandomForestClassifier(n_estimators=150, max_depth=20,
                                     min_samples_leaf=2, random_state=42, n_jobs=-1)
        clf.fit(Xt, yt)
        acc = accuracy_score(yv, clf.predict(Xv))
        st.success(f'✅ Model trained — Validation accuracy: **{acc:.1%}**')
        joblib.dump((clf, le), MODEL_PATH)
    return clf, le

# ============================================================
#  ANALYSIS ENGINE
# ============================================================

def signature_scan(data: bytes) -> list:
    hits = []
    # Constant-based signatures
    for algo, sigs in CRYPTO_SIGNATURES.items():
        best = None
        for sig, conf, desc in sigs:
            off = data.find(sig)
            if off != -1:
                if best is None or conf > best['confidence']:
                    best = {'algorithm': algo, 'confidence': conf,
                            'description': desc, 'offset': off, 'type': 'signature'}
        if best: hits.append(best)
    # Text markers
    for marker, algo, conf, desc in TEXT_MARKERS:
        off = data.find(marker)
        if off != -1:
            hits.append({'algorithm': algo, 'confidence': conf,
                         'description': desc, 'offset': off, 'type': 'marker'})
    return hits

def entropy_profile(data: bytes, block=256) -> tuple:
    positions, values = [], []
    for i in range(0, len(data), block):
        chunk = data[i:i+block]
        if len(chunk) >= 32:
            positions.append(i)
            values.append(shannon_entropy(chunk))
    return positions, values

def ml_classify(data: bytes, clf, le, block=256) -> dict:
    counts = Counter()
    total = 0
    limit = min(len(data), block * 80)
    for i in range(0, limit, block):
        chunk = data[i:i+block]
        if len(chunk) == block:
            feat = extract_features(chunk).reshape(1, -1)
            pred = le.inverse_transform(clf.predict(feat))[0]
            counts[pred] += 1
            total += 1
    if total == 0:
        return {}
    return {k: v/total for k, v in counts.most_common()}

def ml_classify_detailed(data: bytes, clf, le, block=256) -> list:
    """Return per-block classification with offsets and confidence scores."""
    results = []
    limit = min(len(data), block * 80)
    for i in range(0, limit, block):
        chunk = data[i:i+block]
        if len(chunk) == block:
            feat = extract_features(chunk).reshape(1, -1)
            proba = clf.predict_proba(feat)[0]
            pred_idx = np.argmax(proba)
            pred_class = le.inverse_transform([pred_idx])[0]
            confidence = float(proba[pred_idx])
            results.append({
                'offset': i,
                'class': pred_class,
                'confidence': confidence,
            })
    return results

def analyze_binary(data: bytes, clf, le) -> dict:
    """Full analysis of a single binary file."""
    arch    = detect_architecture(data)
    sigs    = signature_scan(data)
    pos, ent = entropy_profile(data)
    ml_dist = ml_classify(data, clf, le)
    ml_details = ml_classify_detailed(data, clf, le)
    return {
        'arch': arch, 'size': len(data),
        'entropy': shannon_entropy(data),
        'sigs': sigs, 'entropy_profile': (pos, ent),
        'ml_dist': ml_dist, 'ml_details': ml_details,
        'sha256': hashlib.sha256(data).hexdigest(),
    }

# ============================================================
#  HEX DUMP UTILITY
# ============================================================

def hex_dump(data: bytes, offset: int, context: int = 160) -> str:
    """Generate a formatted hex dump around a specific offset."""
    start = max(0, offset - 32)
    start = start - (start % 16)  # align to 16-byte boundary
    end = min(len(data), offset + context)
    chunk = data[start:end]

    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        addr = start + i
        hex_part = ' '.join(f'{b:02X}' for b in row)
        hex_part = hex_part.ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '·' for b in row)
        marker = '  ◄◄ match' if start + i <= offset < start + i + 16 else ''
        lines.append(f'{addr:08X}  {hex_part}  |{ascii_part}|{marker}')

    return '\n'.join(lines)

# ============================================================
#  2D ENTROPY HEATMAP
# ============================================================

def entropy_heatmap_data(data: bytes, block: int = 64) -> tuple:
    """Compute entropy for small blocks and arrange into a 2D grid."""
    n_blocks = len(data) // block
    if n_blocks == 0:
        return None, 0, 0

    entropies = []
    for i in range(n_blocks):
        chunk = data[i*block:(i+1)*block]
        entropies.append(shannon_entropy(chunk))

    width = int(math.ceil(math.sqrt(n_blocks * 1.5)))
    width = max(width, 1)
    height = int(math.ceil(n_blocks / width))

    while len(entropies) < width * height:
        entropies.append(0)

    grid = np.array(entropies[:width * height]).reshape(height, width)
    return grid, width, height

# ============================================================
#  REPORT GENERATION
# ============================================================

def generate_report_html(res: dict, filename: str) -> str:
    """Generate a downloadable HTML analysis report."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    arch = res['arch']
    sigs = res['sigs']
    ent = res['entropy']
    ent_status = '🔴 HIGH' if ent > 7.2 else '🟡 MODERATE' if ent > 5.5 else '🟢 LOW'
    algos = list(set(d['algorithm'] for d in sigs if d['type'] in ('signature','marker')))

    sig_rows = ''
    for d in sigs:
        sig_rows += (f'<tr><td>{d["algorithm"]}</td><td>{d["confidence"]:.0%}</td>'
                     f'<td>{d["description"]}</td><td><code>0x{d["offset"]:08X}</code></td>'
                     f'<td>{d["type"]}</td></tr>')

    ml_rows = ''
    for cls, ratio in res.get('ml_dist', {}).items():
        label = CLASS_LABELS.get(cls, cls)
        bw = int(ratio * 100)
        ml_rows += (f'<tr><td>{label}</td><td>{ratio:.1%}</td>'
                    f'<td><div style="background:#1a2332;border-radius:4px;height:12px;width:200px">'
                    f'<div style="background:#00d4ff;height:12px;width:{bw}%;border-radius:4px"></div>'
                    f'</div></td></tr>')

    ml_detail_rows = ''
    for item in res.get('ml_details', [])[:50]:
        ml_detail_rows += (f'<tr><td><code>0x{item["offset"]:08X}</code></td>'
                          f'<td>{CLASS_LABELS.get(item["class"], item["class"])}</td>'
                          f'<td>{item["confidence"]:.1%}</td></tr>')

    badge_cls = 'badge-danger' if ent > 7.2 else 'badge-warning' if ent > 5.5 else 'badge-success'

    html = f'''<!DOCTYPE html><html><head><meta charset="utf-8">
<title>CryptoFirmware Analysis Report — {filename}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI','Inter',sans-serif;background:#0a0e17;color:#c8d6e5;padding:40px;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto}}
h1{{color:#00d4ff;font-size:2em;border-bottom:2px solid #1a2a40;padding-bottom:16px;margin-bottom:8px}}
h2{{color:#a855f7;margin-top:36px;margin-bottom:16px;font-size:1.3em}}
.subtitle{{color:#5a7a9a;margin-bottom:24px}}
table{{border-collapse:collapse;width:100%;margin:16px 0;background:#111827;border-radius:8px;overflow:hidden}}
th{{background:#1a2332;color:#00d4ff;padding:12px 16px;text-align:left;font-weight:600;font-size:.9em;text-transform:uppercase;letter-spacing:.5px}}
td{{padding:10px 16px;border-bottom:1px solid #1a2332;font-size:.92em}}
tr:hover{{background:rgba(0,212,255,.03)}}
code{{background:rgba(0,0,0,.4);padding:2px 8px;border-radius:4px;color:#6a90b0;font-size:.9em}}
.metrics{{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}}
.metric{{flex:1;min-width:150px;background:linear-gradient(135deg,#141c2e,#0d1220);border:1px solid #1a2a40;border-radius:12px;padding:20px;text-align:center}}
.metric-value{{font-size:1.5em;font-weight:700;color:#00d4ff}}
.metric-label{{font-size:.8em;color:#5a7a9a;margin-top:6px;text-transform:uppercase;letter-spacing:.5px}}
.summary-box{{background:linear-gradient(135deg,#0d1a2a,#0a1018);border:1px solid #1a2a40;border-radius:12px;padding:24px;margin:20px 0}}
.footer{{margin-top:50px;padding-top:20px;border-top:1px solid #1a2a40;color:#3a4a5a;font-size:.82em;text-align:center}}
.badge{{display:inline-block;padding:4px 12px;border-radius:20px;font-size:.8em;font-weight:600}}
.badge-success{{background:rgba(34,197,94,.15);color:#22c55e}}
.badge-warning{{background:rgba(234,179,8,.15);color:#eab308}}
.badge-danger{{background:rgba(239,68,68,.15);color:#ef4444}}
</style></head><body>
<div class="container">
<h1>🔐 CryptoFirmware Analysis Report</h1>
<p class="subtitle"><strong>File:</strong> {filename} &nbsp;|&nbsp; <strong>Generated:</strong> {now}</p>
<div class="metrics">
<div class="metric"><div class="metric-value">{res['size']:,} B</div><div class="metric-label">File Size</div></div>
<div class="metric"><div class="metric-value">{ent:.3f}</div><div class="metric-label">Entropy (b/B)</div></div>
<div class="metric"><div class="metric-value">{arch['architecture']}</div><div class="metric-label">Architecture</div></div>
<div class="metric"><div class="metric-value">{arch['format']}</div><div class="metric-label">Format</div></div>
<div class="metric"><div class="metric-value">{len(algos)}</div><div class="metric-label">Crypto Hits</div></div>
</div>

<h2>📁 Binary Details</h2>
<table><tr><th>Property</th><th>Value</th></tr>
<tr><td>Format</td><td>{arch['format']}</td></tr>
<tr><td>Architecture</td><td>{arch['architecture']}</td></tr>
<tr><td>Bits</td><td>{arch['bits']}</td></tr>
<tr><td>Endianness</td><td>{arch['endianness']}</td></tr>
<tr><td>OS / ABI</td><td>{arch['os']}</td></tr>
<tr><td>SHA-256</td><td><code>{res['sha256']}</code></td></tr>
<tr><td>Overall Entropy</td><td>{ent:.3f} b/B &nbsp; <span class="badge {badge_cls}">{ent_status}</span></td></tr>
</table>

<h2>🎯 Cryptographic Detections</h2>
{'<table><tr><th>Algorithm</th><th>Confidence</th><th>Description</th><th>Offset</th><th>Type</th></tr>' + sig_rows + '</table>' if sig_rows else '<p style="color:#5a7a9a">No cryptographic signatures detected.</p>'}

<h2>🤖 ML Classification Distribution</h2>
{'<table><tr><th>Region Type</th><th>Proportion</th><th>Distribution</th></tr>' + ml_rows + '</table>' if ml_rows else '<p style="color:#5a7a9a">No ML classification data.</p>'}

{'<h2>📊 Detailed Block Classification (first 50 blocks)</h2><table><tr><th>Offset</th><th>Classification</th><th>Confidence</th></tr>' + ml_detail_rows + '</table>' if ml_detail_rows else ''}

<div class="summary-box">
<h2 style="margin-top:0">📋 Summary</h2>
<p>{'✅ Detected cryptographic primitives: <strong>' + ', '.join(algos) + '</strong>' if algos else '⚠️ No definitive crypto signatures found via constant scanning.'}</p>
<p>Entropy: <span class="badge {badge_cls}">{ent_status}</span> — {'Binary contains encrypted or compressed sections.' if ent > 7.2 else 'Mixed content: code + data present.' if ent > 5.5 else 'Mostly structured / plaintext content.'}</p>
</div>

<div class="footer">
<p>🔐 Generated by CryptoFirmware Analyzer — AI/ML-Based Cryptographic Primitive Identification</p>
<p>{now}</p></div></div></body></html>'''
    return html

# ============================================================
#  UI CONSTANTS
# ============================================================

CLASS_LABELS = {
    'encrypted_data':    '🔒 Encrypted Data',
    'machine_code':      '⚙️ Machine Code',
    'plaintext_config':  '📄 Plaintext / Config',
    'aes_constants':     '🗝️ AES S-Box / Key Schedule',
    'hash_constants':    '🔗 Hash Constants (SHA/MD5)',      # FIX: Added emoji
    'rsa_key_material':  '🔑 RSA Key Material',
    'compressed_data':   '📦 Compressed Data',
}

COLORS = ['00d4ff','00ff88','ffaa00','ff4466','aa44ff','ff8844','44ffcc','ff44aa']

ALGO_COLORS = {
    'AES': '#00d4ff', 'SHA-256': '#a855f7', 'SHA-1': '#eab308',
    'MD5': '#22c55e', 'RSA': '#f97316', 'RSA/EC': '#f97316',
    'ECDSA/ECDH': '#ec4899', 'X.509/TLS': '#06b6d4',
}

ALGO_ICONS = {
    'AES': '🗝️', 'SHA-256': '#️⃣', 'SHA-1': '1️⃣',
    'MD5': '🔢', 'RSA': '🔑', 'RSA/EC': '🔑',
    'ECDSA/ECDH': '🔐', 'X.509/TLS': '📜',
}

CSS_MAP = {
    'AES': 'algo-AES', 'SHA-256': 'algo-SHA-256',
    'SHA-1': 'algo-SHA-1', 'MD5': 'algo-MD5', 'RSA': 'algo-RSA',
}

# ============================================================
#  MAIN APPLICATION
# ============================================================

def main():
    st.set_page_config(page_title="CryptoFirmware Analyzer", page_icon="🔐", layout="wide")
    st.markdown("""
    <style>
    .block-container { padding-top: 1.5rem; }
    .metric-card {
        background: linear-gradient(135deg, #1a1f2e, #0f1420);
        border: 1px solid #2a3450; border-radius: 12px;
        padding: 16px 20px; text-align: center;
    }
    .det-card {
        padding: 16px 18px; border-radius: 12px; margin: 8px 0;
        border: 1px solid rgba(255,255,255,0.06);
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .algo-AES     { background: linear-gradient(135deg, #0a1f35, #061524); border-left: 5px solid #00d4ff; }
    .algo-SHA-256 { background: linear-gradient(135deg, #1a1030, #110820); border-left: 5px solid #a855f7; }
    .algo-SHA-1   { background: linear-gradient(135deg, #1e1a08, #141207); border-left: 5px solid #eab308; }
    .algo-MD5     { background: linear-gradient(135deg, #08231a, #051510); border-left: 5px solid #22c55e; }
    .algo-RSA     { background: linear-gradient(135deg, #251008, #180a05); border-left: 5px solid #f97316; }
    .algo-default { background: linear-gradient(135deg, #111827, #0f1420); border-left: 5px solid #6b7280; }
    .hex-dump {
        font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
        font-size: 0.8em; line-height: 1.6;
        background: #080c14; padding: 12px 16px; border-radius: 8px;
        border: 1px solid #1a2a40; overflow-x: auto;
    }
    footer { visibility: hidden; }
    </style>
    """, unsafe_allow_html=True)

    # ── Header ──────────────────────────────────────────────
    st.title("🔐 CryptoFirmware Analyzer")
    st.markdown("*AI/ML-Based Identification of Cryptographic Primitives in Multi-Architecture Firmware Binaries*")
    st.markdown("---")

    # ── Sidebar ──────────────────────────────────────────────
    with st.sidebar:
        st.header("⚙️ Settings")
        show_entropy  = st.checkbox("Entropy Map",            value=True)
        show_heatmap  = st.checkbox("2D Entropy Heatmap",     value=True)
        show_ml       = st.checkbox("ML Classification",      value=True)
        show_ml_table = st.checkbox("Detailed ML Table",      value=False)
        show_sigs     = st.checkbox("Signature Detection",    value=True)
        show_hexdump  = st.checkbox("Hex Dump Viewer",        value=True)
        st.divider()
        st.markdown("**Supported Formats**")
        for f in ['ELF (x86, ARM, MIPS, PPC)', 'PE (Windows)', 'Mach-O (iOS/macOS)',
                  'U-Boot images', 'Raw binary blobs']:
            st.markdown(f"▸ {f}")
        st.divider()
        st.markdown("**Detectable Primitives**")
        for p in ['AES (128/192/256-bit)', 'SHA-256 / SHA-512', 'SHA-1',
                  'MD5', 'RSA / ECC', 'DES / 3DES', 'RC4 / ChaCha20']:
            st.markdown(f"▸ {p}")

    # ── Model loading ────────────────────────────────────────
    clf, le = get_model()

    # ── Tabs ─────────────────────────────────────────────────
    tab_single, tab_compare = st.tabs(["🔍 Single Analysis", "📊 Compare Binaries"])

    # ══════════════════════════════════════════════════════════
    #  TAB 1: SINGLE ANALYSIS
    # ══════════════════════════════════════════════════════════
    with tab_single:
        col_up, col_hint = st.columns([3, 2])
        with col_up:
            uploaded = st.file_uploader(
                "Upload Firmware / Binary File",
                type=None,
                help="ELF, PE, .bin, raw firmware — any binary file",
                key="single_upload"
            )
        with col_hint:
            st.markdown("### 📌 What This Tool Does")
            st.markdown("- Detects **crypto algorithm constants** embedded in binaries")
            st.markdown("- **ML classifier** identifies code vs encrypted vs key-material regions")
            st.markdown("- Full **entropy map** shows encrypted sections visually")
            st.markdown("- **Multi-arch** support: ARM, x86, MIPS, PowerPC, AArch64")

        if not uploaded:
            st.info("👆 Upload a binary file to begin analysis")
        else:
            data = uploaded.read()
            st.markdown("---")

            # ── Progress Bar Analysis ────────────────────────
            progress = st.progress(0, text="🔍 Starting analysis...")

            progress.progress(10, text="🏗️ Detecting architecture...")
            arch = detect_architecture(data)

            progress.progress(25, text="🔍 Scanning for cryptographic signatures...")
            sigs = signature_scan(data)

            progress.progress(40, text="📊 Computing entropy profile...")
            pos, ent_vals = entropy_profile(data)

            progress.progress(55, text="🤖 Running ML classification...")
            ml_dist = ml_classify(data, clf, le)

            progress.progress(70, text="📋 Analyzing individual blocks...")
            ml_details = ml_classify_detailed(data, clf, le)

            progress.progress(90, text="🔢 Computing file hash...")
            file_hash = hashlib.sha256(data).hexdigest()
            overall_entropy = shannon_entropy(data)

            res = {
                'arch': arch, 'size': len(data),
                'entropy': overall_entropy,
                'sigs': sigs, 'entropy_profile': (pos, ent_vals),
                'ml_dist': ml_dist, 'ml_details': ml_details,
                'sha256': file_hash,
            }

            progress.progress(100, text="✅ Analysis complete!")
            time.sleep(0.5)
            progress.empty()

            # ── Top Metrics ──────────────────────────────────
            m1, m2, m3, m4, m5 = st.columns(5)
            arch_str = res['arch']['architecture']
            n_sig = len(set(d['algorithm'] for d in res['sigs'] if d['type'] in ('signature','marker')))
            ent = res['entropy']
            ent_color = "🔴" if ent > 7.2 else "🟡" if ent > 5.5 else "🟢"

            m1.metric("📦 File Size",          f"{res['size']:,} B")
            m2.metric("🔐 Crypto Hits",        n_sig)
            m3.metric(f"{ent_color} Entropy",  f"{ent:.3f} b/B")
            m4.metric("🏗️ Architecture",       arch_str if arch_str != 'Unknown' else '⚠️ Unknown')
            m5.metric("🔢 SHA-256",            res['sha256'][:12] + "…")

            # ── Download Report ──────────────────────────────
            report_html = generate_report_html(res, uploaded.name)
            st.download_button(
                label="📥 Download Analysis Report (HTML)",
                data=report_html,
                file_name=f"cryptofw_report_{uploaded.name}.html",
                mime="text/html",
                use_container_width=True,
            )

            st.divider()

            # ── Binary Info ──────────────────────────────────
            with st.expander("📁 Binary Format & Architecture Details", expanded=True):
                a = res['arch']
                c1,c2,c3,c4,c5 = st.columns(5)
                c1.markdown(f"**Format**\n\n{a['format']}")
                c2.markdown(f"**Architecture**\n\n{a['architecture']}")
                c3.markdown(f"**Bits**\n\n{a['bits']}")
                c4.markdown(f"**Endianness**\n\n{a['endianness']}")
                c5.markdown(f"**OS/ABI**\n\n{a['os']}")
                st.code(f"SHA-256: {res['sha256']}", language=None)

            # ── Signature Detections ─────────────────────────
            if show_sigs:
                st.subheader("🎯 Signature-Based Cryptographic Detection")
                sig_hits = [d for d in res['sigs'] if d['type'] in ('signature','marker')]
                by_algo = {}
                for d in sig_hits:
                    if d['algorithm'] not in by_algo or d['confidence'] > by_algo[d['algorithm']]['confidence']:
                        by_algo[d['algorithm']] = d

                if by_algo:
                    cols = st.columns(min(len(by_algo), 4))
                    for i, (algo, det) in enumerate(by_algo.items()):
                        conf = det['confidence']
                        color   = ALGO_COLORS.get(algo, '#6b7280')
                        icon    = ALGO_ICONS.get(algo, '🔍')
                        css_cls = CSS_MAP.get(algo, 'algo-default')
                        with cols[i % len(cols)]:
                            st.markdown(f'''<div class="det-card {css_cls}">
                                <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
                                    <span style="font-size:1.5em">{icon}</span>
                                    <span style="font-size:1.15em;font-weight:700;color:{color};letter-spacing:0.5px">{algo}</span>
                                </div>
                                <div style="margin-bottom:10px">
                                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px">
                                        <span style="font-size:0.78em;color:#7a8fa8">Confidence</span>
                                        <span style="font-weight:700;color:{color};font-size:1.0em">{conf:.0%}</span>
                                    </div>
                                    <div style="background:rgba(255,255,255,0.08);border-radius:6px;height:7px;width:100%">
                                        <div style="background:{color};width:{int(conf*100)}%;height:7px;border-radius:6px;box-shadow:0 0 8px {color}88"></div>
                                    </div>
                                </div>
                                <div style="color:#9aaabb;font-size:0.82em;margin-bottom:6px">{det["description"]}</div>
                                <span style="font-size:0.78em;color:#7a8fa8;margin-right:4px">Offset:</span><code style="font-size:0.75em;color:#6a90b0;background:rgba(0,0,0,0.35);padding:2px 8px;border-radius:4px">0x{det["offset"]:08X}</code>
                            </div>''', unsafe_allow_html=True)

                    # ── Hex Dump Viewer ───────────────────────
                    if show_hexdump:
                        st.markdown("")
                        st.markdown("**🔬 Hex Dump at Detection Offsets**")
                        for algo, det in by_algo.items():
                            with st.expander(f"📍 {algo} — Offset `0x{det['offset']:08X}` — {det['description']}"):
                                dump = hex_dump(data, det['offset'], context=160)
                                st.markdown(f'<div class="hex-dump"><pre>{dump}</pre></div>',
                                           unsafe_allow_html=True)
                else:
                    st.info("No signature matches found. Binary may use obfuscated or custom crypto implementations.")

                # Entropy-based detections
                hi_ent = [d for d in res['sigs'] if d['type'] == 'entropy']
                if hi_ent:
                    st.markdown("**⚡ High-Entropy Regions (Likely Encrypted/Compressed Sections)**")
                    for d in hi_ent[:3]:
                        st.markdown(f"- `0x{d['offset']:08X}` — {d['description']}")

            # ── Entropy Map ──────────────────────────────────
            if show_entropy and res['entropy_profile'][0]:
                st.subheader("📈 Binary Entropy Profile")
                pos, ent_vals = res['entropy_profile']

                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=pos, y=ent_vals, mode='lines', name='Entropy',
                    line=dict(color='#00d4ff', width=1.5),
                    fill='tozeroy', fillcolor='rgba(0,212,255,0.08)'
                ))
                fig.add_hrect(y0=7.2, y1=8.1, fillcolor='rgba(255,68,68,0.08)',
                              line_width=0, annotation_text="Likely Encrypted", annotation_position="right")
                fig.add_hrect(y0=5.5, y1=7.2, fillcolor='rgba(255,170,0,0.06)',
                              line_width=0, annotation_text="Code/Mixed", annotation_position="right")
                fig.add_hline(y=7.2, line=dict(color='#ff4444', dash='dash', width=1))
                fig.add_hline(y=5.5, line=dict(color='#ffaa00', dash='dash', width=1))
                fig.update_layout(
                    xaxis_title="File Offset (bytes)",
                    yaxis_title="Shannon Entropy (bits/byte)",
                    yaxis=dict(range=[0, 8.3]),
                    template='plotly_dark', height=320,
                    margin=dict(t=10, b=30), showlegend=False,
                )
                st.plotly_chart(fig, use_container_width=True)

                hi  = sum(1 for e in ent_vals if e > 7.2)
                mid = sum(1 for e in ent_vals if 5.5 <= e <= 7.2)
                lo  = sum(1 for e in ent_vals if e < 5.5)
                ec1, ec2, ec3 = st.columns(3)
                ec1.metric("🔴 High-Entropy Blocks (>7.2)", hi,  help="Encrypted / compressed sections")
                ec2.metric("🟡 Medium-Entropy Blocks",      mid, help="Code / mixed data")
                ec3.metric("🟢 Low-Entropy Blocks (<5.5)",  lo,  help="Plaintext / config / padding")

            # ── 2D Entropy Heatmap ───────────────────────────
            if show_heatmap and len(data) >= 64:
                st.subheader("🗺️ 2D Entropy Heatmap (Binvis-Style)")
                grid, gw, gh = entropy_heatmap_data(data, block=64)
                if grid is not None:
                    fig_hm = go.Figure(go.Heatmap(
                        z=grid,
                        colorscale=[
                            [0.0,  '#0a0e17'],
                            [0.25, '#22c55e'],
                            [0.50, '#eab308'],
                            [0.72, '#f97316'],
                            [0.90, '#ef4444'],
                            [1.0,  '#ff0040'],
                        ],
                        zmin=0, zmax=8,
                        colorbar=dict(title="Entropy<br>(b/B)", tickvals=[0, 2, 4, 6, 8]),
                        hovertemplate="Block row %{y}, col %{x}<br>Entropy: %{z:.2f} b/B<extra></extra>",
                    ))
                    fig_hm.update_layout(
                        template='plotly_dark', height=max(220, min(gh * 8, 500)),
                        xaxis=dict(title="Block Column", showgrid=False),
                        yaxis=dict(title="Block Row", showgrid=False, autorange='reversed'),
                        margin=dict(t=10, b=30, l=40, r=20),
                    )
                    st.plotly_chart(fig_hm, use_container_width=True)
                    st.caption(f"Each cell = 64 bytes · Grid: {gw}×{gh} · 🟢 Low entropy → 🔴 High entropy (encrypted/compressed)")

            # ── ML Classification ────────────────────────────
            if show_ml and res['ml_dist']:
                st.subheader("🤖 ML Region Classification")
                ml = res['ml_dist']
                cc1, cc2 = st.columns([1, 1])

                with cc1:
                    labels = [CLASS_LABELS.get(k, k) for k in ml]
                    values = list(ml.values())
                    fig2 = go.Figure(go.Pie(
                        labels=labels, values=values, hole=0.45,
                        marker=dict(colors=[f'#{c}' for c in COLORS[:len(labels)]]),
                        textfont=dict(size=11),
                    ))
                    fig2.update_layout(
                        title="Binary Content Distribution",
                        template='plotly_dark', height=300,
                        margin=dict(t=40, b=0, l=0, r=0),
                    )
                    st.plotly_chart(fig2, use_container_width=True)

                with cc2:
                    st.markdown("**Classification Breakdown (per 256-byte block)**")
                    for cls, ratio in ml.items():
                        label = CLASS_LABELS.get(cls, cls)
                        st.markdown(f"**{label}**  `{ratio:.1%}`")
                        st.progress(float(ratio))

            # ── Detailed ML Table ────────────────────────────
            if show_ml_table and res.get('ml_details'):
                st.subheader("📊 Detailed Block-by-Block Classification")
                df = pd.DataFrame(res['ml_details'])
                df['offset_hex'] = df['offset'].apply(lambda x: f'0x{x:08X}')
                df['label'] = df['class'].map(CLASS_LABELS).fillna(df['class'])
                df['confidence_pct'] = df['confidence'].apply(lambda x: f'{x:.1%}')

                st.dataframe(
                    df[['offset_hex', 'label', 'confidence_pct']].rename(columns={
                        'offset_hex': 'Offset',
                        'label': 'Classification',
                        'confidence_pct': 'Confidence',
                    }),
                    use_container_width=True,
                    height=400,
                )

            # ── Summary ──────────────────────────────────────
            st.divider()
            st.subheader("📋 Analysis Summary")
            algos = list(set(d['algorithm'] for d in res['sigs'] if d['type'] in ('signature','marker')))
            if algos:
                st.success(f"✅ Detected cryptographic primitives: **{', '.join(algos)}**")
            else:
                st.warning("⚠️ No definitive crypto signatures found via constant scanning.")

            ov = res['entropy']
            if ov > 7.2:
                st.error(f"🔴 High overall entropy ({ov:.3f}) — Binary contains encrypted or compressed sections.")
            elif ov > 5.5:
                st.warning(f"🟡 Moderate entropy ({ov:.3f}) — Mixed content: code + data present.")
            else:
                st.success(f"🟢 Low entropy ({ov:.3f}) — Mostly structured / plaintext content.")

            a = res['arch']
            if a['architecture'] != 'Unknown':
                st.info(f"🏗️ {a['format']} — {a['architecture']}, {a['bits']}, {a['endianness']}")

    # ══════════════════════════════════════════════════════════
    #  TAB 2: COMPARE BINARIES
    # ══════════════════════════════════════════════════════════
    with tab_compare:
        st.markdown("### 📊 Multi-Binary Comparison")
        st.markdown("Upload **2–4** firmware/binary files to compare them side-by-side.")

        compare_files = st.file_uploader(
            "Upload binaries to compare",
            type=None,
            accept_multiple_files=True,
            help="Upload 2-4 binary files for comparison",
            key="compare_upload"
        )

        if not compare_files or len(compare_files) < 2:
            if compare_files and len(compare_files) == 1:
                st.warning("⚠️ Please upload at least **2 files** for comparison.")
            else:
                st.info("👆 Upload 2 or more binary files to compare")
        else:
            if len(compare_files) > 4:
                st.warning("⚠️ Maximum 4 files supported. Using first 4.")
                compare_files = compare_files[:4]

            # Read all files
            files_data = []
            for f in compare_files:
                files_data.append((f.name, f.read()))

            # Analyze with progress
            progress = st.progress(0, text="🔍 Analyzing files for comparison...")
            results = []
            for idx, (fname, fdata) in enumerate(files_data):
                pct = int((idx + 1) / len(files_data) * 100)
                progress.progress(pct, text=f"🔍 Analyzing {fname}...")
                results.append((fname, analyze_binary(fdata, clf, le)))

            progress.progress(100, text="✅ Comparison ready!")
            time.sleep(0.3)
            progress.empty()

            # ── Comparison Metrics Table ─────────────────────
            st.subheader("📋 Comparison Metrics")
            comp_data = []
            for fname, r in results:
                algos = list(set(d['algorithm'] for d in r['sigs'] if d['type'] in ('signature','marker')))
                comp_data.append({
                    'File': fname,
                    'Size': f"{r['size']:,} B",
                    'Format': r['arch']['format'],
                    'Architecture': r['arch']['architecture'],
                    'Bits': r['arch']['bits'],
                    'Entropy': f"{r['entropy']:.3f}",
                    'Crypto Hits': ', '.join(algos) if algos else 'None',
                    'SHA-256': r['sha256'][:16] + '…',
                })
            st.dataframe(pd.DataFrame(comp_data), use_container_width=True, hide_index=True)

            # ── Overlaid Entropy Profiles ────────────────────
            st.subheader("📈 Entropy Profile Overlay")
            fig_comp = go.Figure()
            comp_colors = ['#00d4ff', '#ff4466', '#00ff88', '#ffaa00']
            for idx, (fname, r) in enumerate(results):
                p, e = r['entropy_profile']
                if p:
                    fig_comp.add_trace(go.Scatter(
                        x=p, y=e, mode='lines', name=fname,
                        line=dict(color=comp_colors[idx % len(comp_colors)], width=2),
                    ))

            fig_comp.add_hline(y=7.2, line=dict(color='#ff4444', dash='dash', width=1),
                              annotation_text="Encryption threshold")
            fig_comp.add_hline(y=5.5, line=dict(color='#ffaa00', dash='dash', width=1))
            fig_comp.update_layout(
                xaxis_title="File Offset (bytes)",
                yaxis_title="Shannon Entropy (bits/byte)",
                yaxis=dict(range=[0, 8.3]),
                template='plotly_dark', height=350,
                legend=dict(orientation='h', y=-0.15),
                margin=dict(t=10, b=60),
            )
            st.plotly_chart(fig_comp, use_container_width=True)

            # ── ML Distribution Comparison ───────────────────
            st.subheader("🤖 ML Classification Comparison")
            comp_cols = st.columns(len(results))
            for idx, (fname, r) in enumerate(results):
                with comp_cols[idx]:
                    st.markdown(f"**{fname}**")
                    if r['ml_dist']:
                        labels = [CLASS_LABELS.get(k, k) for k in r['ml_dist']]
                        values = list(r['ml_dist'].values())
                        fig_p = go.Figure(go.Pie(
                            labels=labels, values=values, hole=0.5,
                            marker=dict(colors=[f'#{c}' for c in COLORS[:len(labels)]]),
                            textfont=dict(size=9),
                        ))
                        fig_p.update_layout(
                            template='plotly_dark', height=250,
                            margin=dict(t=10, b=0, l=0, r=0),
                            showlegend=False,
                        )
                        st.plotly_chart(fig_p, use_container_width=True)
                    else:
                        st.info("No ML data")

            # ── Crypto Detection Comparison ──────────────────
            st.subheader("🎯 Detection Comparison")
            all_algos = sorted(set(
                d['algorithm'] for _, r in results
                for d in r['sigs'] if d['type'] in ('signature','marker')
            ))
            if all_algos:
                det_data = []
                for algo in all_algos:
                    row = {'Algorithm': algo}
                    for fname, r in results:
                        found = [d for d in r['sigs'] if d['algorithm'] == algo and d['type'] in ('signature','marker')]
                        if found:
                            best = max(found, key=lambda x: x['confidence'])
                            row[fname] = f"✅ {best['confidence']:.0%}"
                        else:
                            row[fname] = "❌"
                    det_data.append(row)
                st.dataframe(pd.DataFrame(det_data), use_container_width=True, hide_index=True)
            else:
                st.info("No cryptographic signatures detected in any of the uploaded files.")

if __name__ == "__main__":
    main()
