#!/usr/bin/env python3
"""Resilient ADB shell with auto-reconnect and pacing. Usage: acmd2.py 'cmd1' 'cmd2'"""
import sys, time
from adb_shell.adb_device import AdbDeviceTcp
import adb_shell.auth.sign_pythonrsa as signmod

BANNER = b'\x00'  # minimal banner reduces some vendor parser quirks

def connect():
    signer = signmod.PythonRSASigner(
        open('/home/user/.android/adbkey.pub').read().strip(),
        open('/home/user/.android/adbkey.pk8').read())
    d = AdbDeviceTcp('10.42.0.55', 5555)
    d.connect(rsa_keys=[signer], auth_timeout_s=20)
    return d

def main():
    d = connect()
    for cmd in sys.argv[1:]:
        for attempt in range(4):
            try:
                out = d.shell(cmd, timeout_s=120)
                print('$', cmd)
                print(out)
                break
            except Exception as e:
                print('[retry %d for: %s (%s)]' % (attempt+1, cmd[:60], type(e).__name__), file=sys.stderr)
                time.sleep(6)
                try: d.close()
                except Exception: pass
                d = connect()

if __name__ == '__main__':
    main()
