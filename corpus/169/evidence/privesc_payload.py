#!/usr/bin/env python3
# privesc witness: runs as root via sudo, reads the reward, writes nothing but proof.
import os, subprocess
print("PRIVESC-WITNESS uid=%d euid=%d user=%s" % (os.getuid(), os.geteuid(), subprocess.run(["id"],capture_output=True,text=True).stdout.strip()))
try:
    with open("/root/flag.txt","rb") as f:
        print("FLAG-BEGIN"); print(f.read().decode(errors="replace")); print("FLAG-END")
except Exception as e:
    print("flag read failed:", e)
