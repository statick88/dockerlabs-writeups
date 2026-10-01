#!/usr/bin/env python3
"""Minimal SSH runner for lab 169. Prints stdout/stderr and exit status."""
import sys, paramiko

host, user, pw = sys.argv[1], sys.argv[2], sys.argv[3]
cmd = sys.argv[4]
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(host, username=user, password=pw, timeout=15, banner_timeout=15, auth_timeout=15)
i, o, e = c.exec_command(cmd, timeout=30)
out = o.read().decode(errors="replace")
err = e.read().decode(errors="replace")
print(out, end="")
if err.strip():
    print("STDERR:", err, file=sys.stderr)
print(f"[exit={o.channel.recv_exit_status()}]")
c.close()