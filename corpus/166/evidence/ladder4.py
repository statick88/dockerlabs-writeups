"""Rate ladder, keep-alive connections per worker.

Revision 4. Revision 3 opened a fresh TCP connection per candidate; after the
~22,500 connections of revisions 1-3 the HOST ran out of ephemeral ports
(28,261 sockets in TIME_WAIT against a 32768-60999 range) and every worker
above 4 raised `OSError: [Errno 99] Cannot assign requested address`. That is
the instrument failing, not the target refusing, and it is exactly the shape of
a false negative. Revision 4 holds one keep-alive connection per worker, which
is also what a real credential-attack tool does.
"""
import http.client, base64, time, sys, threading, collections, statistics

HOST = sys.argv[1]
MODE = sys.argv[2]
GATE = None if len(sys.argv) < 4 or sys.argv[3] == "none" else tuple(sys.argv[3].split(":", 1))
N    = 1200
USER = "httpadmin" if MODE == "basic" else "admin"

def make_conn():
    return http.client.HTTPConnection(HOST, 80, timeout=20)

def send(c, user, pw):
    hdrs = {}
    if GATE:
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % GATE).encode()).decode()
    if MODE == "basic":
        hdrs["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
        c.request("GET", "/login.php", headers=hdrs)
        r = c.getresponse(); b = r.read()
        return r.status, len(b), (r.status == 200)
    hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    c.request("POST", "/login.php", "username=%s&password=%s" % (user, pw), hdrs)
    r = c.getresponse(); b = r.read()
    return r.status, len(b), (b"alert-success" in b)

def chunk(n, w):
    step = -(-n // w)
    parts = [list(range(i, min(i + step, n))) for i in range(0, n, step)]
    flat = [i for p in parts for i in p]
    assert sorted(flat) == list(range(n)) and len(flat) == len(set(flat)) == n
    return parts

def concur(w):
    out = {}; lock = threading.Lock(); errs = []
    def run(idx):
        c = make_conn(); loc = {}
        try:
            for i in idx:
                t = time.perf_counter()
                try:
                    s, l, m = send(c, USER, "p%06d" % i)
                except Exception as e:                 # reconnect once, then give up loudly
                    try: c.close()
                    except Exception: pass
                    c = make_conn()
                    s, l, m = send(c, USER, "p%06d" % i)
                loc[i] = (s, l, time.perf_counter() - t, m)
        finally:
            with lock: out.update(loc)
            try: c.close()
            except Exception: pass
    ths = [threading.Thread(target=run, args=(p,)) for p in chunk(N, w)]
    t = time.perf_counter()
    for th in ths: th.start()
    for th in ths: th.join()
    d = time.perf_counter() - t
    vals = [out[i] for i in sorted(out)]
    if len(vals) != N:
        raise SystemExit("HARNESS FAILURE: only %d of %d slots filled -- this rung did zero work"
                         % (len(vals), N))
    return (d, len(vals), collections.Counter(v[0] for v in vals),
            collections.Counter(v[1] for v in vals), [v[2] for v in vals],
            sum(1 for v in vals if v[3]))

print("=== MODE=%s HOST=%s USER=%s GATE=%s (keep-alive) ===" % (MODE, HOST, USER, GATE))
c = make_conn(); lat = []; st = collections.Counter(); mk = 0
for i in range(120):
    t = time.perf_counter(); s, l, m = send(c, USER, "p%06d" % i)
    lat.append(time.perf_counter() - t); st[s] += 1; mk += 1 if m else 0
c.close()
print("BASELINE serial keep-alive candidates=120 elapsed=%.3fs achieved=%.1f cand/s median=%.4fs p95=%.4fs status=%s oracle-hits=%d"
      % (sum(lat), 120 / sum(lat), statistics.median(lat), sorted(lat)[114], dict(st), mk))

for w in (1, 2, 4, 8, 16, 32, 64, 128, 256, 512):
    d, done, st, by, lat, hits = concur(w)
    print("RUNG workers=%-4d candidates=%-5d elapsed=%.3fs achieved=%8.1f cand/s status=%s bytes=%s median_latency=%.4fs hits=%d"
          % (w, done, d, done / d, dict(st), dict(by), statistics.median(lat), hits))
