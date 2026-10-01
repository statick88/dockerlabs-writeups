# Retrieval hazards — how a scanner confidently reports nothing

Distinct from `self-corrections.md`. Those are broken instruments. These are
**correct instruments pointed at the wrong question**, returning a clean negative
that reads as a result. Each one was hit, measured, and written down because the
negative looked exactly like the positive.

| Class | What the tool reports | What is true | How to separate them |
|---|---|---|---|
| **TCP-only scan vs a UDP service** | `closed` or absent | IPMI/BMC on `623/udp`, bound to `0.0.0.0`, granting `ADMINISTRATOR` with no credential | `nmap -p-` is TCP by definition. Confirm with `/proc/net/udp`, the image's `ExposedPorts`, or a live protocol exchange. A blind spot is not an absent service. |
| **A catch-all vhost** | Every name answers `200` | One host answers, and it is the baseline | Normalise the body, hash it, and include a name that **cannot exist** as the control. In lab 65 sixteen names shared one hash, including an invented TLD — and the real admin lived two levels deeper than the `admin` name a flat wordlist finds. |
| **A port closed by a knock** | `filtered` | The service exists and wants three packets | `closed` conflates *no service* with *service awaiting a sequence*. Only the knock-as-positive-control separates them. |
| **An HTTP scanner vs a WebSocket** | Zero endpoints | A live channel answering `101` | The handshake is a `GET`, the channel is not HTTP. The same `nmap --script=http-*` run that reports a title on port 8080 produces **no output at all** on 9229. |
| **A tunnel-only target** | Ports on the operator's own workstation | Nothing on the target | `nmap -p-` through a misconfigured SOCKS silently scans you. In lab 113 it reported `587/tcp open smtp-proxy` from the agent's own machine. |
| **A blind XXE with in-band reflection** | No OOB channel, so no finding | The HTTP response **is** the exfiltration | "No OOB, no XXE" is true only for *blind* XXE. When the expanded value is rendered, the response carries it and no collaborator is needed. |
| **A password in a front-end bundle** | A secret exposed | A public build variable | `VITE_*`, `NEXT_PUBLIC_*` and `REACT_APP_*` are inlined **by design**. Read them and you have read the documentation. The finding is a token with write scope, or a service credential — not a value that happens to look like one. |
| **A memory dump vs a config dump** | Secrets exposed | Six secret classes in the heap, none in any `.properties` | A heap dump carries runtime state a config file never had — a plaintext admin password that is bcrypt-hashed on every boot. Conversely `/actuator/env` returned 96 values and 96 `******`, and reporting the **name** `app.jwt.secret` as a leak is a fabricated finding. |
| **A `403` from a WAF** | Blocked | A working control, and the scan user-agent is what triggered it | `403` and `429` are expected working conditions, not verdicts. Work under an open circuit needs explicit authorisation and a declared window; only an account- or team-level block is terminal. |
| **A backtick that concatenates** | An empty `<pre></pre>`, or a refusal body | The command ran anyway | The three metachars are not interchangeable. `;` and `\|` separate, but a backtick inside an already-quoted word **concatenates**, so the shell produces nothing, the body comes back empty, and an empty body is byte-identical to the app's own refusal. Measured: the marker file the payload touched existed, while the response read as a block. **A refusal body and a malformed-payload body are the same bytes** — only a witness read back out of band separates them. |
| **A renamed admin path** | No `/admin` | The admin panel | A security plugin rewrote `/wp-admin/` to `/ghost-admin/`. Read the rewrite rules. The path is not the control; the authorisation decision is. |

## The one that generalises

Every row is the same question asked three ways:

> **Reachable / what the body carries / decisive.**

A scanner answers the first. A report needs all three. The gap between them is
where findings are invented and findings are missed, and it is the cheapest thing
in this corpus to get right — a hash of a normalised body, a byte count, a
`LENGTH()`, a mode read back as the identity that owns it.
