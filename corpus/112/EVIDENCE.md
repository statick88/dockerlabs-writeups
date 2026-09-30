# 112 Asucar — raw evidence index

Raw artefacts from the 2026-09-30 engagement. Each file is a transcript, not a
reproduction: the repo holds no lab artefacts, so these are the primary record
and the target cannot be re-run from here.

| File | What it is | Read it before trusting |
|---|---|---|
| `surface.md` | `nmap -p-`, `ss -tln`/`ss -lun`/`netstat -lun`, `/proc/net/udp*`, `ExposedPorts`, docroot inventory counts | the "no UDP surface" negative — four instruments, all counting zero |
| `identity.txt` | `id` and `/proc/self/status` at every hop, taken **as** the identity, plus the permission matrix as `www-data` and as `curiosito` | any claim about a permission boundary |
| `plugin-defect.txt` | the missing-class check, the `dependency/` listing, the verbatim PHP fatal from `/var/log/apache2/error.log`, and the control/treatment table | Finding 1 and Finding 2 |
| `escalation.txt` | the puttygen oracle before/after, `sudo -n -l`, the failed `-O save-as:` and bare-key attempts, and the SSH session that closed the chain | Finding 3 |
| `credential-sweep.txt` | the positive control that proved the xmlrpc oracle can fire, then the 409,165-candidate sweep with its work count | the "no WordPress password found" negative |
| `salts.txt` | `wp_salt()` vs the `wp-config.php` placeholder, the `wp_options` rows, and the identity tests that say which source is consumed | anything about cookie forgery |
| `reward-search.txt` | every `FLAG{`-shaped search, its count, and the four non-zero matches quoted so a reader can see they are not rewards | the "no reward" statement |
| `restore.txt` | the restore and its positive verification, including the two byte counts that had to match the pre-engagement baseline | the claim that the lab is back to shipped |
