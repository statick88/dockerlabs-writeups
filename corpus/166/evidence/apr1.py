"""Apache MD5 (apr1) -- a transcription of apr_md5_encode().

Source of truth: apr_md5.c, apr_md5_encode(), fetched from
https://raw.githubusercontent.com/apache/apr/trunk/crypto/apr_md5.c and read
locally as apr_md5.c:504-666. Line references below are to that file.

Used to (a) measure the KDF cost in candidates/second, which is what separates
"the KDF ran" from "the KDF was silently skipped", and (b) crack the shipped
/home/.htpasswd offline. Correctness is pinned against `openssl passwd -apr1`
and against the target's own `htpasswd -vb`, not against another copy of this.
"""
import hashlib, sys

ITOA64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def to64(v, n):
    out = bytearray()
    while n >= 1:
        out.append(ITOA64[v & 0x3F]); v >>= 6; n -= 1
    return bytes(out)

def apr1(pw: bytes, salt: bytes) -> bytes:
    ctx = hashlib.md5()
    ctx.update(pw)              # :557
    ctx.update(b"$apr1$")       # :562
    ctx.update(salt)            # :567

    final = hashlib.md5(pw + salt + pw).digest()   # :576-579

    pl = len(pw)                # :580-583
    while pl > 0:
        ctx.update(final[:min(pl, 16)]); pl -= 16

    final = b"\x00" * 16        # :588 memset

    i = len(pw)                 # :593-600
    while i != 0:
        ctx.update(final[:1] if (i & 1) else pw[:1]); i >>= 1

    final = ctx.digest()        # :610

    for i in range(1000):       # :617-647
        c = hashlib.md5()
        c.update(pw if (i & 1) else final)          # :626-631
        if i % 3: c.update(salt)                    # :632-634
        if i % 7: c.update(pw)                      # :636-638
        c.update(final if (i & 1) else pw)          # :640-645
        final = c.digest()                          # :646

    o = b"$apr1$" + salt + b"$"
    o += to64((final[0]<<16)|(final[6]<<8)|final[12], 4)   # :651
    o += to64((final[1]<<16)|(final[7]<<8)|final[13], 4)   # :652
    o += to64((final[2]<<16)|(final[8]<<8)|final[14], 4)   # :653
    o += to64((final[3]<<16)|(final[9]<<8)|final[15], 4)   # :654
    o += to64((final[4]<<16)|(final[10]<<8)|final[5],  4)  # :655
    o += to64(final[11], 2)                              # :656
    return o

if __name__ == "__main__":
    print(apr1(sys.argv[1].encode(), sys.argv[2].encode()).decode())
