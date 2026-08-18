#!/usr/bin/env python3
"""
gen_jwks.py: Build a standards-compliant JWKS (RFC 7517) from one or more PEM
RSA keys.

Usage: python3 gen_jwks.py <output_jwks.json> <kid1>:<private_key1.pem> [<kid2>:<private_key2.pem> ...]

For each <kid>:<path> pair, parses the RSA public key from the
SubjectPublicKeyInfo DER structure, extracts the modulus (n) and public
exponent (e), base64url-encodes them, and adds an "RS256" entry under that
kid to the output JWKS document. JWKS natively supports multiple keys this
way, each of the gateway's three signing purposes (admin/backend/lookup)
gets its own kid-distinguished entry so a verifier resolves the right public
key by the kid in the token header.
"""
import base64, glob, json, os, shutil, subprocess, sys

def find_openssl() -> str:
    """Locate the OpenSSL binary: env var > /opt/openssl > /opt/openssl-* scan > PATH."""
    env = os.environ.get("OPENSSL_BIN")
    if env and os.path.isfile(env):
        return env
    # The canonical alias, published by the base image and by deploy.sh. Ahead of
    # the glob because the glob's reverse sort is LEXICOGRAPHIC, not semantic:
    # once a 3.10.x exists it sorts BELOW 3.6.x as a string, and the scan
    # silently picks the older OpenSSL.
    alias = "/opt/openssl/bin/openssl"
    if os.path.isfile(alias):
        return alias
    # Retained as a fallback for hosts installed before the alias existed.
    candidates = sorted(glob.glob("/opt/openssl-*/bin/openssl"), reverse=True)
    if candidates:
        return candidates[0]
    return shutil.which("openssl") or "openssl"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def read_der_int(data: bytes, pos: int):
    """Read a DER-encoded INTEGER at position pos.  Returns (value_bytes, new_pos)."""
    assert data[pos] == 0x02, f"Expected INTEGER tag (0x02) at pos={pos}, got {data[pos]:#04x}"
    pos += 1
    length = data[pos]; pos += 1
    if length & 0x80:
        nb = length & 0x7f
        length = int.from_bytes(data[pos : pos + nb], "big")
        pos += nb
    value = data[pos : pos + length]
    pos += length
    return value.lstrip(b"\x00"), pos

def extract_rsa_params(pem_key_path: str):
    """Extract raw (n, e) bytes from an RSA PEM private key."""
    der = subprocess.check_output([
        find_openssl(), "rsa",
        "-in", pem_key_path,
        "-outform", "DER", "-pubout",
    ])

    # SubjectPublicKeyInfo structure (RFC 5480):
    #   SEQUENCE {
    #     SEQUENCE { OID rsaEncryption, NULL }   <- AlgorithmIdentifier
    #     BIT STRING {
    #       SEQUENCE { INTEGER n, INTEGER e }    <- RSAPublicKey
    #     }
    #   }
    idx = 0
    assert der[idx] == 0x30; idx += 1          # outer SEQUENCE tag
    if der[idx] & 0x80:
        idx += 1 + (der[idx] & 0x7f)           # multi-byte length
    else:
        idx += 1                                 # single-byte length

    assert der[idx] == 0x30; idx += 1          # AlgorithmIdentifier SEQUENCE tag
    alg_len = der[idx]; idx += 1
    if alg_len & 0x80:
        nb = alg_len & 0x7f
        alg_len = int.from_bytes(der[idx : idx + nb], "big"); idx += nb
    idx += alg_len                               # skip AlgorithmIdentifier body

    assert der[idx] == 0x03; idx += 1          # BIT STRING tag
    bs_len = der[idx]; idx += 1
    if bs_len & 0x80:
        nb = bs_len & 0x7f
        bs_len = int.from_bytes(der[idx : idx + nb], "big"); idx += nb
    idx += 1                                     # skip unused-bits byte (0x00)

    assert der[idx] == 0x30; idx += 1          # RSAPublicKey SEQUENCE tag
    rsa_len = der[idx]; idx += 1
    if rsa_len & 0x80:
        nb = rsa_len & 0x7f
        rsa_len = int.from_bytes(der[idx : idx + nb], "big"); idx += nb

    n_bytes, idx = read_der_int(der, idx)
    e_bytes, idx = read_der_int(der, idx)
    return n_bytes, e_bytes

def main():
    if len(sys.argv) < 3:
        sys.exit(f"Usage: {sys.argv[0]} <output_jwks.json> <kid1>:<private_key1.pem> [<kid2>:<private_key2.pem> ...]")

    out_path = sys.argv[1]
    pairs    = sys.argv[2:]

    keys = []
    for pair in pairs:
        kid, _, key_path = pair.partition(":")
        if not kid or not key_path:
            sys.exit(f"Invalid <kid>:<path> pair: {pair!r}")

        n_bytes, e_bytes = extract_rsa_params(key_path)
        keys.append({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n":   b64url(n_bytes),
            "e":   b64url(e_bytes),
        })
        print(f"  {kid}: n length {len(n_bytes)} bytes ({len(n_bytes)*8} bits), e={int.from_bytes(e_bytes, 'big')}")

    with open(out_path, "w") as f:
        json.dump({"keys": keys}, f, separators=(",", ":"))

    print(f"JWKS written to {out_path} ({len(keys)} key(s))")

if __name__ == "__main__":
    main()
