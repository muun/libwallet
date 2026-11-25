#!/usr/bin/env python3
"""Independent reference implementation of the recovery code spec (SPEC.md).

Generates v3_vectors.json. It is deliberately written without looking at the
Go implementation so that the Go tests cross-check two implementations.

Usage: python3 -I gen_vectors.py > v3_vectors.json
"""

import hashlib
import hmac
import json
import random

ALPHABET = "ABCDEFHJKLMNPQRSTUVWXYZ2345789"
ALPHABET_LEGACY = "ABCDEFHJKMNPQRSTUVWXYZ2345789"
P = 887
LATEST_VERSION = 3


class RCError(Exception):
    def __init__(self, kind):
        super().__init__(kind)
        self.kind = kind


def idx(c):
    return ALPHABET.index(c)


def checksum(body):
    assert len(body) == 32
    s1 = sum((i + 1) * idx(c) for i, c in enumerate(body)) % P
    s2 = sum((i + 1) ** 2 * idx(c) for i, c in enumerate(body)) % P
    return s1, s2


def enc(v):
    return ALPHABET[v // 30] + ALPHABET[v % 30]


def dec(pair):
    v = idx(pair[0]) * 30 + idx(pair[1])
    return v if v < P else None


def fmt(symbols):
    return "-".join(symbols[i:i + 4] for i in range(0, len(symbols), 4))


def make_v3(rng):
    body = "LB" + "".join(rng.choice(ALPHABET) for _ in range(30))
    s1, s2 = checksum(body)
    return fmt(body + enc(s1) + enc(s2))


def make_v2(rng):
    return fmt("LA" + "".join(rng.choice(ALPHABET) for _ in range(30)))


def well_formed(code, alphabet, blocks):
    if len(code) != blocks * 5 - 1:
        return False
    for i, c in enumerate(code):
        if i % 5 == 4:
            if c != "-":
                return False
        elif c not in alphabet:
            return False
    return True


def version(code):
    if len(code) >= 2 and code[0] == "L":
        if code[1] not in ALPHABET:
            raise RCError("version")
        v = idx(code[1]) + 2
        if v > LATEST_VERSION:
            raise RCError("version")
        blocks = 8 if v == 2 else 9
        if len(code) != blocks * 5 - 1:
            raise RCError("length")
        if not well_formed(code, ALPHABET, blocks):
            raise RCError("characters")
        if v == 3:
            symbols = code.replace("-", "")
            s1, s2 = dec(symbols[32:34]), dec(symbols[34:36])
            if (s1, s2) != checksum(symbols[:32]):
                raise RCError("checksum")
        return v
    if len(code) != 39:
        raise RCError("length")
    if not well_formed(code, ALPHABET_LEGACY, 8):
        raise RCError("characters")
    return 1


def private_key(code, salt):
    v = version(code)
    if v == 1:
        return hashlib.scrypt(code.encode(), salt=bytes.fromhex(salt),
                              n=512, r=8, p=1, dklen=32).hex()
    return hmac.new(b"muun:rc", code.encode(), hashlib.sha256).hexdigest()


def strip(code):
    return "".join(c for c in code.upper() if c != "-" and not c.isspace())


def normalize(code):
    s = strip(code)
    if len(s) >= 2 and s[0] == "L":
        if s[1] not in ALPHABET or idx(s[1]) + 2 > LATEST_VERSION:
            raise RCError("version")
        want = 32 if idx(s[1]) + 2 == 2 else 36
    else:
        want = 32
    if len(s) != want:
        raise RCError("length")
    return fmt(s)


def is_valid_v3_symbols(s):
    try:
        return version(fmt(s)) == 3
    except RCError:
        return False


def locate(code):
    """Returns (position, corrected) for the unique valid v3 code at distance 1."""
    s = strip(code)
    if len(s) != 36:
        return None
    bad = [i for i, c in enumerate(s) if c not in ALPHABET]
    if len(bad) > 1:
        return None
    if not bad and is_valid_v3_symbols(s):
        return None
    positions = bad if bad else range(36)
    found = []
    for i in positions:
        for c in ALPHABET:
            if c == s[i]:
                continue
            cand = s[:i] + c + s[i + 1:]
            if is_valid_v3_symbols(cand):
                found.append((i, fmt(cand)))
    if len(found) != 1:
        return None
    return found[0]


def sub(code, sym_pos, rng):
    """Replace the symbol at sym_pos (dash-free index) with a different one."""
    s = code.replace("-", "")
    c = rng.choice(ALPHABET.replace(s[sym_pos], ""))
    return fmt(s[:sym_pos] + c + s[sym_pos + 1:])


def swap(code, a, b):
    s = list(code.replace("-", ""))
    assert s[a] != s[b]
    s[a], s[b] = s[b], s[a]
    return fmt("".join(s))


def validate_vector(desc, code, salt=""):
    v = {"description": desc, "input": code}
    try:
        ver = version(code)
        v.update(valid=True, error="", version=ver,
                 private_key=private_key(code, salt))
    except RCError as e:
        v.update(valid=False, error=e.kind, version=0, private_key="")
    if salt:
        v["salt"] = salt
    return v


def main():
    rng = random.Random(20261125)
    vectors = {"validate": [], "normalize": [], "locate": []}
    V = vectors["validate"]

    # --- Unchanged v1 / v2 behavior -------------------------------------
    V.append(validate_vector("v1 legacy code", "R52Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUA", "FFFFFFFF"))
    V.append(validate_vector("v1 legacy code with real salt", "3V4N-R9EC-V3TQ-NRB3-Q7NY-9HXP-CSDC-B5BC", "63f701fda4fc0b0c"))
    V.append(validate_vector("v2 code", "LA2Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUA"))
    for i in range(2):
        V.append(validate_vector("v2 random code %d" % (i + 1), make_v2(rng)))

    # --- Valid v3 ---------------------------------------------------------
    for i in range(6):
        V.append(validate_vector("v3 random code %d" % (i + 1), make_v3(rng)))
    edges = {("S1", 0): None, ("S1", P - 1): None, ("S2", 0): None, ("S2", P - 1): None}
    while any(v is None for v in edges.values()):
        code = make_v3(rng)
        s1, s2 = checksum(code.replace("-", "")[:32])
        for key in edges:
            if edges[key] is None and (s1 if key[0] == "S1" else s2) == key[1]:
                edges[key] = code
    for (name, val), code in sorted(edges.items()):
        V.append(validate_vector("v3 code with %s = %d" % (name, val), code))

    # --- v3 detection ----------------------------------------------------
    base = make_v3(rng)
    V.append(validate_vector("v3 base code for error cases", base))
    for block in range(9):
        pos = block * 4 + (2 if block == 0 else rng.randrange(4))
        V.append(validate_vector("v3 single substitution in block %d" % (block + 1), sub(base, pos, rng)))
    s = base.replace("-", "")
    a = next(i for i in range(2, 31) if s[i] != s[i + 1])
    V.append(validate_vector("v3 adjacent transposition", swap(base, a, a + 1)))
    b = next(j for j in range(31, 2, -1) if s[j] != s[2])
    V.append(validate_vector("v3 distant transposition", swap(base, 2, b)))
    V.append(validate_vector("v3 transposition between body and checksum block",
                             swap(base, 31, next(j for j in range(32, 36) if s[j] != s[31]))))
    V.append(validate_vector("v3 two substitutions", sub(sub(base, 5, rng), 20, rng)))
    V.append(validate_vector("v3 checksum value out of range (>= 887)", fmt(s[:32] + "99" + s[34:])))
    V.append(validate_vector("v3 checksum second value out of range (>= 887)", fmt(s[:34] + "99")))

    # --- Length / version / format ----------------------------------------
    V.append(validate_vector("v3 code missing block 9", fmt(s[:32])))
    v2 = make_v2(rng)
    V.append(validate_vector("v2 code with an extra block", v2 + "-ABCD"))
    V.append(validate_vector("v2 code with version flipped to B", "LB" + v2[2:]))
    V.append(validate_vector("v3 code with version flipped to A", "LA" + base[2:]))
    V.append(validate_vector("unknown version C", "LC" + v2[2:]))
    V.append(validate_vector("unknown version C with 9 blocks", "LC" + base[2:]))
    V.append(validate_vector("version char not in alphabet", "L1" + v2[2:]))
    V.append(validate_vector("v3 with misplaced dash", base[:3] + "-" + base[3] + base[5:]))
    V.append(validate_vector("v3 with invalid character O", base[:6] + "O" + base[7:]))
    V.append(validate_vector("v3 lowercase is not canonical", base.lower()))
    V.append(validate_vector("v3 without dashes", s))
    V.append(validate_vector("v2 invalid character", "LA2Q-48Z3-25JR-S51B-5SUS-HXHJ-RCMM-8YUA"))
    V.append(validate_vector("v2 invalid length", "LA2Q-48Z3-25JR-SB5S-USHX-HJRC-MM8YUA"))
    V.append(validate_vector("v1 invalid character L", "R52Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUL"))
    V.append(validate_vector("empty string", ""))
    V.append(validate_vector("single L", "L"))

    # --- Normalize --------------------------------------------------------
    N = vectors["normalize"]

    def norm(desc, inp):
        try:
            N.append({"description": desc, "input": inp, "output": normalize(inp), "error": ""})
        except RCError as e:
            N.append({"description": desc, "input": inp, "output": "", "error": e.kind})

    norm("canonical v3 unchanged", base)
    norm("v3 lowercase", base.lower())
    norm("v3 spaces instead of dashes", base.replace("-", " "))
    norm("v3 without separators", s)
    norm("v3 surrounding and mixed whitespace", "  " + base.replace("-", "\t", 2) + " \n")
    norm("v2 lowercase without separators", v2.replace("-", "").lower())
    norm("v1 lowercase", "r52q-48z3-25jr-s5jb-5sus-hxhj-rcmm-8yua")
    norm("v3 keeps characters outside the alphabet", (base[:6] + "o" + base[7:]).lower())
    norm("v3 one symbol short", s[:35])
    norm("v2 one symbol too many", v2.replace("-", "") + "A")
    norm("unknown version", "LC" + s[2:])
    norm("empty string", "")
    norm("only separators", " - - ")

    # --- Locate -----------------------------------------------------------
    L = vectors["locate"]

    def loc(desc, inp):
        r = locate(inp)
        L.append({"description": desc, "input": inp, "found": r is not None,
                  "position": r[0] if r else -1, "corrected": r[1] if r else ""})

    loc3 = make_v3(rng)
    t = loc3.replace("-", "")
    loc("valid code has no typo", loc3)
    for pos in (2, 9, 17, 31, 32, 33, 34, 35):
        loc("single substitution at symbol %d" % pos, sub(loc3, pos, rng))
    loc("version char typo (B -> C)", fmt(t[:1] + "C" + t[2:]))
    loc("prefix typo (L -> M)", fmt("M" + t[1:]))
    loc("character outside alphabet (O)", fmt(t[:12] + "O" + t[13:]))
    loc("lowercase input without dashes", sub(loc3, 20, rng).replace("-", "").lower())
    loc("two characters outside alphabet", fmt(t[:3] + "O" + t[4:20] + "I" + t[21:]))
    loc("wrong length", fmt(t[:32]))
    # Pick a deterministic adjacent transposition and double substitution and
    # record whatever the reference implementation says (usually not found).
    a = next(i for i in range(2, 31) if t[i] != t[i + 1])
    loc("adjacent transposition", swap(loc3, a, a + 1))
    loc("two substitutions", sub(sub(loc3, 4, rng), 27, rng))

    json.dump(vectors, __import__("sys").stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
