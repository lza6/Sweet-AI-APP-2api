#!/usr/bin/env python3
"""Decode obfuscated string arrays from Sweet AI (com.mxxtech.sweetai) decompiled code.
Cipher: p409hb.C19322a.decrypt(data, key) = XOR repeating key, UTF-8.
"""
import sys

SYM = {
    # p364f2.C18772a
    'A7': -49, 'B7': -38, 'C7': -31, 'E7': -39, 'n7': -40, 'o7': -64, 'p7': -63,
    'r7': -61, 't7': -58, 'u7': -57, 'v7': -55, 'x7': -53, 'y7': -51, 'z7': -50,
    's7': None, 'w7': None,
    # p026b5.C3948a
    'W': 33, 'X': 36, 'Z': 38, 'a0': 39, 'b0': 41, 'e0': 44, 'f0': 45,
    # p323d4.C18318o
    'C18318oA': 113, 'C18318ow': 100, 'C18318oz': -14,
    # com.google.common.base.Ascii
    'CAN': 24, 'DC2': 18, 'DC4': 20, 'DLE': 16, 'EM': 25, 'ESC': 27, 'ETB': 23,
    'FF': 12, 'NAK': 21, 'SI': 15, 'SO': 14, 'VT': 11, 'XOFF': 19, 'GS': 29, 'RS': 30,
    # kotlin.io.encoding.Base64
    'BASE64EQ': 61,
}


def parse(s):
    out = []
    for tok in s.split(','):
        tok = tok.strip()
        if not tok:
            continue
        if tok in ('Byte.MIN_VALUE',):
            out.append(-128)
        elif tok in ('Byte.MAX_VALUE',):
            out.append(127)
        elif tok in SYM:
            v = SYM[tok]
            if v is None:
                raise SystemExit('unmapped symbol: ' + tok)
            out.append(v)
        else:
            out.append(int(tok))
    return [(x + 256) % 256 for x in out]


def dec(val, key):
    v, k = parse(val), parse(key)
    return bytes(bytearray(v[i] ^ k[i % len(k)] for i in range(len(v)))).decode('utf-8', 'replace')


if __name__ == '__main__':
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        val, key = line.split('|')
        print(f'{dec(val, key)!r}')
