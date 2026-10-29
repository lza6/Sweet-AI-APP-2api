#!/usr/bin/env python3
"""Emulate small pure-computation functions in libprmp.so (obfuscated constant blobs)."""
import sys
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *

LIB = r'D:\apk-analysis\sweet-ai\raw\lib\arm64-v8a\libprmp.so'
CODE_BASE = 0x0
STACK = 0x20000000
STACK_SIZE = 0x20000
DATA = 0x10000000


def load():
    data = open(LIB, 'rb').read()
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    # map image (rounded to 4k)
    size = (len(data) + 0xFFF) & ~0xFFF
    uc.mem_map(0, size + 0x100000)
    uc.mem_write(0, data)
    # page 0 already mapped as part of image -> tpidr reads fine
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_map(DATA, 0x10000)
    uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x100)
    return uc, data


def run(uc, entry, out_addr, stop, x0=None):
    uc.reg_write(UC_ARM64_REG_X0, x0 if x0 is not None else out_addr)
    uc.reg_write(UC_ARM64_REG_X8, out_addr)
    try:
        uc.emu_start(entry, stop, count=100000)
    except Exception as e:
        print('   emu error:', e)
    return uc.mem_read(out_addr, 32)


if __name__ == '__main__':
    targets = [
        ('className  ', 0x5e30c, 0x5e464),
        ('methodName ', 0x5e464, 0x5e5ac),
        ('signature  ', 0x5e5ac, 0x5e7a8),
        ('formatStr  ', 0x5e7a8, 0x5e8a8),
    ]
    for name, entry, stop in targets:
        uc, _ = load()
        raw = bytes(run(uc, entry, DATA + 0x100, stop))
        print(f'{name} {raw!r}')
