#!/usr/bin/env python3
"""Full Unicorn emulation of libprmp.so :: getAppSecret(long stamp, String rand).

Recovered call graph (static analysis):
    getAppSecret(stamp, rand):
        cls = FindClass("java/lang/Long")
        mid = GetStaticMethodID(cls, "toString", "(J)Ljava/lang/String;")
        stampStr = CallStaticObjectMethod(cls, mid, stamp)      -> "1759...".
        buf = vsprintf(fmt = "%d_%d_%s_%s", <args>)
        secret = MD5_hex(buf)[:32]                              -> 32 chars
        return secret
"""
import hashlib
import struct
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm64_const import *

LIB = r'D:\apk-analysis\sweet-ai\raw\lib\arm64-v8a\libprmp.so'
PLT_BASE = 0x887b0
PLT_ENTRY = 16
STACK = 0x20000000
STACK_SZ = 0x80000
HEAP = 0x30000000
HEAP_SZ = 0x100000
JOBJ = 0x40000000

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pltmap import Lib as ElfLib


class Harness:
    def __init__(self, verbose=False):
        self.data = open(LIB, 'rb').read()
        self.elf = ElfLib()
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        img_size = ((len(self.data) + 0xFFF) & ~0xFFF) + 0x40000
        self.uc.mem_map(0, img_size)
        self.uc.mem_write(0, self.data)
        self.uc.mem_map(STACK, STACK_SZ)
        self.uc.mem_map(HEAP, HEAP_SZ)
        self.uc.mem_map(JOBJ, 0x10000)
        self.heap = HEAP + 0x100
        self.jobj_seq = JOBJ + 0x100
        self.strings = {}   # jobject -> python str
        self.classes = {}   # jclass -> name
        self.mids = {}
        self.arrays = {}    # jobject -> bytearray
        self.verbose = verbose
        self.plt = self._build_plt()
        self._relocate()
        self.calls = []
        self.result = None
        self.vsprintf_arg = None
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)

    def _relocate(self):
        """Apply dynamic relocations (image is loaded at base 0)."""
        from elftools.elf.relocation import RelocationSection
        R_RELATIVE, R_ABS64, R_GLOB_DAT = 1027, 257, 1025
        for s in self.elf.elf.iter_sections():
            if not isinstance(s, RelocationSection):
                continue
            for r in s.iter_relocations():
                t = r['r_info_type']
                off = r['r_offset']
                val = r['r_addend'] if r.is_RELA() else 0
                if t == R_RELATIVE:
                    self.uc.mem_write(off, struct.pack('<Q', (val) & 0xFFFFFFFFFFFFFFFF))
                elif t == R_GLOB_DAT:
                    sym = self.elf.dsym.get_symbol(r['r_info_sym'])
                    if sym['st_value'] and sym['st_shndx'] != 'SHN_UNDEF':
                        self.uc.mem_write(off, struct.pack('<Q', sym['st_value'] & 0xFFFFFFFFFFFFFFFF))
                elif t == R_ABS64:
                    sym = self.elf.dsym.get_symbol(r['r_info_sym'])
                    if sym['st_value']:
                        self.uc.mem_write(off, struct.pack('<Q', (sym['st_value'] + val) & 0xFFFFFFFFFFFFFFFF))
                # GLOB_DAT: leave 0 (external symbol -> stub returns 0)

    # ---- helpers -------------------------------------------------
    def _build_plt(self):
        """Decode every PLT stub's adrp+ldr to find its GOT slot -> symbol."""
        out = {}
        for i in range(1, 271):
            addr = PLT_BASE + i * PLT_ENTRY
            name = self.elf.sym_at_plt(addr)
            if name and not name.startswith('<got'):
                out[addr] = name
        return out

    def alloc(self, nbytes):
        p = self.heap
        self.heap = (p + nbytes + 15) & ~15
        assert self.heap < HEAP + HEAP_SZ
        return p

    def put(self, blob):
        p = self.alloc(len(blob) + 1)
        self.uc.mem_write(p, blob + b'\x00')
        return p

    def cstr(self, p, limit=4096):
        out = b''
        while len(out) < limit:
            ch = self.uc.mem_read(p, 1)
            if ch == b'\x00':
                break
            out += bytes(ch)
            p += 1
        return out.decode('utf-8', 'replace')

    def new_jstr(self, s):
        h = self.jobj_seq
        self.jobj_seq += 0x10
        self.strings[h] = s
        return h

    def _ret(self, value):
        uc = self.uc
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_X0, value & 0xFFFFFFFFFFFFFFFF)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def _render(self, fmt, regs):
        """Minimal printf renderer over the vararg register sequence."""
        out, i, k = [], 0, 0
        while i < len(fmt):
            ch = fmt[i]
            if ch != '%':
                out.append(ch)
                i += 1
                continue
            j = i + 1
            while j < len(fmt) and fmt[j] in '-+ #0123456789.lh':
                j += 1
            conv = fmt[j] if j < len(fmt) else ''
            spec = fmt[i:j + 1]
            val = regs[k] if k < len(regs) else 0
            k += 1
            if conv in 'diu':
                n = val & 0xFFFFFFFF
                if conv == 'd' and n >= 0x80000000:
                    n -= 0x100000000
                out.append(spec % n if '%' in spec else str(n))
            elif conv == 's':
                out.append(self.cstr(val))
            elif conv in 'lxX':
                out.append(spec % val)
            elif conv == '%':
                out.append('%')
                k -= 1
            i = j + 1
        return ''.join(out)

    # ---- JNI / libc stubs ---------------------------------------
    def _on_code(self, uc, addr, size, _):
        if addr == 0x53F00:      # bl <vsprintf helper> inside getAppSecret
            dst = uc.reg_read(UC_ARM64_REG_X0)
            fmt_ptr = uc.reg_read(UC_ARM64_REG_X2)
            a3 = uc.reg_read(UC_ARM64_REG_X3)
            a4 = uc.reg_read(UC_ARM64_REG_X4)
            a5 = uc.reg_read(UC_ARM64_REG_X5)
            a6 = uc.reg_read(UC_ARM64_REG_X6)
            a7 = uc.reg_read(UC_ARM64_REG_X7)
            fmt = self.cstr(fmt_ptr)
            self.vsprintf_arg = (fmt, a3, a4, a5, a6, a7)
            out = self._render(fmt, [a3, a4, a5, a6, a7])
            self.uc.mem_write(dst, out.encode() + b'\x00')
            self.formatted = out
            self.uc.reg_write(UC_ARM64_REG_X0, len(out))
            self.uc.reg_write(UC_ARM64_REG_PC, 0x53F04)
            return
        name = self.plt.get(addr)
        if name is None:
            return
        self.calls.append(name)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x3 = uc.reg_read(UC_ARM64_REG_X3)
        r = 0
        if name == '_ZN7_JNIEnv17GetStringUTFCharsEP8_jstringPh':
            s = self.strings.get(x1, '')
            r = self.put(s.encode())
        elif name == '_ZN7_JNIEnv9FindClassEPKc':
            cls = self.jobj_seq
            self.jobj_seq += 0x10
            self.classes[cls] = self.cstr(x1)
            r = cls
        elif name == '_ZN7_JNIEnv17GetStaticMethodIDEP7_jclassPKcS3_':
            mid = self.jobj_seq
            self.jobj_seq += 0x10
            self.mids[mid] = (self.cstr(x2), self.cstr(x3))
            r = mid
        elif name == '_ZN7_JNIEnv22CallStaticObjectMethodEP7_jclassP10_jmethodIDz':
            mid = x2
            mname, _sig = self.mids.get(mid, ('?', '?'))
            arg = uc.reg_read(UC_ARM64_REG_X3)
            if mname == 'toString':
                r = self.new_jstr(str(struct.unpack('<q', struct.pack('<Q', arg))[0]))
            else:
                r = self.new_jstr('')
        elif name == '_ZN7_JNIEnv12NewStringUTFEPKc':
            r = self.new_jstr(self.cstr(x1))
            self.result = self.strings[r]
        elif name in ('_ZN7_JNIEnv21ReleaseStringUTFCharsEP8_jstringPKc',
                      '_ZN7_JNIEnv14DeleteLocalRefEP8_jobject',
                      '_ZN7_JNIEnv24ReleaseByteArrayElementsEP11_jbyteArrayPai'):
            r = 0
        elif name == '__strlen_chk':
            r = len(self.cstr(x0))
        elif name == '_ZN7_JNIEnv12NewByteArrayEi':
            arr = self.jobj_seq
            self.jobj_seq += 0x10
            self.arrays[arr] = bytearray(struct.unpack('<i', struct.pack('<I', x1 & 0xFFFFFFFF))[0])
            r = arr
        elif name == '_ZN7_JNIEnv18SetByteArrayRegionEP11_jbyteArrayiiPKa':
            arr = x1
            start, length, buf = x2, x3, uc.reg_read(UC_ARM64_REG_X4)
            raw = bytes(uc.mem_read(buf, length))
            self.arrays[arr][start:start + length] = raw
            r = 0
        elif name == '_Z12Fe8xy6PWr7OVP7_JNIEnvP11_jbyteArray':
            raw = bytes(self.arrays.get(x1, b''))
            r = self.put(hashlib.sha1(raw).hexdigest()[:32].encode())
        elif name == '_ZN7_JNIEnv20GetByteArrayElementsEP11_jbyteArrayPh':
            raw = bytes(self.arrays.get(x1, b''))
            r = self.put(raw)
        elif name in ('__strncpy_chk', '__strncpy_chk2'):
            n = x2
            src = x1
            raw = bytes(uc.mem_read(src, n))
            uc.mem_write(x0, raw)
            r = x0
        elif name == '__memset_chk':
            uc.mem_write(x0, bytes(x2 & 0xFF))
            r = x0
        elif name == '__cxa_guard_acquire':
            r = 1
        elif name in ('__cxa_guard_release', '__cxa_guard_abort'):
            r = 0
        elif name == '__stack_chk_fail':
            raise RuntimeError('stack smashing detected in libprmp')
        elif name == '__vsprintf_chk':
            # rare: let the internal wrapper handle it
            raise RuntimeError('__vsprintf_chk hit directly')
        else:
            if self.verbose:
                print(f'   [stub] unhandled {name} -> 0')
            r = 0
        self._ret(r)

    # ---- public API ---------------------------------------------
    def get_app_secret(self, stamp, rand):
        uc = self.uc
        uc.reg_write(UC_ARM64_REG_SP, STACK + STACK_SZ - 0x200)
        jrand = self.new_jstr(rand)
        jcls = self.jobj_seq
        self.jobj_seq += 0x10
        self.strings[jcls] = 'clazz'
        uc.reg_write(UC_ARM64_REG_X0, JOBJ)          # JNIEnv* (fake, unused)
        uc.reg_write(UC_ARM64_REG_X1, jcls)
        uc.reg_write(UC_ARM64_REG_X2, stamp)
        uc.reg_write(UC_ARM64_REG_X3, jrand)
        uc.reg_write(UC_ARM64_REG_LR, 0x0)           # park: ret -> 0
        self.result = None
        try:
            uc.emu_start(0x53dfc, 0x0, count=2_000_000)
        except UcError as e:
            print('emu stop:', e)
        return self.result


if __name__ == '__main__':
    h = Harness(verbose=True)
    print('secret =', h.get_app_secret(1756800000000, 'A' * 40))
    print('calls  =', h.calls)
