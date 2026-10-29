#!/usr/bin/env python3
"""Map AArch64 PLT call targets in libprmp.so to imported symbol names."""
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

LIB = r'D:\apk-analysis\sweet-ai\raw\lib\arm64-v8a\libprmp.so'


class Lib:
    def __init__(self, path=LIB):
        self.path = path
        self.data = open(path, 'rb').read()
        self.elf = ELFFile(open(path, 'rb'))
        self.secs = [(s['sh_addr'], s['sh_offset'], s['sh_size'])
                     for s in self.elf.iter_sections() if s['sh_addr']]
        self.dsym = self.elf.get_section_by_name('.dynsym')
        self.got2sym = {}
        for s in self.elf.iter_sections():
            if isinstance(s, RelocationSection) and s.name == '.rela.plt':
                for r in s.iter_relocations():
                    self.got2sym[r['r_offset']] = self.dsym.get_symbol(r['r_info_sym']).name
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    def off(self, v):
        for a, o, sz in self.secs:
            if a <= v < a + sz:
                return o + (v - a)
        return None

    def read(self, v, n):
        o = self.off(v)
        return self.data[o:o + n]

    def sym_at_plt(self, addr):
        """Decode adrp+ldr in the PLT stub to find the GOT slot."""
        o = self.off(addr)
        ins = list(self.md.disasm(self.data[o:o + 16], addr))
        if not ins:
            return None
        page = None
        for i in ins:
            if i.mnemonic == 'adrp':
                page = int(i.op_str.split('#')[-1], 16)
            elif i.mnemonic == 'ldr' and page is not None:
                # format: x17, [x16, #0x123]
                import re
                m = re.search(r'\[x\d+, #(0x[0-9a-f]+)\]', i.op_str)
                if m:
                    slot = page + int(m.group(1), 16)
                    return self.got2sym.get(slot, f'<got {hex(slot)}>')
        return None


if __name__ == '__main__':
    lib = Lib()
    for a in sys.argv[1:]:
        addr = int(a, 16)
        print(hex(addr), '->', lib.sym_at_plt(addr))
