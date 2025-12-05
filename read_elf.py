import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

if len(sys.argv) != 2:
    print("Usage: python read_elf.py <binary>")
    sys.exit(1)

filename = sys.argv[1]

with open(filename, 'rb') as f:
    elf = ELFFile(f)
    
    for section in elf.iter_sections():
        print(section.name)
        
        if section.name == '.text':
            data = section.data()
            print(data[:50].hex())

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for instruction in md.disasm(data, 0x10000):
                print(f"0x{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}")

