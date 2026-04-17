"""
Generates a synthetic x86-64 ELF firmware binary that contains:
  - Proper ELF header
  - AES S-box embedded in .rodata
  - SHA-256 constants in .rodata
  - High-entropy region (simulating AES-encrypted payload)
  - Some x86-64 opcodes in .text
  - MD5 init constants

Run: python generate_test_binary.py
Output: test_firmware.elf
"""

import struct
import os
import random

def sha256_k():
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]
    return b''.join(struct.pack('>I', k) for k in K)

def compute_aes_sbox():
    def gfmul(a, b):
        p = 0
        while b:
            if b & 1: p ^= a
            a = ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff
            b >>= 1
        return p

    def gfinv(a):
        if a == 0: return 0
        r, base = 1, a
        for _ in range(7):
            r = gfmul(r, r); r = gfmul(r, base)
        return gfmul(r, r)

    sbox = []
    for i in range(256):
        b = gfinv(i); sb = 0
        for bit in range(8):
            bv = ((b>>bit)&1)^((b>>((bit+4)%8))&1)^((b>>((bit+5)%8))&1) \
               ^ ((b>>((bit+6)%8))&1)^((b>>((bit+7)%8))&1)^((0x63>>bit)&1)
            sb |= (bv << bit)
        sbox.append(sb)
    return bytes(sbox)

def build_elf():
    rng = random.Random(1337)

    aes_sbox   = compute_aes_sbox()
    sha256_k_bytes = sha256_k()
    sha256_h   = struct.pack('>IIIIIIII',
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)
    md5_init   = struct.pack('<IIII', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

    # x86-64 nop sled + some opcodes
    text = bytes([
        0x55, 0x48, 0x89, 0xe5,              # push rbp; mov rbp, rsp
        0x48, 0x83, 0xec, 0x40,              # sub rsp, 64
        0x48, 0x8d, 0x35, 0x00,0x00,0x00,0x00, # lea rsi, [rip+0]
        0xb8, 0x01, 0x00, 0x00, 0x00,        # mov eax, 1
        0x0f, 0x05,                          # syscall
        0x90, 0x90, 0x90, 0x90,              # nops
        0xc9, 0xc3,                          # leave; ret
    ] + [0x90] * 100)

    # High-entropy encrypted blob
    enc_blob = bytes([rng.randint(0, 255) for _ in range(2048)])

    # Assemble .rodata
    rodata = b'\x00' * 8          # padding
    rodata += b'AES_SBOX:\x00'
    rodata += aes_sbox
    rodata += b'\x00' * 8
    rodata += b'SHA256_H:\x00'
    rodata += sha256_h
    rodata += b'SHA256_K:\x00'
    rodata += sha256_k_bytes
    rodata += b'\x00' * 8
    rodata += b'MD5_INIT:\x00'
    rodata += md5_init
    rodata += b'\x00' * 8

    # .data = encrypted payload
    data_sec = enc_blob

    # --- Build minimal ELF64 ---
    ELF_HEADER_SZ = 64
    PHDR_SZ = 56
    SHDR_SZ = 64

    text_off   = ELF_HEADER_SZ + PHDR_SZ * 3
    rodata_off = text_off   + len(text)
    data_off   = rodata_off + len(rodata)
    shstr_off  = data_off   + len(data_sec)

    shstrings  = b'\x00.text\x00.rodata\x00.data\x00.shstrtab\x00'
    idx_text    = shstrings.index(b'.text')
    idx_rodata  = shstrings.index(b'.rodata')
    idx_data    = shstrings.index(b'.data')
    idx_shstr   = shstrings.index(b'.shstrtab')
    shdrs_off   = shstr_off + len(shstrings)

    # Align
    def pad4k(x): return x  # no paging alignment for simplicity

    load_va = 0x400000

    # ELF Header (ET_EXEC, x86-64)
    elf_hdr = struct.pack('<4sBBBBBxxxxxxx',
        b'\x7fELF', 2, 1, 1, 0, 0)  # magic, 64-bit, LE, ELF ver, OS=SysV
    elf_hdr += struct.pack('<HHIQQQIHHHHHH',
        2,            # ET_EXEC
        0x3e,         # EM_X86_64
        1,            # EV_CURRENT
        load_va + text_off,  # e_entry
        ELF_HEADER_SZ,       # e_phoff
        shdrs_off,           # e_shoff
        0,            # e_flags
        ELF_HEADER_SZ,       # e_ehsize
        PHDR_SZ,             # e_phentsize
        3,            # e_phnum
        SHDR_SZ,             # e_shentsize
        5,            # e_shnum (null + text + rodata + data + shstrtab)
        4,            # e_shstrndx
    )

    # Program headers (PT_LOAD for text, rodata, data)
    def phdr(type_, flags, off, va, filesz, memsz, align=0x1000):
        return struct.pack('<IIQQQQQQ', type_, flags, off, va, va, filesz, memsz, align)

    phdrs  = phdr(1, 5,  text_off,   load_va+text_off,   len(text),     len(text))
    phdrs += phdr(1, 4,  rodata_off, load_va+rodata_off, len(rodata),   len(rodata))
    phdrs += phdr(1, 6,  data_off,   load_va+data_off,   len(data_sec), len(data_sec))

    # Section headers
    def shdr(name, type_, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        return struct.pack('<IIQQQQIIQQ', name, type_, flags, addr, off, size,
                          link, info, align, entsize)

    shdrs  = shdr(0, 0, 0, 0, 0, 0)  # null
    shdrs += shdr(idx_text,   1, 6, load_va+text_off,   text_off,   len(text),     align=16)
    shdrs += shdr(idx_rodata, 1, 2, load_va+rodata_off, rodata_off, len(rodata),   align=16)
    shdrs += shdr(idx_data,   1, 3, load_va+data_off,   data_off,   len(data_sec), align=16)
    shdrs += shdr(idx_shstr,  3, 0, 0, shstr_off, len(shstrings))

    return elf_hdr + phdrs + text + rodata + data_sec + shstrings + shdrs

if __name__ == '__main__':
    elf_data = build_elf()
    out = 'test_firmware.elf'
    with open(out, 'wb') as f:
        f.write(elf_data)
    print(f'Generated {out} ({len(elf_data):,} bytes)')
    print('Contains: AES S-Box, SHA-256 constants, MD5 init, high-entropy encrypted section')
    print(f'Architecture: x86-64 ELF')
