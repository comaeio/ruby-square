#!/usr/bin/env python3

# Turn a binary into an ELF executable.

import argparse
import struct
import sys


class ElfMachine:
    """ELF machine type."""
    ARM   = 0x28  # 32-bit ARM
    AMD64 = 0x3e  # x86_64


# ELF header sizes.
ELF_HDR_SZ32 = 0x34
ELF_HDR_SZ64 = 0x40


# Program header entry sizes.
PROG_HDR_SZ32 = 0x20
PROG_HDR_SZ64 = 0x38


# Notes:
# * the section header table is optional for an executable
# * the program header table is only for an executable.
#
# References:
# https://cirosantilli.com/elf-hello-world#minimal-elf-file
# http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
class ElfHdr:
    """ELF header."""
    ei_magic       = None  # oft32/64: 0x00, sz32/64: 4
    ei_class       = None  # oft32/64: 0x04, sz32/64: 1
    ei_data        = None  # oft32/64: 0x05, sz32/64: 1
    ei_version     = None  # oft32/64: 0x06, sz32/64: 1
    ei_os_abi      = None  # oft32/64: 0x07, sz32/64: 1
    ei_abi_version = None  # oft32/64: 0x08, sz32/64: 1
    ei_pad         = None  # oft32/64: 0x09, sz32/64: 7

    e_type         = None  # oft32/64: 0x10, sz32/64: 2
    e_machine      = None  # oft32/64: 0x12, sz32/64: 2
    e_version      = None  # oft32/64: 0x14, sz32/64: 4

    e_entry        = None  # oft32/64: 0x18, sz32: 4, sz64: 8

    e_phoff        = None  # oft32: 0x1c, oft64: 0x20, sz32: 4, sz64: 8
    e_shoff        = None  # oft32: 0x20, oft64: 0x28, sz32: 4, sz64: 8

    e_flags        = None  # oft32: 0x24, oft64: 0x30, sz32/64: 4
    e_ehsize       = None  # oft32: 0x28, oft64: 0x34, sz32/64: 2
    e_phentsize    = None  # oft32: 0x2a, oft64: 0x36, sz32/64: 2
    e_phnum        = None  # oft32: 0x2c, oft64: 0x38, sz32/64: 2
    e_shentsize    = None  # oft32: 0x2e, oft64: 0x3a, sz32/64: 2
    e_shnum        = None  # oft32: 0x30, oft64: 0x3c, sz32/64: 2
    e_shstrndx     = None  # oft32: 0x32, oft64: 0x3e, sz32/64: 2

    def __init__(self, is32bit, e_machine, e_entry, e_shoff, e_phnum,
                 e_shnum, e_shstrndx):
        self.is32bit = is32bit

        self.ei_magic       = b"\x7f\x45\x4c\x46"
        self.ei_class       = b"\x01" if is32bit else b"\x02"
        self.ei_data        = b"\x01"  # XXX: hardcoded 'little-endian'
        self.ei_version     = b"\x01"  # always 1
        self.ei_os_abi      = b"\x00"  # XXX: hardcoded 'System V'
        self.ei_abi_version = b"\x00"  # XXX: hardcoded
        self.ei_pad         = b"\x00" * 7  # always 0

        self.e_type         = struct.pack("<H", 2)  # XXX: hardcoded 'ET_EXEC'
        self.e_machine      = struct.pack("<H", e_machine)
        self.e_version      = struct.pack("<L", 1)  # always 1

        if self.is32bit:
            self.e_entry = struct.pack("<L", e_entry)
            self.e_phoff = struct.pack("<L", 0x34)
            self.e_shoff = struct.pack("<L", e_shoff)
        else:
            self.e_entry = struct.pack("<Q", e_entry)
            self.e_phoff = struct.pack("<Q", 0x40)
            self.e_shoff = struct.pack("<Q", e_shoff)

        if is32bit:
            self.e_ehsize = struct.pack("<H", ELF_HDR_SZ32)
        else:
            self.e_ehsize = struct.pack("<H", ELF_HDR_SZ64)

        # XXX: These values are based on sample files.
        #
        # For 32-bit ARM:
        # https://static.docs.arm.com/ihi0044/g/aaelf32.pdf
        # * 0x05000000 -- ABI version 5
        # * 0x00000200 -- soft float, since ABI version 5
        # * 0x00000400 -- hard float, since ABI version 5.
        if e_machine == ElfMachine.ARM:
            self.e_flags     = b"\x00\x02\x00\x05"
            self.e_phentsize = struct.pack("<H", PROG_HDR_SZ32)
            # self.e_shentsize = b"\x28\x00"

        elif e_machine == ElfMachine.AMD64:
            self.e_flags     = b"\x00" * 4
            self.e_phentsize = struct.pack("<H", PROG_HDR_SZ64)
            # self.e_shentsize = b"\x40\x00"

        else:
            print("Unexpected machine type")
            exit(1)

        # XXX: Assumes there is no section table header.
        self.e_shentsize = struct.pack("<H", 0)

        self.e_phnum     = struct.pack("<H", e_phnum)
        self.e_shnum     = struct.pack("<H", e_shnum)
        self.e_shstrndx  = struct.pack("<H", e_shstrndx)

    def bytes(self):
        res = b""

        res += self.ei_magic
        res += self.ei_class
        res += self.ei_data
        res += self.ei_version
        res += self.ei_os_abi
        res += self.ei_abi_version
        res += self.ei_pad

        res += self.e_type
        res += self.e_machine
        res += self.e_version

        res += self.e_entry

        res += self.e_phoff
        res += self.e_shoff

        res += self.e_flags
        res += self.e_ehsize
        res += self.e_phentsize
        res += self.e_phnum
        res += self.e_shentsize
        res += self.e_shnum
        res += self.e_shstrndx

        return res


class ProgHdr:
    """Program header table entry."""
    p_type   = None  # oft32/64: 0x00, sz32/64: 4

    p_flags  = None  # oft32: 0x18, oft64: 0x04, sz32/64: 4

    p_offset = None  # oft32: 0x04, oft64: 0x08, sz32: 4, sz64: 8
    p_vaddr  = None  # oft32: 0x08, oft64: 0x10, sz32: 4, sz64: 8
    p_paddr  = None  # oft32: 0x0c, oft64: 0x18, sz32: 4, sz64: 8
    p_filesz = None  # oft32: 0x10, oft64: 0x20, sz32: 4, sz64: 8
    p_memsz  = None  # oft32: 0x14, oft64: 0x28, sz32: 4, sz64: 8
    p_align  = None  # oft32: 0x1c, oft64: 0x30, sz32: 4, sz64: 8

    def __init__(self, is32bit, load_addr, p_offset, p_size, p_align):
        self.is32bit = is32bit

        self.p_type  = b"\x01\x00\x00\x00"  # XXX: hardcoded 'PT_LOAD'
        self.p_flags = b"\x07\x00\x00\x00"  # XXX: hardcoded 'RWX'

        p_vaddr = load_addr + p_offset
        assert p_offset % p_align == p_vaddr % p_align

        if self.is32bit:
            self.p_offset = struct.pack("<L", p_offset)
            self.p_vaddr  = struct.pack("<L", p_vaddr)
            self.p_paddr  = struct.pack("<L", p_vaddr)
            self.p_filesz = struct.pack("<L", p_size)
            self.p_memsz  = struct.pack("<L", p_size)
            self.p_align  = struct.pack("<L", p_align)
        else:
            self.p_offset = struct.pack("<Q", p_offset)
            self.p_vaddr  = struct.pack("<Q", p_vaddr)
            self.p_paddr  = struct.pack("<Q", p_vaddr)
            self.p_filesz = struct.pack("<Q", p_size)
            self.p_memsz  = struct.pack("<Q", p_size)
            self.p_align  = struct.pack("<Q", p_align)

    def bytes(self):
        res = b""

        res += self.p_type

        if not self.is32bit:
            res += self.p_flags

        res += self.p_offset
        res += self.p_vaddr
        res += self.p_paddr
        res += self.p_filesz
        res += self.p_memsz

        if self.is32bit:
            res += self.p_flags

        res += self.p_align

        return res


class ArgParser:
    args = None

    def __init__(self):
        parser = argparse.ArgumentParser(add_help=False)

        required = parser.add_argument_group("required arguments")
        optional = parser.add_argument_group("optional arguments")

        optional.add_argument(
            "-h",
            "--help",
            action="help",
            default=argparse.SUPPRESS,
            help="show this help message and exit")

        required.add_argument(
            "-i",
            "--input",
            required=True,
            help="input binary file")

        required.add_argument(
            "-o",
            "--output",
            required=True,
            help="output ELF file")

        required.add_argument(
            "-t",
            "--text-addr",
            required=True,
            help="start of .text in the output file, in hex")

        required.add_argument(
            "-e",
            "--entry-offset",
            required=True,
            help="offset to entrypoint from .text in the input file, in hex")

        required.add_argument(
            "-m",
            "--machine",
            required=True,
            help="machine type: 'arm' (32-bit) or 'amd64'")

        optional.add_argument(
            "-u",
            "--thumb",
            action="store_true",
            required=False,
            help="thumb mode (set LSB of entrypoint address to 1), 'arm'-only")

        self.args = parser.parse_args()


def main():
    argparser = ArgParser()

    file_in      = argparser.args.input
    file_out     = argparser.args.output
    text_addr    = argparser.args.text_addr
    entry_offset = argparser.args.entry_offset
    e_machine    = argparser.args.machine
    is_thumb     = argparser.args.thumb

    text_addr    = int(text_addr, 16)
    entry_offset = int(entry_offset, 16)

    if e_machine == "arm":
        e_machine   = ElfMachine.ARM
        is32bit     = True
        elf_hdr_sz  = ELF_HDR_SZ32
        prog_hdr_sz = PROG_HDR_SZ32
        p_align     = 0x4

    elif e_machine == "amd64":
        e_machine   = ElfMachine.AMD64
        is32bit     = False
        elf_hdr_sz  = ELF_HDR_SZ64
        prog_hdr_sz = PROG_HDR_SZ64
        p_align     = 0x10

    else:
        print("Unexpected machine type")
        exit(1)

    data = None
    with open(file_in, "rb") as f:
        data = f.read()

    e_phnum = 1  # one entry in the program header table

    # Calculate the load address such that the start of .text in the output
    # file matches the provided 'text_addr' value.
    padding_before = 0
    load_addr = text_addr - elf_hdr_sz - (prog_hdr_sz * e_phnum)

    while load_addr % 0x1000 != 0:
        padding_before += 1
        load_addr -= 1

    e_entry  = text_addr
    e_entry += entry_offset

    if e_machine == ElfMachine.ARM and is_thumb:
        e_entry += 1

    elf_hdr = ElfHdr(
        is32bit    = is32bit,
        e_machine  = e_machine,
        e_entry    = e_entry,
        e_shoff    = 0,  # no section header table
        e_phnum    = e_phnum,
        e_shnum    = 0,  # no section header table
        e_shstrndx = 0)  # no section header table

    # No section header table after 'data'.  Must match 'elf_hdr'.
    padding_after = 0
    p_size = elf_hdr_sz + (prog_hdr_sz * e_phnum) + padding_before + len(data)

    while p_size % 0x1000 != 0:
        padding_after += 1
        p_size += 1

    prog_hdr = ProgHdr(
        is32bit   = is32bit,
        load_addr = load_addr,
        p_offset  = 0,  # 0 for the first entry
        p_size    = p_size,
        p_align   = p_align)

    # One program header table entry.  Must match 'e_phnum'.
    prog_hdr_table  = b""
    prog_hdr_table += prog_hdr.bytes()

    # Result.
    res  = b""
    res += elf_hdr.bytes()
    res += prog_hdr_table
    res += b"\x00" * padding_before
    res += data
    res += b"\x00" * padding_after
    # No section header table after 'data'.  Must match 'elf_hdr'.

    with open(file_out, "wb") as f:
        f.write(res)


if __name__ == "__main__":
    main()
