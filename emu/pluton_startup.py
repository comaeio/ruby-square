#!/usr/bin/env python3

import struct
import sys
from capstone import *
from collections import namedtuple
from unicorn import *
from unicorn.arm_const import *


CS = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
LOAD_ADDR = None
CODE = None
CODE_SIZE = None
STACK_SIZE = 0x2000
STACK_BASE = 0x102fff + 1 - STACK_SIZE  # see 0x108290
INSN_COUNT = 0


# List of visited addresses.
TRACE_BUFFER = []

# File to write trace information to.
TRACE_FILE = None

# Binary input file.
INPUT_FILE = None


# Memory access type.
Access = namedtuple("Access", "addr type size")


# Known access types.  Read-write is tracked as two different accesses.
class AccessType:
    access_type = None

    def __init__(self, uc_access_type):
        if uc_access_type == UC_MEM_READ:
            self.access_type = "read"

        elif uc_access_type == UC_MEM_WRITE:
            self.access_type = "write"

        else:
            print("Error: unexpected access type: {}".format(uc_access_type))
            exit(1)

    def __str__(self):
        return self.access_type

    def __eq__(self, other):
        return self.access_type == other.access_type

    def __lt__(self, other):
        return self.access_type < other.access_type


# Set of memory accesses.
ACCESSES = list(
    # See 0x10dbb0.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_WRITE), size=1),
        range(0x106020, 0x106020 + 0x1e50))
) + [
    # See 0x10c93e.
    Access(addr=0xe000ed94, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10c944.
    Access(addr=0xe000ed94, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x10c94e.
    Access(addr=0xe000ed90, type=AccessType(UC_MEM_READ), size=4),

    # See 0x109f26.
    Access(addr=0xe000ed98, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x109ede.
    Access(addr=0xe000ed9c, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x109f16.
    Access(addr=0xe000eda0, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x10889a.
    Access(addr=0x2108000c, type=AccessType(UC_MEM_READ), size=4),

    # See 0x1088a0.
    Access(addr=0x2108000c, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x1088a2.
    Access(addr=0x21020030, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x10a142.
    Access(addr=0xe000ed08, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x10a150.
    Access(addr=0xe000ed24, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x10a186.
    Access(addr=0x21030060, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10a18c.
    Access(addr=0x21030060, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x108b16.
    Access(addr=0x11ffe8, type=AccessType(UC_MEM_WRITE), size=4),
] + list(
    # See 0x108214.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=1),
        range(0x11ffe8, 0x11ffe8 + 24))
) + [
    # See 0x108270.
    Access(addr=0x11ffe0, type=AccessType(UC_MEM_WRITE), size=4),
    Access(addr=0x11ffe4, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x108baa.
    Access(addr=0x11ffec, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10886a.
    Access(addr=0x21020034, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x108872.
    Access(addr=0x21020038, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x108878.
    Access(addr=0x21020030, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10ca74.
    Access(addr=0x1060b4, type=AccessType(UC_MEM_WRITE), size=4),

    # See 0x10ca7c.
    # XXX: Random address.
    Access(addr=0xfffff000, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10ca8e.
    # XXX: Random address.
    Access(addr=0xfffff004, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10ca9c.
    # XXX: Random address.
    Access(addr=0xfffff00c, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10caa0.
    # XXX: Random address.
    Access(addr=0xfffff008, type=AccessType(UC_MEM_READ), size=4),

    # See 0x10caa2.
    Access(addr=0x0010616c, type=AccessType(UC_MEM_WRITE), size=4),
] + list(
    # See 0x108c90 and 0x10caa6.
    # XXX: Random address.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=4),
        range(0xffffd000, 0xffffd000 + 0x430 + 1))
) + list(
    # See 0x108c94 and 0x10caa6.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_WRITE), size=4),
        range(0x106170, 0x106170 + 0x430 + 1))
) + [
    # See 0x10cab4.
    # XXX: Random address.
    Access(addr=0xfffff010, type=AccessType(UC_MEM_READ), size=4),
] + list(
    # See 0x108c90 and 0x10cab2.
    # XXX: Random address.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=4),
        range(0xffffb000, 0xffffb000 + 0x80 + 1))
) + list(
    # See 0x108c94 and 0x10caa2.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_WRITE), size=4),
        range(0x106034, 0x106034 + 0x80 + 1))
) + list(
    # See 0x108c90 and 0x10cabe.
    # XXX: Random address.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=4),
        range(0xfffff014, 0xfffff014 + 0x80 + 1))
) + list(
    # See 0x108c94 and 0x10cabe.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_WRITE), size=4),
        range(0x1065a4, 0x1065a4 + 0x80 + 1))
)


def addr_to_offset(addr):
    global LOAD_ADDR

    assert addr >= LOAD_ADDR

    return addr - LOAD_ADDR


def yellow(s):
    return "\33[33m{}\033[0m".format(s)


def green(s):
    return "\33[32m{}\033[0m".format(s)


def red(s):
    return "\33[31m{}\033[0m".format(s)


# Need to map more memory than required by the binary due to alignment checks.
# See if the address is actually mapped.
def is_mapped(addr, access_type, size):
    global LOAD_ADDR, CODE
    global STACK_BASE, STACK_SIZE

    is_code   = addr >= LOAD_ADDR   and addr < (LOAD_ADDR + len(CODE))
    is_stack  = addr >= STACK_BASE  and addr < (STACK_BASE + STACK_SIZE)

    # Ignore 'access_type' and 'size' for these.
    if is_code or is_stack:
        return True

    for access in ACCESSES:
        if (access.addr == addr and
            access.type == access_type and
            access.size == size
        ):
            return True

    return False


def hook_mem_access(uc, uc_access_type, addr, size, value, user_data):
    access_type = AccessType(uc_access_type)

    if not is_mapped(addr, access_type, size):
        print(red("Accessing unmapped memory: 0x{:08x}, size: 0x{:08x} ({})"
              .format(addr, size, access_type)))

        flush_trace()
        print_context(uc)
        exit(1)

    # The original 'value' is only valid for 'UC_MEM_WRITE'.
    if access_type == AccessType(UC_MEM_READ):
        bytes_ = uc.mem_read(addr, size)
        value = int.from_bytes(bytes_, "little")  # XXX: hardcoded endianness

    print(green("Hook mem: addr: 0x{:08x}, size: 0x{:08x}, value: 0x{:08x} ({})"
          .format(addr, size, value, access_type)))

    add_trace_mem(uc, addr, size, value, access_type)


def hook_block(uc, addr, size, user_data):
    offset = addr_to_offset(addr)

    print(yellow("Hook block: 0x{offset:08x} 0x{addr:08x}"
        .format(
            offset = offset,
            addr   = addr)))


def hook_code(uc, addr, size, user_data):
    global CODE
    global INSN_COUNT

    offset = addr_to_offset(addr)
    disasm = CS.disasm(CODE[offset:], 0, 1)
    insn = next(disasm)

    INSN_COUNT += 1
    add_trace(uc, addr)

    # XXX: For Pluton: printf (always failure?).
    if addr == 0x10a2c4:
        print(red("Executing printf; failure?"))

        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)

        msg = uc.mem_read(r0, 0x100)
        msg = msg[1:]  # skip the byte
        msg = msg.split(b"\x00")[0]  # all until the NULL byte
        msg = msg.decode("utf-8")

        print(red("R0: {}".format(msg)))
        print(red("R1: 0x{:08x}".format(r1)))
        print(red("R2: 0x{:08x}".format(r2)))

        flush_trace()
        print_context(uc)
        exit(1)

    # XXX: Always failure?
    if addr == 0x108d3c:
        print(red("Executing panic; failure?"))

        flush_trace()
        print_context(uc)
        exit(1)

    # XXX: Skip the initial memset(0) to save time.
    if addr == 0x10dbb0:
        # Zero the buffer just in case.
        uc.mem_write(0x106020, b"\x00" * 0x1e50)
        # Jump to the next instruction in thumb mode.
        uc.reg_write(UC_ARM_REG_PC, 0x10dbb4 | 1)

    if addr == 0x108c60:
        dst  = uc.reg_read(UC_ARM_REG_R0)
        val  = uc.reg_read(UC_ARM_REG_R1)
        size = uc.reg_read(UC_ARM_REG_R2)

        print(red("Executing memset(0x{:08x}, 0x{:08x}, 0x{:08x})"
              .format(dst, val, size)))

    if addr == 0x108c70:
        dst  = uc.reg_read(UC_ARM_REG_R0)
        src  = uc.reg_read(UC_ARM_REG_R1)
        size = uc.reg_read(UC_ARM_REG_R2)

        print(red("Executing memcpy(0x{:08x}, 0x{:08x}, 0x{:08x})"
              .format(dst, src, size)))

    if not is_mapped(addr, AccessType(UC_MEM_READ), size):
        print(red("Executing unmapped memory: 0x{:08x}"
              .format(addr)))

        flush_trace()
        print_context(uc)
        exit(1)

    print("Hook code: 0x{offset:08x} 0x{addr:08x} {bytes_:<8} {mnem} {ops}"
        .format(
            offset = offset,
            addr   = addr,
            bytes_ = insn.bytes.hex(),
            mnem   = insn.mnemonic,
            ops    = insn.op_str))


class Emu:
    emu       = None
    code      = None
    load_addr = None
    end_addr  = None

    def __init__(self, load_addr, code):
        global STACK_BASE, STACK_SIZE

        self.emu       = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        self.code      = code  # all binary data
        self.load_addr = load_addr
        code_size      = 4 * 1024 * 1024  # 4 MB
        self.end_addr  = self.load_addr + code_size

        assert code_size >= len(code)

        # Code.
        # Note: memory addresses need to be aligned.
        self.emu.mem_map(self.load_addr, code_size)
        self.emu.mem_write(self.load_addr, self.code)

        # Stack.
        self.emu.mem_map(STACK_BASE, STACK_SIZE)
        # XXX: Do not write to SP here, the start routine will do that.

        # Hooks.
        self.emu.hook_add(UC_HOOK_BLOCK, hook_block)
        self.emu.hook_add(UC_HOOK_CODE, hook_code)
        self.emu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)

    def run(self, start_addr, end_addr=None, count=0):
        if end_addr is None:
            end_addr = self.end_addr

        return self.emu.emu_start(
            begin   = start_addr,
            until   = end_addr,
            timeout = 0,  # may not print errors otherwise
            count   = count)

    def reg_read(self, reg):
        return self.emu.reg_read(reg)

    def reg_write(self, reg, value):
        return self.emu.reg_write(reg, value)

    def mem_map(self, addr, size):
        return self.emu.mem_map(addr, size)

    def mem_write(self, addr, data):
        return self.emu.mem_write(addr, data)


REGISTERS = {
    "cpsr": UC_ARM_REG_CPSR,

    "lr":   UC_ARM_REG_LR,
    "sp":   UC_ARM_REG_SP,

    "r0":   UC_ARM_REG_R0,
    "r1":   UC_ARM_REG_R1,
    "r2":   UC_ARM_REG_R2,
    "r3":   UC_ARM_REG_R3,
    "r4":   UC_ARM_REG_R4,
    "r5":   UC_ARM_REG_R5,
    "r6":   UC_ARM_REG_R6,
    "r7":   UC_ARM_REG_R7,
    "r8":   UC_ARM_REG_R8,
    "r9":   UC_ARM_REG_R9,
    "r10":  UC_ARM_REG_R10,
    "r11":  UC_ARM_REG_R11,
    "r12":  UC_ARM_REG_R12,
}


def add_trace_mem(uc, addr, size, value, access_type):
    global TRACE_BUFFER

    if not TRACE_BUFFER:
        return

    s = (" ; mem: addr: 0x{:08x}, size: 0x{:08x}, value: 0x{:08x} ({})"
         .format(addr, size, value, access_type))

    # XXX: Use locking here: callbacks are probably racy.
    TRACE_BUFFER[-1] += s


def add_trace(uc, addr):
    global TRACE_BUFFER

    s = "0x{:08x}".format(addr)

    # Print all registers as it's easier than tracking the changes.
    # Add CPSR too as it's changed often.
    for reg in REGISTERS:
        value = uc.reg_read(REGISTERS[reg])
        s += " ; {:<4} = 0x{:08x}".format(reg, value)

    TRACE_BUFFER.append(s)


def flush_trace():
    global TRACE_BUFFER, TRACE_FILE, INPUT_FILE
    global LOAD_ADDR

    with open(TRACE_FILE, "w") as f:
        # Write the header.
        f.write("# input file: {}\n".format(INPUT_FILE))
        f.write("# load address: 0x{:08x}\n".format(LOAD_ADDR))

        for s in TRACE_BUFFER:
            f.write("{}\n".format(s))

    TRACE_BUFFER = []


def print_context(emu):
    print("PC: 0x{:08x}".format(emu.reg_read(UC_ARM_REG_PC)))
    print("SP: 0x{:08x}".format(emu.reg_read(UC_ARM_REG_SP)))
    print("Instructions: {}".format(INSN_COUNT))


def main():
    global CODE, LOAD_ADDR
    global INPUT_FILE, TRACE_FILE

    INPUT_FILE = sys.argv[1]  # XXX: Pluton binary
    TRACE_FILE = sys.argv[2]  # trace file

    LOAD_ADDR  = 0x108000  # XXX: for Pluton
    start_addr = 0x108290  # XXX: start
    count      = 100000

    with open(INPUT_FILE, "rb") as f:
        CODE = f.read()
        print("Read bytes: 0x{:x}".format(len(CODE)))

    print("Initializing emulator")
    emu = Emu(load_addr=LOAD_ADDR, code=CODE)

    try:
        emu.reg_write(UC_ARM_REG_PC, start_addr)
        offset = addr_to_offset(start_addr)
        print("Bytes at PC: {}".format(CODE[offset:offset + 16].hex()))

        # Stack.
        # XXX: Do not write to SP here, the start routine will do that.

        # Memory.
        # Helper buffer used by r0 buffer at 0x10caa0.
        buf_0x10caa0_addr = 0xffffd000
        buf_0x10caa0_size = 0x1000
        emu.mem_map(buf_0x10caa0_addr, buf_0x10caa0_size)
        # Write garbage to it to make it easier to see in the trace since
        # the layout is not known.
        emu.mem_write(buf_0x10caa0_addr, b"\x42" * buf_0x10caa0_size)

        # Helper buffer used by r0 buffer at 0x10cab4.
        buf_0x10cab4_addr = 0xffffb000
        buf_0x10cab4_size = 0x1000
        emu.mem_map(buf_0x10cab4_addr, buf_0x10cab4_size)
        # Write garbage to it to make it easier to see in the trace since
        # the layout is not known.
        emu.mem_write(buf_0x10cab4_addr, b"\x43" * buf_0x10cab4_size)

        r0_buf_addr = 0xfffff000  # XXX: random address
        r0_buf_size = 0x1000
        emu.mem_map(r0_buf_addr, r0_buf_size)
        # Write garbage to it to make it easier to see in the trace since
        # the layout is not known.
        emu.mem_write(r0_buf_addr, b"\x41" * r0_buf_size)
        # See 0x10ca7c.
        emu.mem_write(r0_buf_addr, struct.pack("<L", 0x5afd5bfd))  # magic
        # See 0x10ca8e.
        emu.mem_write(r0_buf_addr + 4, struct.pack("<L", 1))  # version?
        # See 0x10caa0.
        emu.mem_write(r0_buf_addr + 8, struct.pack("<L", buf_0x10caa0_addr))
        # See 0x10cab4.
        emu.mem_write(r0_buf_addr + 0x10, struct.pack("<L", buf_0x10cab4_addr))

        # XXX: See 'ACCESSES'.
        emu.mem_map(0x106000,   0x2000)
        emu.mem_map(0xe000e000, 0x1000)
        emu.mem_map(0x21080000, 0x1000)
        emu.mem_map(0x21020000, 0x1000)
        emu.mem_map(0x21030000, 0x1000)

        # Registers.
        emu.reg_write(UC_ARM_REG_R0, r0_buf_addr)

        print("Starting emulation")
        emu.run(start_addr=start_addr | 1, count=count)  # OR 1 for thumb

        print("Done")
        flush_trace()
        print_context(emu)

    except UcError as e:
        print("Error: {}".format(e))
        flush_trace()
        print_context(emu)


if __name__ == "__main__":
    main()
