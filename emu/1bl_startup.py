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
STACK_SIZE = 0x1000
STACK_BASE = 0x105fff + 1 - STACK_SIZE  # see 0x108290
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
    # See 0x10356e.
    map(lambda x: Access(addr=x, type=AccessType(UC_MEM_WRITE), size=1),
        range(0x104080, 0x104080 + 0x150))
) + [
    Access(addr=0xe000ed90, type=AccessType(UC_MEM_READ), size=4),

    Access(addr=0xe000ed94, type=AccessType(UC_MEM_READ), size=4),
    Access(addr=0xe000ed94, type=AccessType(UC_MEM_WRITE), size=4),

    Access(addr=0xe000ed98, type=AccessType(UC_MEM_WRITE), size=4),

    Access(addr=0xe000ed9c, type=AccessType(UC_MEM_WRITE), size=4),

    Access(addr=0xe000eda0, type=AccessType(UC_MEM_READ), size=4),
    Access(addr=0xe000eda0, type=AccessType(UC_MEM_WRITE), size=4),

    Access(addr=0x1041b8, type=AccessType(UC_MEM_READ), size=4),
    Access(addr=0x104080, type=AccessType(UC_MEM_READ), size=4),
    Access(addr=0x104108, type=AccessType(UC_MEM_READ), size=4),
]


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

    if addr == 0x10145a:
        print(red("panic; error?"))
        flush_trace()
        print_context(uc)
        exit(1)

    if addr == 0x101934:
        dst  = uc.reg_read(UC_ARM_REG_R0)
        val  = uc.reg_read(UC_ARM_REG_R1)
        size = uc.reg_read(UC_ARM_REG_R2)

        print(red("Executing memset(0x{:08x}, 0x{:08x}, 0x{:08x})"
              .format(dst, val, size)))

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
        # code_size      = 4 * 1024 * 1024  # 4 MB
        code_size      = 0x4000
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

    INPUT_FILE = sys.argv[1]  # XXX: e615 1BL binary
    TRACE_FILE = sys.argv[2]  # trace file

    LOAD_ADDR  = 0x100000  # XXX: for e615 1BL
    start_addr = 0x100484  # XXX: start
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
        # XXX: See 'ACCESSES'.
        emu.mem_map(0x00104000, 0x1000)
        emu.mem_map(0xe000e000, 0x1000)

        # https://developer.arm.com/documentation/ddi0439/b/Memory-Protection-Unit/MPU-programmers-model
        # Address     Name      Type  Reset       Description
        # 0xe000ed90  MPU_TYPE  RO    0x00000800  MPU Type Register
        # 0xe000ed94  MPU_CTRL  RW    0x00000000  MPU Control Register
        emu.mem_write(0xe000ed90, struct.pack("<L", 0x00000800))
        emu.mem_write(0xe000ed94, struct.pack("<L", 0))

        # Registers.
        # XXX: todo.

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
