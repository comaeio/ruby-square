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
STACK_SIZE = 4096
STACK_BASE = 0xffffffff + 1 - STACK_SIZE
BUFFER_SIZE = 0x1000  # input buffer
BUFFER_BASE = 0x1000
INSN_COUNT = 0


# List of visited addresses.
TRACE_BUFFER = []

# File to write trace information to.
TRACE_FILE = None

# Binary input file.
INPUT_FILE = None

# Current input data.
INPUT_BUFFER = None


# Address -> handler name.
HANDLER_NAMES = {
    0x10bd14: "PlRApiSetPostcode",
    0x10b1f8: "PlRApiGetBootModeFlags",
    0x109b8a: "PlRApiDeviceReset",
    0x10b1dc: "PlRApiReadRng",
    0x10b81c: "PlpCommandIndex_48",
    0x10b7e0: "PlpCommandIndex_49",
    0x10b7a8: "PlpCommandIndex_50",
    0x10b770: "PlpCommandIndex_51",
    0x10b73c: "PlpCommandIndex_52",
    0x10b700: "PlpCommandIndex_53",
    0x10b0a0: "PlpCommandIndex_54",
    0x10b6b0: "PlpCommandIndex_55",
    0x109b7e: "PlpCommandIndex_56",
    0x10b674: "PlpCommandIndex_57",
    0x10b084: "PlpCommandIndex_58",
    0x10c5e0: "PlRApiGetSecurityState",
    0x10b518: "PlpCommandIndex_66",
    0x10b498: "PlRApiIsCapabilityEnabled",
    0x10b4dc: "PlRApiGetEnabledCapabilities",
    0x10b160: "PlRApiGetManufacturingState",
    0x10b3d8: "PlRApiSetManufacturingState",
    0x10b0e8: "PlRApiGenerateClientAuthKey",
    0x10b2c8: "PlRApiCommitClientAuthKey",
    0x10c390: "PlRApiGetTenantPublicKey",
    0x10c1c0: "PlRApiProcessAttestation",
    0x10bff4: "PlRApiSignWithTenantAttestationKey",
    0x10b264: "PlpCommandIndex_4",
    0x10b138: "PlpCommandIndex_83",
    0x10b344: "PlpCommandIndex_84",
    0x10b854: "PlpCommandIndex_85",
    0x10c67c: "PlRApiDecodeCapabilities",
}


# The handler that is currently being executed.
CURRENT_HANDLER_NAME = None


# Memory access type.
Access = namedtuple("Access", "addr type size")


# Accesses are likely to depend on input data, so track that.
AccessKey = namedtuple("AccessKey", "name input")


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


# Handler name and input -> accessed addresses.
HANDLER_ACCESSES = {
    # First random input with matching size.
    AccessKey(
        name="PlRApiSetPostcode",
        input=b"\x08\x00\x41\x42\x43\x44\x45\x46\x47\x48"):
    [
        # Used by PlRApiSetPostcode at 0x00000b16 0x00108b16.
        Access(addr=0x0011ffe8, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe0, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe4, type=AccessType(UC_MEM_WRITE), size=4),
    ] +
        # Used by PlRApiSetPostcode at 0x00000214 0x00108214.
        # See the check at 0x108244.
        list(map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=1),
                 range(0x0011ffe8, 0x0011ffe8 + 0x18))),

    # Previous random input adjusted to pass the check at 0x108b2c.
    AccessKey(
        name="PlRApiSetPostcode",
        input=b"\x08\x00\x41\x42\x99\x99\x99\x39\x47\x48"):
    [
        # Used by PlRApiSetPostcode at 0x00000b16 0x00108b16.
        Access(addr=0x0011ffe8, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe0, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe4, type=AccessType(UC_MEM_WRITE), size=4),
    ] +
        # Used by PlRApiSetPostcode at 0x00000214 0x00108214.
        # See the check at 0x108244.
        list(map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=1),
                 range(0x0011ffe8, 0x0011ffe8 + 0x18))),

    # Previous random input adjusted to pass the check at 0x108b34.
    AccessKey(
        name="PlRApiSetPostcode",
        input=b"\x08\x00\x41\x42\x00\x00\xf0\x20\x47\x48"):
    [
        # Used by PlRApiSetPostcode at 0x00000b16 0x00108b16.
        Access(addr=0x0011ffe8, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe0, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe4, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000baa 0x00108baa.
        Access(addr=0x0011ffec, type=AccessType(UC_MEM_READ), size=4),

        # Used by PlRApiSetPostcode at 0x0000086a 0x0010886a.
        Access(addr=0x21020034, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000872 0x00108872.
        Access(addr=0x21020038, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000878 0x00108878.
        Access(addr=0x21020030, type=AccessType(UC_MEM_READ), size=4),

        # Used by PlRApiSetPostcode at 0x00000888 0x00108888.
        Access(addr=0x21020030, type=AccessType(UC_MEM_WRITE), size=4),
    ] +
        # Used by PlRApiSetPostcode at 0x00000214 0x00108214.
        # See the check at 0x108244.
        list(map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=1),
                 range(0x0011ffe8, 0x0011ffe8 + 0x18))),

    # Previous random input adjusted to pass the check at 0x108b50.
    AccessKey(
        name="PlRApiSetPostcode",
        input=b"\x08\x00\x41\x42\x00\x00\x61\x40\x47\x48"):
    [
        # Used by PlRApiSetPostcode at 0x00000b16 0x00108b16.
        Access(addr=0x0011ffe8, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe0, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe4, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000b52 0x00108b52.
        Access(addr=0x0011ffec, type=AccessType(UC_MEM_READ), size=4),

        # Used by PlRApiSetPostcode at 0x00000b58 0x00108b58.
        Access(addr=0x0011ffec, type=AccessType(UC_MEM_WRITE), size=4),
    ] +
        # Used by PlRApiSetPostcode at 0x00000214 0x00108214.
        # See the check at 0x108244.
        list(map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=1),
                 range(0x0011ffe8, 0x0011ffe8 + 0x18))),

    # Previous random input with size 4 adjusted to pass the check at 0x108b50.
    AccessKey(
        name="PlRApiSetPostcode",
        input=b"\x04\x00\x00\x00\x00\x00\x61\x40\x47\x48"):
    [
        # Used by PlRApiSetPostcode at 0x00000b16 0x00108b16.
        Access(addr=0x0011ffe8, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe0, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000270 0x00108270.
        Access(addr=0x0011ffe4, type=AccessType(UC_MEM_WRITE), size=4),

        # Used by PlRApiSetPostcode at 0x00000b52 0x00108b52.
        Access(addr=0x0011ffec, type=AccessType(UC_MEM_READ), size=4),

        # Used by PlRApiSetPostcode at 0x00000b58 0x00108b58.
        Access(addr=0x0011ffec, type=AccessType(UC_MEM_WRITE), size=4),
    ] +
        # Used by PlRApiSetPostcode at 0x00000214 0x00108214.
        # See the check at 0x108244.
        list(map(lambda x: Access(addr=x, type=AccessType(UC_MEM_READ), size=1),
                 range(0x0011ffe8, 0x0011ffe8 + 0x18))),

    AccessKey(
        name="PlRApiDecodeCapabilities",
        # u16 size must be >= 1028 to match
        # 'sizeof(azure_sphere_decode_capabilities_request)', which is
        # the data after padding.
        input=(b"\x04\x04" +  # u16 input size
               b"\x00\x00" +  # u16 padding
               # Data ('struct azure_sphere_decode_capabilities_request'):
               # * field: uint32_t length
               b"\x88\x01\x00\x00" +
               # * field: uint8_t capability_blob[1024]
               #   89cb30b8700c43428982f8d1a67e19f4_device_capability.bin
               b"\xfd\x5c\xfd\x5c\x01\x00\x00\x00" +
               b"\xcc\x00\x00\x00\x00\x00\x00\x00" +
               (b"\x00\x00\x00\x00\x00\x00\x00\x00" * 23) +  # save some space
               b"\x00\x00\x00\x00\x34\x58\x34\x4d" +
               b"\x03\x00\x00\x00\x49\x44\x24\x00" +
               b"\x0d\x00\x00\x00\xd8\xb5\x28\x41" +
               b"\xc2\xab\x55\x41\x9a\x33\x8a\x1f" +
               b"\x31\xed\x67\xec\xb8\x30\xcb\x89" +
               b"\x0c\x70\x42\x43\x89\x82\xf8\xd1" +
               b"\xa6\x7e\x19\xf4\x53\x47\x18\x00" +
               b"\xb3\x6d\xad\xda\xbd\xbc\xa3\x17" +
               b"\x8b\x79\x30\x82\x61\x61\xc8\x35" +
               b"\x77\x86\x51\x9f\x01\x00\x00\x00" +
               b"\x44\x42\x28\x00\xb1\x9a\xa8\x5e" +
               b"\x00\x00\x00\x00\x44\x65\x76\x69" +
               b"\x63\x65\x20\x43\x61\x70\x61\x62" +
               b"\x69\x6c\x69\x74\x79\x00\x00\x00" +
               b"\x00\x00\x00\x00\x00\x00\x00\x00" +
               b"\x00\x00\x00\x00\x7c\x00\x00\x00" +
               b"\x70\xd1\xb6\x98\xd5\x02\xf6\xfe" +
               b"\x98\x1d\xf4\x51\xb2\xe8\xcf\x06" +
               b"\xed\x08\xb9\x4b\x1c\x01\x2b\xa1" +
               b"\xb2\xe8\x7d\x6a\xda\x90\x91\xbe" +
               b"\x44\x92\x88\x59\x1d\xdf\x1a\x88" +
               b"\x8b\x0b\xb6\x40\x25\xa5\xef\x9c" +
               b"\x48\xfc\xc3\x34\x01\x0c\x15\xa2" +
               b"\x84\xea\x2c\xd1\xda\xac\x90\xe8")):
    [
    ]
}


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
    global BUFFER_BASE, BUFFER_SIZE
    global CURRENT_HANDLER_NAME, INPUT_BUFFER

    is_code   = addr >= LOAD_ADDR   and addr < (LOAD_ADDR + len(CODE))
    is_stack  = addr >= STACK_BASE  and addr < (STACK_BASE + STACK_SIZE)
    is_buffer = addr >= BUFFER_BASE and addr < (BUFFER_BASE + BUFFER_SIZE)

    # Ignore 'access_type' and 'size' for these.
    if is_code or is_stack or is_buffer:
        return True

    access_key = AccessKey(
        name=CURRENT_HANDLER_NAME,
        input=INPUT_BUFFER)

    for access in HANDLER_ACCESSES.get(access_key, []):
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
    global CURRENT_HANDLER_NAME, INPUT_BUFFER

    offset = addr_to_offset(addr)
    disasm = CS.disasm(CODE[offset:], 0, 1)
    insn = next(disasm)

    INSN_COUNT += 1
    add_trace(uc, addr)

    handler_name = HANDLER_NAMES.get(addr)
    if handler_name:
        print(red("Executing handler: {}".format(handler_name)))
        CURRENT_HANDLER_NAME = handler_name

    # XXX: For Pluton.
    if addr == 0x10bda4:
        print(red("Calling handler"))

        sp = uc.reg_read(UC_ARM_REG_SP)
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        r2 = uc.reg_read(UC_ARM_REG_R2)
        r3 = uc.reg_read(UC_ARM_REG_R3)
        r4 = uc.reg_read(UC_ARM_REG_R4)
        r5 = uc.reg_read(UC_ARM_REG_R5)

        print(red("SP: 0x{:08x}".format(sp)))
        print(red("R0: 0x{:08x}".format(r0)))
        print(red("R1: 0x{:08x}".format(r1)))
        print(red("R2: 0x{:08x}".format(r2)))
        print(red("R3: 0x{:08x}".format(r3)))
        print(red("R4: 0x{:08x}".format(r4)))
        print(red("R5: 0x{:08x}".format(r5)))

        step = 4
        for i in range(0, 4 * step, step):
            bytes_ = uc.mem_read(sp + i, step)
            value = int.from_bytes(bytes_, "little")  # XXX: hardcoded endianness
            print(red("Stack+0x{:02x}: 0x{:08x}".format(i, value)))

    # XXX: For Pluton.
    if addr == 0x10bda6:
        print(red("Handler executed"))

        access_key = AccessKey(
            name=CURRENT_HANDLER_NAME,
            input=INPUT_BUFFER)

        accesses = sorted(HANDLER_ACCESSES.get(access_key, []))

        for access in accesses:
            bytes_ = uc.mem_read(access.addr, access.size)
            value = int.from_bytes(bytes_, "little")  # XXX: hardcoded endianness
            print(red("Access: addr: 0x{:08x}, value: 0x{:08x}, size: 0x{:08x} ({})"
                  .format(access.addr, value, access.size, access.type)))

        flush_trace()
        print_context(uc)
        exit(0)

    # XXX: For Pluton: CMP R3, R1  ; compare with the provided index
    if addr == 0x10bd7a:
        print(red("R3: 0x{:08x} (table command index)"
              .format(uc.reg_read(UC_ARM_REG_R3))))
        print(red("R1: 0x{:08x} (provided command index)"
              .format(uc.reg_read(UC_ARM_REG_R1))))

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
        self.reg_write(UC_ARM_REG_SP, STACK_BASE + STACK_SIZE - 4)

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
    global LOAD_ADDR, INPUT_BUFFER

    with open(TRACE_FILE, "w") as f:
        # Write the header.
        f.write("# input file: {}\n".format(INPUT_FILE))
        f.write("# input buffer: {}\n".format(INPUT_BUFFER.hex()))
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
    global BUFFER_BASE, BUFFER_SIZE
    global INPUT_BUFFER
    global INPUT_FILE, TRACE_FILE

    INPUT_FILE = sys.argv[1]  # XXX: Pluton binary
    TRACE_FILE = sys.argv[2]  # trace file

    # XXX: Support different load and map addresses.
    LOAD_ADDR  = 0x108000  # XXX: for Pluton
    start_addr = 0x10bd44  # XXX: PlutonCommandHandler
    count      = 10000

    with open(INPUT_FILE, "rb") as f:
        CODE = f.read()
        print("Read bytes: 0x{:x}".format(len(CODE)))

    print("Initializing emulator")
    emu = Emu(load_addr=LOAD_ADDR, code=CODE)

    try:
        emu.reg_write(UC_ARM_REG_PC, start_addr)
        offset = addr_to_offset(start_addr)
        print("Bytes at PC: {}".format(CODE[offset:offset + 16].hex()))

        # XXX: For 'PlRApiDecodeCapabilities'.
        input_size = 0x404
        INPUT_BUFFER  = struct.pack("<H", input_size)  # u16 input size
        INPUT_BUFFER += b"\x00\x00"  # u16 padding
        # Data:
        INPUT_BUFFER += b"\x88\x01\x00\x00"
        INPUT_BUFFER += (
            b"\xfd\x5c\xfd\x5c\x01\x00\x00\x00" +
            b"\xcc\x00\x00\x00\x00\x00\x00\x00" +
            (b"\x00\x00\x00\x00\x00\x00\x00\x00" * 23) +  # save some space
            b"\x00\x00\x00\x00\x34\x58\x34\x4d" +
            b"\x03\x00\x00\x00\x49\x44\x24\x00" +
            b"\x0d\x00\x00\x00\xd8\xb5\x28\x41" +
            b"\xc2\xab\x55\x41\x9a\x33\x8a\x1f" +
            b"\x31\xed\x67\xec\xb8\x30\xcb\x89" +
            b"\x0c\x70\x42\x43\x89\x82\xf8\xd1" +
            b"\xa6\x7e\x19\xf4\x53\x47\x18\x00" +
            b"\xb3\x6d\xad\xda\xbd\xbc\xa3\x17" +
            b"\x8b\x79\x30\x82\x61\x61\xc8\x35" +
            b"\x77\x86\x51\x9f\x01\x00\x00\x00" +
            b"\x44\x42\x28\x00\xb1\x9a\xa8\x5e" +
            b"\x00\x00\x00\x00\x44\x65\x76\x69" +
            b"\x63\x65\x20\x43\x61\x70\x61\x62" +
            b"\x69\x6c\x69\x74\x79\x00\x00\x00" +
            b"\x00\x00\x00\x00\x00\x00\x00\x00" +
            b"\x00\x00\x00\x00\x7c\x00\x00\x00" +
            b"\x70\xd1\xb6\x98\xd5\x02\xf6\xfe" +
            b"\x98\x1d\xf4\x51\xb2\xe8\xcf\x06" +
            b"\xed\x08\xb9\x4b\x1c\x01\x2b\xa1" +
            b"\xb2\xe8\x7d\x6a\xda\x90\x91\xbe" +
            b"\x44\x92\x88\x59\x1d\xdf\x1a\x88" +
            b"\x8b\x0b\xb6\x40\x25\xa5\xef\x9c" +
            b"\x48\xfc\xc3\x34\x01\x0c\x15\xa2" +
            b"\x84\xea\x2c\xd1\xda\xac\x90\xe8")

        # Stack.
        # See the layout at 0x10bd4e.
        sp = emu.reg_read(UC_ARM_REG_SP)
        sp -= 4
        emu.mem_write(sp, struct.pack("<L", input_size + 4))
        emu.reg_write(UC_ARM_REG_SP, sp)

        # Registers.
        emu.mem_map(BUFFER_BASE, BUFFER_SIZE)
        emu.mem_write(BUFFER_BASE, INPUT_BUFFER)
        emu.reg_write(UC_ARM_REG_R3, BUFFER_BASE)

        # XXX: Used by PlRApiSetPostcode.
        # emu.mem_map(0x21020000, 0x1000)

        # XXX: For 'PlutonCommandHandler': command index.
        # emu.reg_write(UC_ARM_REG_R2, 2)  # PlRApiSetPostcode
        emu.reg_write(UC_ARM_REG_R2, 0x56)  # PlRApiDecodeCapabilities
        # XXX: For 'PlutonCommandHandler': channel? (2 or 4).
        emu.reg_write(UC_ARM_REG_R1, 2)

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
