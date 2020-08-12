#!/usr/bin/env python3

import logging
import struct

from manticore.native import Manticore
from manticore.core.plugin import (
    InstructionCounter, Visited, Tracer, RecordSymbolicBranches)
from manticore.core.manticore import set_verbosity


FILE      = "./bin/09a87fd5eea743799cf162994e0b1958_pluton_runtime.bin_elf"
VERBOSITY = 3  # 1 -- default, 3 -- to see the instructions


logger = logging.getLogger("manticore.main")
set_verbosity(VERBOSITY)


# Avoid writing anything to 'STDIN'.
m = Manticore(FILE, concrete_start="", stdin_size=0)


# Same as in 'manticore/native/cli.py'.
m.register_plugin(InstructionCounter())
m.register_plugin(Visited())
m.register_plugin(Tracer())
m.register_plugin(RecordSymbolicBranches())


def red(s):
    return "\33[31m{}\033[0m".format(s)


# The fake entrypoint is set to 'PlutonCommandHandler'.  Initialize the state
# necessary for calling a handler.
@m.hook(0x10bd44)
def hook_pluton_command_handler(state):
    print(red("Starting emulation"))

    # Update the Z3 timeout.
    from manticore.core.smtlib.solver import consts
    smt_timeout = 60 * 60  # seconds
    consts.update(name="timeout", value=smt_timeout, default=smt_timeout)

    # Stack.
    stack_addr = 0xfffff000
    stack_size = 0x1000
    stack = state.cpu.memory.mmap(stack_addr, stack_size, "rw")
    state.cpu.SP = stack + stack_size - 4

    # Input buffer.
    # XXX: In reality, this should be somewhere on the stack, but this is
    # easier than figuring out the layout.  Fix this later if it's an issue.
    input_buf_addr = 0xffff7000
    input_buf_size = 0x1000
    state.cpu.memory.mmap(input_buf_addr, input_buf_size, "rw")

    # input_data_size = 10  # for 'PlRApiSetPostcode'
    input_data_size = 1028  # for 'PlRApiDecodeCapabilities'
    input_data = state.new_symbolic_buffer(input_data_size)

    # Generic:
    # u16 input size
    state.constrain(input_data[0:2] == struct.pack("<H", input_data_size))
    # u16 padding
    state.constrain(input_data[2:4] == struct.pack("<H", 0))

    # XXX: For PlRApiDecodeCapabilities:
    # u16 input size
    # struct azure_sphere_decode_capabilities_request:
    # uint32_t length (from the sample binary)
    state.constrain(input_data[4:8] == struct.pack("<L", 392))
    # uint8_t capability_blob[1024] (magic from the sample binary)
    state.constrain(input_data[8:12] == b"\xfd\x5c\xfd\x5c")
    # unknown, maybe version
    state.constrain(input_data[12:16] == struct.pack("<L", 1))
    # offset to 4X4M metadata in the file
    state.constrain(input_data[16:20] == struct.pack("<L", 0xcc))
    # 4X4M metadata magic at offset 0xcc in the sample
    state.constrain(
        input_data[4 + 4 + 0xcc:4 + 4 + 0xcc + 4] == b"\x34\x58\x34\x4d")
    # ImageMetadataHeader.SectionCount (3 in the sample)
    # XXX: Try values larger and smaller than this.
    # XXX: A very large value results in an OOB read at 0x10acf2.
    # Note that r0 also affects r4 later, so these need to be in bounds
    # to avoid triggering OOB at 0x10acf2 address too.
    state.constrain(
        input_data[4 + 4 + 0xd0:4 + 4 + 0xd0 + 4] == struct.pack("<L", 3))
    # ImageMetadataSectionHeader.DataLength of each section based on the
    # sample.
    state.constrain(
        input_data[4 + 4 + 0xd6:4 + 4 + 0xd6 + 2] == struct.pack("<H", 0x24))
    state.constrain(
        input_data[4 + 4 + 0xfe:4 + 4 + 0xfe + 2] == struct.pack("<H", 0x18))
    state.constrain(
        input_data[4 + 4 + 0x11a:4 + 4 + 0x11a + 2] == struct.pack("<H", 0x28))
    # 4X4M metadata size
    state.constrain(
        input_data[4 + 4 + 0x144:4 + 4 + 0x144 + 4] == struct.pack("<L", 0x7c))

    state.cpu.write_bytes(input_buf_addr, input_data)

    # See the layout at 0x10bd4e.
    state.cpu.SP -= 4
    state.cpu.write_bytes(state.cpu.SP, struct.pack("<L", input_data_size + 4))

    # Registers.
    # state.cpu.R11 = state.new_symbolic_value(nbits=64, label="R11")  # symbolic
    state.cpu.R3 = input_buf_addr
    # state.cpu.R2 = 2  # command index = 'PlRApiSetPostcode'
    state.cpu.R2 = 0x56  # command index = 'PlRApiDecodeCapabilities'
    state.cpu.R1 = 2  # channel? (2 or 4)


# XXX: For PlRApiDecodeCapabilities: an unknown memory region is used starting
# from 0x10adf4.  Skip this part and start emulating from 0x10ade2, where
# the input buffer is first used again.
# (not used here) R9 = 13 (ImageType, hardcoded by the caller == firmware config)
# R8 = ptr to the start of signature at the end
# R7 = ptr to the start of buffer/file (.capability_blob start)
# R6 = buf length/device capability file size - 64 (start of signature at the end)
# Everything else comes from memory.
@m.hook(0x10adf4)
def hook_sym_mem(state):
    state.cpu.write_bytes(
        state.cpu.SP + 0xe0 - 0x6c,
        struct.pack("<L", 32))  # set at 0x10aee4
    state.cpu.PC = 0x10ade2

# XXX: For PlRApiDecodeCapabilities: can skip this memset as it sets something
# in device memory.
# 001091D4 FF F7 44 FD BL      memset
# R2 = 32 (comes from tlv_32_byte_struct.length)
# R1 = 0xcc
# R0 = 0x2f020180
@m.hook(0x1091d4)
def hook_memset_cc(state):
    state.cpu.R0 = 0x2f020180
    state.cpu.PC = 0x1091d8


@m.hook(0x10bd14)
def hook_set_postcode(state):
    print(red("Found PlRApiSetPostcode"))

@m.hook(0x10c67c)
def hook_decode_capabilities(state):
    print(red("Found PlRApiDecodeCapabilities"))


# Do not spend time investigating these branches as they lead to failure.
@m.hook(0x10bd66)
def hook_pluton_command_handler_failure1(state):
    state.abandon()

@m.hook(0x10bd86)
def hook_pluton_command_handler_failure2(state):
    state.abandon()

@m.hook(0x10bdc0)
def hook_pluton_command_handler_failure3(state):
    state.abandon()

@m.hook(0x10bd24)
def hook_set_postcode_failure1(state):
    state.abandon()

@m.hook(0x10c6b0)
def hook_decode_capabilities_failure1(state):
    state.abandon()

@m.hook(0x10c6ce)
def hook_decode_capabilities_failure2(state):
    state.abandon()

@m.hook(0x10c7cc)
def hook_decode_capabilities_failure3(state):
    state.abandon()

@m.hook(0x10c70e)
def hook_decode_capabilities_failure4(state):
    state.abandon()

@m.hook(0x10ad5a)
def hook_sub_10ac88_failure1(state):
    state.abandon()

@m.hook(0x10ad8c)
def hook_sub_10ac88_failure2(state):
    state.abandon()

@m.hook(0x10af32)
def hook_sub_10ac88_failure3(state):
    state.abandon()

@m.hook(0x10af24)
def hook_sub_10ac88_failure4(state):
    state.abandon()

@m.hook(0x10ad9c)
def hook_sub_10ac88_failure5(state):
    state.abandon()

@m.hook(0x10adae)
def hook_sub_10ac88_failure6(state):
    state.abandon()

@m.hook(0x10acc4)
def hook_sub_10ac88_failure7(state):
    state.abandon()

@m.hook(0x10ad64)
def hook_sub_10ac88_failure8(state):
    state.abandon()

# This is just an explored code path that doesn't look
# very interesting.
@m.hook(0x10ad92)
def hook_sub_10ac88_failure9(state):
    state.abandon()

# This looks like the panic handler.
@m.hook(0x108d3c)
def hook_panic(state):
    state.abandon()


# This is the next instruction after branching to the handler.  If we are
# here, the handler was successfully executed.  No need to emulate further.
@m.hook(0x10bda6)
def hook_handler_executed(state):
    print(red("Handler executed"))
    state.abandon()


m.run()
m.finalize()
