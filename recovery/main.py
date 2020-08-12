#!/usr/bin/env python3

from cobs import cobs
from crccheck.crc import CrcXmodem
import os
from serial import Serial, PARITY_NONE
import struct
import sys
from xmodem import XMODEM


# To see colors in Windows 10 Command Prompt, add this DWORD to the registry:
# [HKEY_CURRENT_USER\Console]
# "VirtualTerminalLevel"=dword:00000001
def yellow(s):
        return "\33[33m{}\033[0m".format(s)


def green(s):
        return "\33[32m{}\033[0m".format(s)


# In C# code: 'EncapsulatePayload'.
def uart_encode(payload):
    assert len(payload) <= 0xffff

    res = bytearray()
    res += struct.pack("<H", len(payload))
    res += payload

    crc = uart_crc(bytes(res))

    res += struct.pack("<H", crc)

    return bytes(res)


# In C# code: 'ExtractPayload'.
def uart_decode(payload):
    assert len(payload) >= 4

    payload_length = payload[0:2]
    payload_length = int(struct.unpack("<H", payload_length)[0])

    assert len(payload) - 4 == payload_length

    frame_crc = payload[payload_length + 2:payload_length + 2 + 2]
    frame_crc = int(struct.unpack("<H", frame_crc)[0])

    calc_crc = uart_crc(payload[0:payload_length + 2])

    assert frame_crc == calc_crc

    return payload[2:payload_length + 2]


# In C# code: 'CalculateCrc'.
def uart_crc(bs):
    return CrcXmodem.calc(bs)


class EmptyOutputError(Exception):
    pass


def decode(output):
    terminator = b"\x00"
    split = output.split(terminator)
    leftovers = terminator.join(split[1:])
    output = split[0]

    if not output:
        raise EmptyOutputError

    output = cobs.decode(output)
    print(green("[>] Decoded COBS: {}".format(output)))

    output = uart_decode(output)
    print(green("[>] Decoded UART: {}".format(output)))

    print(green("[>] Leftovers: {}".format(leftovers)))

    return output, leftovers


def read_decode(serial):
    output = serial.read(1000)
    print(green("[>] Output: {}".format(output)))
    return decode(output)


def smart_decode(serial, leftovers):
    if leftovers:
        return decode(leftovers)
    else:
        return read_decode(serial)


def encode(payload):
    print(yellow("[<] Payload: {}".format(payload)))
    uart = uart_encode(payload)
    print(yellow("[<] Encoded UART: {}".format(uart)))
    return cobs.encode(uart) + b"\x00"


def write_encode(serial, payload):
    payload = encode(payload)
    print(yellow("[<] Encoded COBS: {}".format(payload)))
    serial.write(payload)


def readline(serial):
    output = serial.readline()
    print(green("[>] Output: {}".format(output)))
    return output


def read(serial, nbytes):
    output = serial.read(nbytes)
    print(green("[>] Output: {}".format(output)))
    return output


def assert_file_size(filename, size):
    with open(filename, "rb") as f:
        assert len(f.read()) == size


# Caching serial settings is required due to 'BaudrateSwitchQuery'.
def xmodem_send(serial, stream, timeout):
    rtscts = serial.rtscts
    serial.rtscts = 0

    # From https://pypi.org/project/xmodem/.
    def getc(size, timeout=timeout):
        res = serial.read(size) or None
        return res

    def putc(data, timeout=timeout):
        res = serial.write(data)  # note that this ignores the timeout
        return res

    xmodem = XMODEM(getc, putc)
    xmodem.send(stream)

    serial.rtscts = rtscts


# Boot into recovery mode manually:
# - connect the DEBUG_RTS pin to 3.3v
# - power up the board (or use the RESET button).
# (Tested on the AVNET starter kit.)
def main():
    # DEBUG port ('/dev/ttyUSB3', 'COM6', etc.), typically the last one.
    port = sys.argv[1]

    # Recovery directory (recovery protocol version 2).
    recovery_dir = sys.argv[2]

    # Device capabilities file (with matching device id).
    device_caps = sys.argv[3]

    recovery_1bl      = os.path.join(recovery_dir, "recovery-1bl-rtm.bin")
    recovery_runtime  = os.path.join(recovery_dir, "recovery-runtime.bin")
    recovery_manifest = os.path.join(recovery_dir, "recovery.imagemanifest")

    # XXX: These sizes are hardcoded in the 'ServerMessageType.ImageRequestAck'
    # messages below.
    assert_file_size(device_caps, 0x188)
    assert_file_size(recovery_runtime, 0xeda4)
    assert_file_size(recovery_manifest, 0x5d8)

    timeout = 2

    serial = Serial(
        port=port,
        baudrate=115200,
        parity=PARITY_NONE,
        bytesize=8,
        stopbits=1,
        rtscts=0,
        timeout=timeout)

    # Check that the board is in recovery mode.
    # If you open the port directly and hit the RESET button, you should see:
    # RECOVERY
    # 0000362000008A01020A00008FC8C833
    # CCC
    #
    # 'C's mean that this is XMODEM with CRC-16 and the receiver is ready to
    # receive data.
    # http://web.mit.edu/6.115/www/amulet/xmodem.htm

    serial.timeout = 10
    output = read(serial, 10)
    serial.timeout = timeout

    # If you're getting an error here:
    # - the board is not in recovery mode
    # - you connected too early, try again
    # - something is wrong with the serial port (try opening it in ExtraPutty,
    #   it supports XMODEM too).
    assert b"CC" in output

    # Send the recovery 1BL over XMODEM.
    print(yellow("[<] Sending recovery 1BL"))
    stream = open(recovery_1bl, "rb")
    xmodem_send(serial, stream, timeout)

    # Output: b'+GOOD\r\n'
    readline(serial)

    # Output: b'[1BL] BOOT: INIT\r\n'
    # or
    # Output: b'[1BL] BOOT: 28030000/00000010/07000000\r\n'
    # The postcode (the last three numbers) might be different.
    #
    # In C# code: 'WaitForRecoveryBoot', 'VerifyBootMessage', 'DeviceResponses'.
    readline(serial)

    # Output: b'\x02\x89\x02\x01\x02\x85\x02\x01\x01\x01\x81006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x03\xbe\x03\x00 (repeated)'
    #
    # Format:
    # \x02\x89\x02\x01\x02\x85\x02\x01\x01\x01\x81
    # 006...bee8 -- Device ID
    # \x03\xbe\x03
    # \x00 -- end of packet
    #
    # COBS uses the NULL byte as the packet delimiter.
    # Decoded: b'\x89\x00\x01\x00\x85\x00\x01\x00\x00\x00006fe629beb69fc3bb06cf8494ccc25461f597aae076aa0d1f9b49656d60b63557becad65b338a1a5b4104f769649aaa35340eca1f1899df610305506cd7bee8\x00\xbe\x03'
    #
    # Format:
    # \x89\x00 -- packet size (137, little-endian)
    # \x01\x00 -- ClientMessageType.Initialization (1, little-endian)
    # \x85\x00 -- data size (133, little-endian)
    # \x01\x00\x00\x00 -- version (1, little-endian)
    # 006...bee8 -- Device ID
    # \x00  -- NULL terminator
    # \xbe\x03 -- unk (probably CRC-16).
    output, leftovers = read_decode(serial)

    # In C# code: 'ServerMessageType', 'ControlProtocol'.
    #
    # Format (case for payload length == 0):
    # The array that CRC-16 is calculated on:
    # 04 00 a0 00 00 00
    # \x04\x00 -- size
    # \xa0\x00 -- ServerMessageType.InitializationAck (0x00A0)
    # \x00\x00 -- end of the message.
    #
    # CRC-16 value: 0xecd7.
    #
    # The final array should be:
    # 02 04 02 a0 01 01 03 d7 ec 00
    # last \x00 -- packet delimiter.
    #
    # b"\x02\x04\x02\xa0\x01\x01\x03\xd7\xec\x00"
    write_encode(serial, b"\xa0\x00\x00\x00")

    # Format:
    # \x0b\x00 -- ClientMessageType.RecoveryEvent
    # \x01\x00 -- payload size (1, little-endian)
    # \x01 -- RecoveryEventType.BLInitializationComplete
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x0b\x00\x01\x00\x01"

    # Format:
    # \t\x00 -- ClientMessageType.LogConfigQuery (0x0009)
    # \x00\x00 -- payload size (0, little-endian)
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\t\x00\x00\x00"

    # Sending: b'\x02\x05\x02\xa3\x02\x01\x01\x03!\x8a\x00'
    #
    # In C# code: 'BuildResponse', 'SimpleAckResponse'.
    # Format:
    # \xa3\x00 -- ServerMessageType.SimpleQueryAck (0x00a3)
    # \x01\x00 -- payload size (1, little-endian)
    # \x00     -- ackResponse (0 or 1)
    # XXX: Try sending 1 here as ackResponse.
    write_encode(serial, b"\xa3\x00\x01\x00\x00")

    # In C# code: class 'RequestFileBase'.
    #
    # Format:
    # \x04\x00 -- ClientMessageType.ImageRequestCapability (0x0004)
    # \x08\x00 -- payload size (8, little-endian)
    # \x00\x00\x00\x00 -- index?
    # \xff\xff\xff\xff -- file size?
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x04\x00\x08\x00\x00\x00\x00\x00\xff\xff\xff\xff"

    # Format:
    # \xa4\x00 -- ServerMessageType.ImageRequestAck (0x00a4)
    # \x0c\x00 -- payload size (12, little-endian)
    # \x00\x00\x00\x00 -- start index?
    # \x88\x01\x00\x00 -- send size?
    # \x88\x01\x00\x00 -- total size?
    write_encode(
        serial,
        (b"\xa4\x00" +
         b"\x0c\x00" +
         b"\x00\x00\x00\x00" +
         b"\x88\x01\x00\x00" +
         b"\x88\x01\x00\x00"))

    # Send device capabilities over XMODEM.
    print(yellow("[<] Sending device capabilities"))
    stream = open(device_caps, "rb")
    xmodem_send(serial, stream, timeout)

    # Format:
    # \x0b\x00 -- ClientMessageType.RecoveryEvent (0x000b)
    # \x01\x00 -- payload size (1, little-endian)
    # \x02 -- RecoveryEventType.BLCapabilityImageReceived
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x0b\x00\x01\x00\x02"

    # Format:
    # \x0b\x00 -- ClientMessageType.RecoveryEvent (0x000b)
    # \x01\x00 -- payload size (1, little-endian)
    # \x03 -- RecoveryEventType.BLCapabilityImageLoaded
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x0b\x00\x01\x00\x03"

    # Format:
    # \x07\x00 -- ClientMessageType.ImageRequestByFilename
    # \x1d\x00 -- size (29, little-endian)
    # \x00\x00\x00\x00 -- index?
    # \xff\xff\xff\xff -- file size?
    # recovery-runtime.bin -- filename
    # \x00 -- terminator
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x07\x00\x1d\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery-runtime.bin\x00"

    # Format:
    # \xa4\x00 -- ServerMessageType.ImageRequestAck (0x00a4)
    # \x0c\x00 -- payload size (12, little-endian)
    # \x00\x00\x00\x00 -- start index?
    # \xa4\xed\x00\x00 -- send size?
    # \xa4\xed\x00\x00 -- total size?
    write_encode(
        serial,
        (b"\xa4\x00"
         b"\x0c\x00"
         b"\x00\x00\x00\x00"
         b"\xa4\xed\x00\x00"
         b"\xa4\xed\x00\x00"))

    # Send the recovery runtime over XMODEM.
    print(yellow("[<] Sending recovery runtime"))
    stream = open(recovery_runtime, "rb")
    xmodem_send(serial, stream, timeout)

    # Format:
    # \t\x00 -- ClientMessageType.LogConfigQuery (0x0009)
    # \x00\x00 -- payload size (0, little-endian)
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\t\x00\x00\x00"

    # Format:
    # \xa3\x00 -- ServerMessageType.SimpleQueryAck (0x00a3)
    # \x01\x00 -- payload size (1, little-endian)
    # \x00     -- ackResponse (0 or 1)
    write_encode(serial, b"\xa3\x00\x01\x00\x00")

    # Format:
    # \x0b\x00 -- ClientMessageType.RecoveryEvent (0x000b)
    # \x01\x00 -- payload size (1, little-endian)
    # \x06 -- RecoveryEventType.RABootComplete
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x0b\x00\x01\x00\x06"

    # Format:
    # \x03\x00 -- ClientMessageType.BaudrateSwitchQuery (0x0003)
    # \x00\x00 -- payload size (0, little-endian)
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x03\x00\x00\x00"

    # Format:
    # \xa3\x00 -- ServerMessageType.SimpleQueryAck (0x00a3)
    # \x01\x00 -- payload size (1, little-endian)
    # \x01     -- ackResponse (0 or 1)
    #
    # Baudrate settings:
    # {
    #   PortMode.Bootloader,
    #   new SerialPortConfiguration()
    #   {
    #     BaudRate = 115200,
    #     Parity = Parity.None,
    #     DataBits = 8,
    #     StopBits = StopBits.One,
    #     Handshake = Handshake.None
    #   }
    # },
    # {
    #   PortMode.ImagingMt3620,
    #   new SerialPortConfiguration()
    #   {
    #     BaudRate = 3000000,
    #     Parity = Parity.None,
    #     DataBits = 8,
    #     StopBits = StopBits.One,
    #     Handshake = Handshake.RequestToSend
    #   }
    # },
    # {
    #   PortMode.ImagingMt3620LowSpeed,
    #   new SerialPortConfiguration()
    #   {
    #     BaudRate = 115200,
    #     Parity = Parity.None,
    #     DataBits = 8,
    #     StopBits = StopBits.One,
    #     Handshake = Handshake.RequestToSend
    #   }
    # }
    # write_encode(serial, b"\xa3\x00\x01\x00\x01")  # XXX: doesn't work
    write_encode(serial, b"\xa3\x00\x01\x00\x00")

    # serial.baudrate = 3000000  # XXX: doesn't work
    serial.baudrate = 115200
    serial.parity = PARITY_NONE
    serial.bytesize = 8
    serial.stopbits = 1
    serial.rtscts = 1

    # Format:
    # \x0b\x00 -- ClientMessageType.RecoveryEvent (0x000b)
    # \x01\x00 -- payload size (1, little-endian)
    # \x07     -- RecoveryEventType.RAEraseFlashStarted
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x0b\x00\x01\x00\x07"

    # Format:
    # \x0b\x00 -- ClientMessageType.RecoveryEvent (0x000b)
    # \x01\x00 -- payload size (1, little-endian)
    # \x08     -- RecoveryEventType.RAEraseFlashComplete
    print("[i] Waiting for flash erase to complete")
    while True:
        try:
            output, leftovers = smart_decode(serial, leftovers)
            break
        except EmptyOutputError:
            continue
    assert output == b"\x0b\x00\x01\x00\x08"

    # Format:
    # \x07\x00 -- ClientMessageType.ImageRequestByFilename
    # \x1f\x00 -- size (31, little-endian)
    # \x00\x00\x00\x00 -- index?
    # \xff\xff\xff\xff -- file size?
    # recovery.imagemanifest -- filename
    # \x00 -- terminator
    output, leftovers = smart_decode(serial, leftovers)
    assert output == b"\x07\x00\x1f\x00\x00\x00\x00\x00\xff\xff\xff\xffrecovery.imagemanifest\x00"

    # Format:
    # \xa4\x00 -- ServerMessageType.ImageRequestAck (0x00a4)
    # \x0c\x00 -- payload size (12, little-endian)
    # \x00\x00\x00\x00 -- start index?
    # \xd8\x05\x00\x00 -- send size?
    # \xd8\x05\x00\x00 -- total size?
    write_encode(
        serial,
        (b"\xa4\x00" +
         b"\x0c\x00" +
         b"\x00\x00\x00\x00" +
         b"\xd8\x05\x00\x00" +
         b"\xd8\x05\x00\x00"))

    # Send the recovery manifest over XMODEM.
    print(yellow("[<] Sending recovery manifest"))
    stream = open(recovery_manifest, "rb")
    xmodem_send(serial, stream, timeout)

    # Format:
    # \x0b\x00 -- ClientMessageType.RecoveryEvent
    # \x01\x00 -- payload size (1, little-endian)
    # \x09 -- RecoveryEventType.RAManifestReceived
    output, leftovers = smart_decode(serial, leftovers)
    assert output ==  b"\x0b\x00\x01\x00\t"


if __name__ == "__main__":
    main()
