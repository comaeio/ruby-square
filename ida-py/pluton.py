##
## Usage: SetPlutonApiNames(base)
## eg. SetPlutonApiNames(0x010DC28)
##


import zlib
import hashlib

def AddTypes():
    begin_type_updating(UTP_ENUM)
    id = add_enum(-1,"PLUTON_COMMAND_TYPE",0x1100000)
    add_enum_member(id,"Internal", 0X2, -1)
    add_enum_member(id,"RemoteApi", 0X6, -1)
    end_type_updating(UTP_ENUM)

    begin_type_updating(UTP_STRUCT)
    id = add_struc(-1,"PLUTON_COMMAND_ENTRY",0)

    id = get_struc_id("PLUTON_COMMAND_ENTRY")
    mid = add_struc_member(id,"Index", 0, 0x20000400, -1, 4)
    mid = add_struc_member(id,"Flags", 0X4, 0x28800400, get_enum("PLUTON_COMMAND_TYPE"), 4)
    mid = add_struc_member(id,"Function", 0X8, 0x25500400, 0XFFFFFFFFFFFFFFFF, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000002)
    mid = add_struc_member(id,"u0C", 0XC, 0x20000400, -1, 4)

    id = get_struc_id("PLUTON_COMMAND_ENTRY")
    SetType(get_member_id(id, 0x4), "PLUTON_COMMAND_TYPE")
    SetType(get_member_id(id, 0x8), "void *")
    end_type_updating(UTP_STRUCT)

def GetPlutonCmdName(idx):
    switcher = {
        0: "PlRApiInvalid",
        1: "PlRApiSendEventBuffers",
        2: "PlRApiSetPostcode",
        3: "PlRApiGetBootModeFlags",
        0x40: "PlRApiReadRng",
        0x41: "PlRApiGetSecurityState",
        0x48: "PlRApiIsCapabilityEnabled",
        0x49: "PlRApiGetEnabledCapabilities",
        0x4A: "PlRApiGenerateClientAuthKey",
        0x4B: "PlRApiGetTenantPublicKey",
        0x4C: "PlRApiProcessAttestation",
        0x4D: "PlRApiSignWithTenantAttestationKey",
        0x4E: "PlRApiCommitClientAuthKey",
        0x50: "PlRApiDeviceReset",
        0x51: "PlRApiGetManufacturingState",
        0x52: "PlRApiSetManufacturingState",
        0x56: "PlRApiDecodeCapabilities"
    }

    cmd_name = switcher.get(idx, "unknown") 
    if cmd_name == "unknown":
        cmd_name = "PlpCommandIndex_" + str(idx)

    return cmd_name

def SetPlutonApiNames(addr):
    AddTypes()

    set_name(addr, "PlutonCommandTable")

    res = ""
    i = 0

    while i < 31:
        ptr = addr + i * 0x10
        func_start = Dword(ptr + 0x8) - 1

        MakeFunction(func_start)

        end = find_func_end(func_start)
        length = end - func_start
        buf = get_bytes(func_start, length)
        crc = zlib.crc32(buf) % (1<<32)
        sha2 = hashlib.sha256(buf).hexdigest()

        create_insn(func_start + 1)

        idx = Dword(ptr)
        name = GetPlutonCmdName(idx)
        set_name(func_start, GetPlutonCmdName(idx))

        MakeStruct(ptr, "PLUTON_COMMAND_ENTRY")

        res += "addr:   0x{:08x}\n".format(func_start)
        res += "name:   {}\n".format(name)
        res += "length: 0x{:x}\n".format(length)
        res += "crc32:  0x{:08x}\n".format(crc)
        res += "sha256: {}\n".format(sha2)

        for j, c in enumerate(buf):
            if (j != 0 and (j + 1) % 16 == 0) or j + 1 == len(buf):
                res += "{:02x}\n".format(ord(c))
            else:
                res += "{:02x} ".format(ord(c))

        res += "\n"

        i += 1

    return res


def main():
    plut_table_addr = AskAddr(here(), "Pluton API Table address")
    if not plut_table_addr:
        Warning("Invalid address: {}".format(plut_table_addr))
        return

    out_file = AskFile(1, "*.txt", "Output file")
    if not out_file:
        Warning("Invalid output file")
        return

    print "Setting Pluton API names..."
    sigs = SetPlutonApiNames(plut_table_addr)

    with open(out_file, "w") as f:
        f.write(sigs)

    print "Done"


main()
