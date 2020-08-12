
"""
 Image Manifest (4X4M) Management Library

 Date: June-2020

 Authors:
 - Matt Suiche (msuiche)
 - Nikita Karetnikov (nkaretnikov)

"""

from asmeta import * 

AZ_MANIFEST_HEADER_SIZE = 0x10
AZ_MANIFEST_ENTRY_SIZE = 0x4C
AZ_MANIFEST_VERSION = 0x3

# Partition Type
Invalid = 0
Firmware = 1
Backups = 2
Applications = 4
LogStorage = 5
NwConfig = 6
BootloaderOne = 7
BootloaderOneBackup = 8
LocatorTable = 9
LocatorTableBackup = 0x000A
BlockHashes = 0x000B
BlockHashesBackup = 0x000C
BootManifest = 0x000D
BootManifestBackup = 0x000E
TelemetryStorage = 0x000F
MaxPhysicalLayout = 0x3FFF
EcRuntimeProtectedRange = 0x4000
MaxVirtualLayout = 0xFFFF

class imagemanifest():
    def __init__(self):
        self._file_size = 0
        self._input_file_name = ''
        self._fd = 0

        return

    def open_file(self, _input_file_name):
        self._input_file_name = _input_file_name
        if self._fd == 0:
            self._fd = open(self._input_file_name, 'rb')
        else:
            raise Exception("ERR: You need to close the current handle first")

        self._fd.seek(0)
        header = struct.unpack('<HHHHQ', self._fd.read(AZ_MANIFEST_HEADER_SIZE))
        hdr_version = header[0]
        hdr_image_count = header[1]
        hdr_header_size = header[2]
        hdr_entry_size = header[3]
        hdr_build_date = header[4]

        if hdr_version != AZ_MANIFEST_VERSION or hdr_header_size != AZ_MANIFEST_HEADER_SIZE or hdr_entry_size != AZ_MANIFEST_ENTRY_SIZE:
            raise Exception("ERR: The manifest header may be incorrect or has changed. Please review.")

        self.my_dict = {}
        for i in range(hdr_image_count):
            self._fd.seek(hdr_header_size + hdr_entry_size * i)
            imageuid = struct.unpack('<LHH8B', self._fd.read(0x10))
            image_uid_str = self.get_guid(imageuid)
            componentuid = struct.unpack('<LHH8B', self._fd.read(0x10))
            info = struct.unpack('<HHLL', self._fd.read(0xC))
            image_type = info[0]
            partition_type = info[1]

            self.my_dict[image_uid_str.lower()] = image_uid_str+"_"+self.get_image_type(image_type)+"_"+self.get_partition_type(partition_type)

            print(image_uid_str+"_"+self.get_image_type(image_type)+"_"+self.get_partition_type(partition_type))

        self.meta = asmeta(self._fd, hdr_header_size + hdr_entry_size * hdr_image_count)

    def get_folder_name(self, file_name):
        name = file_name.lower().replace('.bin', '')
        if name in self.my_dict:
            return self.my_dict[name]
        else:
            return name

    def get_guid(self, buff):
        s = "%08x%04x%04x" % (buff[0], buff[1], buff[2])
        for j in range(8):
            s += "%02x" % buff[3 + j]

        return s


    def get_image_type(self, image_type):
        switcher = {
            InvalidImageType: "InvalidImageType",
            OneBL: "OneBL",
            PlutonRuntime: "PlutonRuntime",
            WifiFirmware: "WifiFirmware",
            SecurityMonitor: "SecurityMonitor",
            NormalWorldLoader: "NormalWorldLoader",
            NormalWorldDTB: "NormalWorldDTB",
            NormalWorldKernel: "NormalWorldKernel",
            RootFs: "RootFs",
            Services: "Services",
            Applications: "Applications",
            FirmwareConfig: "FirmwareConfig",
            BootManifest: "BootManifest",
            NormalWorldFileSystem: "NormalWorldFileSystem",
            TrustedKeystore: "TrustedKeystore",
            Policy: "Policy",
            CustomerBoardConfig: "CustomerBoardConfig",
            UpdateCertStore: "UpdateCertStore",
            BaseSystemUpdateManifest: "BaseSystemUpdateManifest",
            FirmwareUpdateManifest: "FirmwareUpdateManifest",
            CustomerUpdateManifest: "CustomerUpdateManifest",
            RecoveryManifest: "RecoveryManifest",
            ManifestSet: "ManifestSet",
            Other: "Other"
        } 
        return switcher.get(image_type, "Unknown")


    def get_partition_type(self, partition_type):
        switcher = {
            Invalid: "Invalid",
            Firmware: "Firmware",
            Backups: "Backups",
            Applications: "Applications",
            LogStorage: "LogStorage",
            NwConfig: "NwConfig",
            BootloaderOne: "BootloaderOne",
            BootloaderOneBackup: "BootloaderOneBackup",
            LocatorTable: "LocatorTable",
            LocatorTableBackup: "LocatorTableBackup",
            BlockHashes: "BlockHashes",
            BlockHashesBackup: "BlockHashesBackup",
            BootManifest: "BootManifest",
            BootManifestBackup: "BootManifestBackup",
            TelemetryStorage: "TelemetryStorage",
            MaxPhysicalLayout: "MaxPhysicalLayout",
            EcRuntimeProtectedRange: "EcRuntimeProtectedRange",
            MaxVirtualLayout: "MaxVirtualLayout"
        } 
        return switcher.get(partition_type, "Unknown")

    def print(self):
        self.meta.print()
        return
        

    def close_file(self):
        self._input_file_name = ''
        if self._fd != 0:
            self._fd.close()
            self._fd = 0