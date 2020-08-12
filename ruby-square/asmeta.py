
"""
 Azure Sphere Execute In Place File System (ASXipFS) Management Library

 ASXipFS is designed for read only file systems that use execute in place (XIP)
 techniques to limit RAM usage on compatible MTD devices.

 Date: June-2020

 Authors:
 - Matt Suiche (msuiche)
 - Nikita Karetnikov (nkaretnikov)

"""
import os
import struct
import binascii

AZ_4X4M_MAGIC = 0x4D345834
AZ_4X4M_HEADER_SIZE = 0x8
AZ_4X4M_SECTION_HEADER_SIZE = 0x4

SECTION_Debug                           = 16964 # 0x4244 DB * 
SECTION_LegacyABIDepends                = 17473 # 0x4441 AD
SECTION_Identity                        = 17481 # 0x4449 ID * 
SECTION_ABIDepends                      = 17486 # 0x444E ND * 
SECTION_Legacy                          = 18252 # 0x474C LG
SECTION_Signature                       = 18259 # 0x4753 SG * 
SECTION_Compression                     = 19779 # 0x4D43 CM
SECTION_RequiredFlashOffset             = 20306 # 0x4F52 RO
SECTION_LegacyABIProvides               = 20545 # 0x5041 AP
SECTION_ABIProvides                     = 20558 # 0x504E NP * 
SECTION_TemporaryImage                  = 20564 # 0x5054 TP * 
SECTION_Revocation                      = 22098 # 0x5652 RV

# Image Type
InvalidImageType = 0
OneBL = 1
PlutonRuntime = 2
WifiFirmware = 3
SecurityMonitor = 4
NormalWorldLoader = 5
NormalWorldDTB = 6
NormalWorldKernel = 7
RootFs = 8
Services = 9
Applications = 10 # 0x000A
FirmwareConfig = 13 # 0x000D
BootManifest = 16 # 0x0010
NormalWorldFileSystem = 17 # 0x0011
TrustedKeystore = 19 # 0x0013
Policy = 20 # 0x0014
CustomerBoardConfig = 21 # 0x0015
UpdateCertStore = 22 # 0x0016
BaseSystemUpdateManifest = 23 # 0x0017
FirmwareUpdateManifest = 24 # 0x0018
CustomerUpdateManifest = 25 # 0x0019
RecoveryManifest = 26 # 0x001A
ManifestSet = 27 # 0x001B
Other = 28 # 0x001C

# IdentityType
IdentityTypeNone = 0
SecureWorldRuntime = 1
OSRuntime = 2
ApplicationRuntime = 3


class asmeta():
    def __init__(self, _fd, _offset):
        self._file_size = 0
        self._meta_offset = _offset
        self._fd = _fd
        self.sections = []
        self.read()

        return

    def read(self):
        self._fd.seek(self._meta_offset)
        header = struct.unpack('<LL', self._fd.read(AZ_4X4M_HEADER_SIZE))
        self.magic = header[0]
        if self.magic != AZ_4X4M_MAGIC:
            # Try to force to retrieve the magic
            self._fd.seek(0)
            buf = self._fd.read()
            found = 0
            while True:
                found = buf.find(b'4X4M', found)
                if found == -1:
                    break
                if buf[found + 6] == 0 and buf[found + 7] == 0:
                    # Generic thingy
                    print("Generic 4X4M found @ 0x%x" % found)
                    self._meta_offset = found
                    self._fd.seek(self._meta_offset)
                    header = struct.unpack('<LL', self._fd.read(AZ_4X4M_HEADER_SIZE))
                    self.magic = header[0]
                    break
                else:
                    found += 4

            if found == -1:
                raise ValueError("Invalid Azure Sphere image.")

        if self.magic != AZ_4X4M_MAGIC:
            raise ValueError("Invalid 4X4M image.")
        self.section_count = header[1]
        print("So far so good.")

        i = 0

        offset = self._meta_offset + AZ_4X4M_HEADER_SIZE
        while i < self.section_count:
            section = self.metadata_section(self._fd, offset)
            self.sections.append(section)
            offset = offset + AZ_4X4M_SECTION_HEADER_SIZE + section.get_datalen()
            i = i + 1

    def get_application_name(self):
        application_name = ''
        for section in self.sections:
            if section.get_section_id() == SECTION_Debug:
                section._fd.seek(section.get_section_offset() + AZ_4X4M_SECTION_HEADER_SIZE)
                section_data = struct.unpack('<LL32s', section._fd.read(section.get_datalen()))
                application_name = section_data[2].decode()
                break
        
        return application_name

    def print(self):
        for section in self.sections:
            section.print()


    class metadata_section():
        def __init__(self, _fd, _offset):
            self._fd = _fd
            self.offset = _offset
            self.size = 0

            self.section_id = 0
            self.data_len = 0

            self.read()

        def read(self):
            self._fd.seek(self.offset)
            header = struct.unpack('<HH', self._fd.read(AZ_4X4M_SECTION_HEADER_SIZE))
            self.section_id = header[0]
            self.data_len = header[1]

        def get_section_offset(self):
            return self.offset

        def get_datalen(self):
            return self.data_len

        def get_section_id(self):
            return self.section_id

        def get_section_name(self, argument):
            switcher = {
                SECTION_Debug: "Debug",
                SECTION_LegacyABIDepends: "LegacyABIDepends",
                SECTION_Identity: "Identity",
                SECTION_ABIDepends: "ABIDepends",
                SECTION_Legacy: "Legacy",
                SECTION_Signature: "Signature",
                SECTION_Compression: "Compression",
                SECTION_RequiredFlashOffset: "RequiredFlashOffset",
                SECTION_LegacyABIProvides: "LegacyABIProvides",
                SECTION_ABIProvides: "ABIProvides",
                SECTION_TemporaryImage: "TemporaryImage",
                SECTION_Revocation: "Revocation"
            }
            return switcher.get(argument, "Unknown")

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

        def get_identity_type(self, identity_type):
            switcher = {
                IdentityTypeNone: "IdentityTypeNone",
                SecureWorldRuntime: "SecureWorldRuntime",
                OSRuntime: "OSRuntime",
                ApplicationRuntime: "ApplicationRuntime"
            } 
            return switcher.get(identity_type, "Unknown")

        def print_section(self):
            if self.get_section_id() == SECTION_Debug:
                self._fd.seek(self.get_section_offset() + AZ_4X4M_SECTION_HEADER_SIZE)
                section_data = struct.unpack('<LL32s', self._fd.read(self.get_datalen()))
                print("   build_date: 0x%x%x\n   name: %s" % (section_data[1], section_data[0], section_data[2].decode()))
            elif self.get_section_id() == SECTION_LegacyABIDepends:
                print("TODO: SECTION_LegacyABIDepends")
            elif self.get_section_id() == SECTION_Identity:
                self._fd.seek(self.get_section_offset() + AZ_4X4M_SECTION_HEADER_SIZE)
                section_data = struct.unpack('<HH16s16s', self._fd.read(self.get_datalen()))
                print("   image_type: %s (0x%x)\n   component_uid = %s, image_uid = %s" % (self.get_image_type(section_data[0]), section_data[0], binascii.hexlify(section_data[2]), binascii.hexlify(section_data[3])))
            elif self.get_section_id() == SECTION_ABIDepends:
                self._fd.seek(self.get_section_offset() + AZ_4X4M_SECTION_HEADER_SIZE)
                count = int((self.get_datalen() / 4)) - 1
                section_data = struct.unpack('<L' + 'L'*count, self._fd.read(self.get_datalen()))
                version_count = section_data[0]
                i = 1
                while i < version_count:
                    print("   identity_type: %s (0x%x)\n   version: 0x%x" % (self.get_identity_type(section_data[i+1]), section_data[i+1], section_data[i]))
                    i += 2
            elif self.get_section_id() == SECTION_Legacy:
                print("TODO: SECTION_Legacy")
            elif self.get_section_id() == SECTION_Signature:
                self._fd.seek(self.get_section_offset() + AZ_4X4M_SECTION_HEADER_SIZE)
                section_data = struct.unpack('<20sL', self._fd.read(self.get_datalen()))
                signing_type = section_data[1]
                print("    signing_cert_thumbprint: %s (%s)" % (binascii.hexlify(section_data[0]), "ECDsa256" if signing_type == 1 else "Invalid"))
            elif self.get_section_id() == SECTION_Compression:
                print("TODO: SECTION_Compression")
            elif self.get_section_id() == SECTION_RequiredFlashOffset:
                print("TODO: SECTION_RequiredFlashOffset")
            elif self.get_section_id() == SECTION_LegacyABIProvides:
                print("TODO: SECTION_LegacyABIProvides")
            elif self.get_section_id() == SECTION_ABIProvides:
                self._fd.seek(self.get_section_offset() + AZ_4X4M_SECTION_HEADER_SIZE)
                count = int((self.get_datalen() / 4)) - 1
                section_data = struct.unpack('<L' + 'L'*count, self._fd.read(self.get_datalen()))
                version_count = section_data[0]
                i = 1
                while i < version_count:
                    print("   identity_type: %s (0x%x)\n   version: 0x%x" % (self.get_identity_type(section_data[i+1]), section_data[i+1], section_data[i]))
                    i += 2
            elif self.get_section_id() == SECTION_TemporaryImage:
                print("TODO: SECTION_TemporaryImage")
            elif self.get_section_id() == SECTION_Revocation:
                self._fd.seek(self.get_section_offset() + AZ_4X4M_SECTION_HEADER_SIZE)
                section_data = struct.unpack('<L', self._fd.read(self.get_datalen()))
                print("   security_version_number: 0x%x" % (section_data[0]))

        def print(self):
            print('  metadata_section: %-20s (data_len: 0x%x)' % (self.get_section_name(self.section_id), self.data_len))
            self.print_section()