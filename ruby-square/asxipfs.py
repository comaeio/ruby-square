
"""
 Azure Sphere Execute In Place File System (ASXipFS) Management Library

 ASXipFS is designed for read only file systems that use execute in place (XIP)
 techniques to limit RAM usage on compatible MTD devices.

 Date: June-2020

 Authors:
 - Matt Suiche (msuiche)
 - Nikita Karetnikov (nkaretnikov)

"""

import os, sys, struct, binascii
from os.path import join, normpath, basename
import struct
import stat

from asmeta import * 

from az_packer import *
from az_meta import *

"""
struct asxipfs_info {
	__u32 crc;
	__u32 edition;
	__u32 blocks;
	__u32 files;
};

/*
 * Superblock information at the beginning of the FS.
 */
struct asxipfs_super {
	__u32 magic;			/* 0x28cd3d45 - random number */
	__u32 size;			/* length in bytes */
	__u32 flags;			/* feature flags */
	__u32 future;			/* reserved for future use */
	__u8 signature[16];		/* ????? unused for now */
	struct asxipfs_info fsid;	/* unique filesystem info */
	__u8 name[16];			/* user-defined name */
	struct asxipfs_inode root;	/* root inode data */
};
"""

### Feature flags
ASXIPFS_FLAG_FSID_VERSION_2 = 0x00000001 # fsid version #2
ASXIPFS_FLAG_SORTED_DIRS = 0x00000002 #  sorted dirs
ASXIPFS_FLAG_CAPABILITIES = 0x00000004 # file capabilities
ASXIPFS_FLAG_WRONG_SIGNATURE = 0x00000200 #  reserved
ASXIPFS_FLAG_SHIFTED_ROOT_OFFSET = 0x00000400 # shifted root fs
ASXIPFS_FLAG_XATTR = 0x00000800 # extended attribute support


# Valid values in super.flags.  Currently we refuse to mount
# if (flags & ~ASXIPFS_SUPPORTED_FLAGS).  Maybe that should be
# changed to test super.future instead.
# Note: we still have the XATTR flag for compatibility on loads
# although we are no longer supporting XATTR as it is unknown
# if we are just setting it on current images

ASXIPFS_SUPPORTED_FLAGS = 	( 0x000000ff | ASXIPFS_FLAG_WRONG_SIGNATURE | ASXIPFS_FLAG_SHIFTED_ROOT_OFFSET | ASXIPFS_FLAG_XATTR )
ASXIPFS_MAGIC = 0x28cd3d45

ASXIPFS_MAGIC_IDX = 0
ASXIPFS_SIZE_IDX = 1
ASXIPFS_FLAGS_IDX = 2
ASXIPFS_FUTURE_IDX = 3
ASXIPFS_SIGNATURE_IDX = 4
ASXIPFS_INFO_CRC_IDX = 5
ASXIPFS_INFO_EDITION_IDX = 6
ASXIPFS_INFO_BLOCKS_IDX = 7
ASXIPFS_INFO_FILES_IDX = 8
ASXIPFS_NAME_IDX = 9

ASXIPFS_INODE_MODE_IDX = 0
ASXIPFS_INODE_SIZE_IDX = 1
ASXIPFS_INODE_NAMELEN_IDX = 2

ASXIPFS_SB_INFO_SIZE = 0x40
ASXIPFS_INODE_OFFSET = 0x40
ASXIPFS_INODE_SIZE = 0xC

DEVCAP_MAGIC = 0x5cfd5cfd
DEVCAP_HDR_SIZE = 0xC
DEVCAP_SIZE_IDX = 2

UTBL_MAGIC = 0x4c425455
UTBL_HDR_SIZE = 0x8
UTBL_ENTRY_SIZE = 0x4

TKS_HDR_SIZE = 0x10
TKS_ENTRY_SIZE = 0x54

NW_LOADER_MAGIC = 0x80000000
NW_LOADER_SIZE_IDX = 1

PLUTON_RUNTIME_MAGIC = 0x102020 # Vector

class asxipfs():
    def __init__(self):
        self._file_size = 0
        self._input_file_name = ''
        self._fd = 0

        return

    def get_application_name(self):
        return self.sb_info.meta.get_application_name()


    def parse_header(self):
        if self._fd == 0:
            raise Exception("ERR: You need to open an image first.")

        self.sb_info = self.asxipfs_sb_info(self._fd)

    def is_compressed_romfs(self):
        return self.sb_info.is_compressed_romfs

    class asxipfs_sb_info():
        def __init__(self, _fd):
            self._fd = _fd
            self.read()

        def read(self):
            self.is_compressed_romfs = False
            self._fd.seek(0)
            self.header = struct.unpack('<LLLL16sLLLL16s', self._fd.read(ASXIPFS_SB_INFO_SIZE))
            self.magic = self.header[ASXIPFS_MAGIC_IDX]

            if self.magic == DEVCAP_MAGIC:
                print("This is a device capability file. Pass.")
                self.size = self.header[DEVCAP_SIZE_IDX]
            elif self.magic == ASXIPFS_MAGIC:  
                self.is_compressed_romfs = True
                print("So far so good.")
                self.size = self.header[ASXIPFS_SIZE_IDX]
                self.flags = self.header[ASXIPFS_FLAGS_IDX]
                self.crc = self.header[ASXIPFS_INFO_CRC_IDX]
                self.edition = self.header[ASXIPFS_INFO_EDITION_IDX]
                self.blocks = self.header[ASXIPFS_INFO_BLOCKS_IDX]
                self.files = self.header[ASXIPFS_INFO_FILES_IDX]

                self.print()
            elif self.magic == NW_LOADER_MAGIC:
                self.size = self.header[NW_LOADER_SIZE_IDX]
            else:
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
                        self.size = found
                        break
                    else:
                        found += 4

                if found == -1:
                    raise ValueError("Invalid Azure Sphere image.")
            """
            else:
                self._fd.seek(0)
                header = struct.unpack('<HH', self._fd.read(4))
                print("TKS: No of entries: %d Version: %d" % (header[0], header[1]))
                utbl_offset = ((TKS_HDR_SIZE + TKS_ENTRY_SIZE) * header[0] + 4)
                print("Next sig offset: 0x%x" % utbl_offset)
                
                self._fd.seek(utbl_offset)
                header = struct.unpack('<LL', self._fd.read(UTBL_HDR_SIZE))
                if header[0] == UTBL_MAGIC:
                    self.size = utbl_offset + header[1] * UTBL_ENTRY_SIZE + UTBL_HDR_SIZE
                    print("4X4M: 0x%x" % self.size)
                else:
                    raise ValueError("Invalid Azure Sphere image.")
            """
            self.meta = asmeta(self._fd, self.size)
            self.meta.print()

        def print(self):
            print("asxipfs_super: ")
            print("  magic:                 0x%x" % (self.header[ASXIPFS_MAGIC_IDX]))
            print("  size:                  0x%x" % (self.header[ASXIPFS_SIZE_IDX]))
            print("  flags:                 0x%x" % (self.header[ASXIPFS_FLAGS_IDX]))
            print("  future:                0x%x" % (self.header[ASXIPFS_FUTURE_IDX]))
            print("  signature:             %s" % (self.header[ASXIPFS_SIGNATURE_IDX]))
            print("  asxipfs_info.crc:      0x%x" % (self.header[ASXIPFS_INFO_CRC_IDX]))
            print("  asxipfs_info.edition:  0x%x" % (self.header[ASXIPFS_INFO_EDITION_IDX]))
            print("  asxipfs_info.blocks:   0x%x" % (self.header[ASXIPFS_INFO_BLOCKS_IDX]))
            print("  asxipfs_info.files:    0x%x" % (self.header[ASXIPFS_INFO_FILES_IDX]))
            print("  name:                  %s" % (self.header[ASXIPFS_NAME_IDX]))

            print("  asxipfs_inode: ")
            # self.walk_nodes()

        def do_directory(self, node, basename, unpack):
            # print("ERR:  do_directory() is unimplemented.")
            dirname = ''
            if len(basename):
                dirname += basename

            if node.get_name():
                dirname += '/' + node.get_name()

            if unpack:
                print("-> Creating \"%s\" directory (offset: 0x%x, size: 0x%x)..." % (dirname, node.inode.get_offset(), node.inode.get_size()))
                try:
                    os.mkdir(dirname)
                except OSError:
                    print ("Creation of the directory \"%s\" failed" % dirname)

            
            dir = self.asxipfs_inode(self._fd, node.inode.get_offset())
            limit = node.inode.get_offset() + node.inode.get_size()

            while dir.get_pos() < limit:
                if unpack == False:
                    dir.print()
                self.do(dir, dirname, unpack)
                dir.next()
            return

        def  do_symlink(self, node, basename, unpack):
            # print("ERR:  do_symlink() is unimplemented.")
            return

        def do_file(self, node, basename, unpack):
            filename = basename + '/' + node.get_name() if len(basename) else node.get_name()
            # print("ERR:  do_file() is unimplemented.")
            if (node.inode.mode & stat.S_ISVTX):
                if unpack:
                    print("-> Creating file \"%s\" (offset: 0x%x, size: 0x%x)...." % (filename, node.inode.get_offset(), node.inode.get_size()))
                    with open(filename, 'wb') as out:
                        self._fd.seek(node.inode.get_offset())
                        data = self._fd.read(node.inode.get_size())
                        out.write(data)
                        out.close()
            else:
                print("ERR: This is not XIP. Unsupported.")
            return

        def do_fifo(self, node):
            print("ERR:  do_fifo() is unimplemented.")
            return

        def do_chrdev(self, node):
            print("ERR:  do_chrdev() is unimplemented.")
            return

        def do_socket(self, node):
            print("ERR:  do_socket() is unimplemented.")
            return

        def do_blk(self, node):
            print("ERR:  do_blk() is unimplemented.")
            return

        def do_unknown(self, node):
            print("ERR:  do_unknown() is unimplemented.")
            print("ERR: offset = 0x%x" % (node.inode.get_node_offset()))
            return

        def do(self, node, basename='', unpack=False):
            if stat.S_ISDIR(node.inode.mode):
                self.do_directory(node, basename, unpack)
            elif stat.S_ISREG(node.inode.mode):
                self.do_file(node, basename, unpack)
            elif stat.S_ISLNK(node.inode.mode):
                self.do_symlink(node, basename, unpack)
            elif stat.S_ISBLK(node.inode.mode):
                self.do_blk(node)
            elif stat.S_ISCHR(node.inode.mode):
                self.do_chrdev(node)
            elif stat.S_ISFIFO(node.inode.mode):
                self.do_fifo(node)
            elif stat.S_ISSOCK(node.inode.mode):
                self.do_socket(node)
            else:
                self.do_unknown(node)

        def walk_nodes(self, dst_folder='', unpack=False):
            root = self.asxipfs_inode(self._fd, ASXIPFS_INODE_OFFSET)
            if unpack == False:
                root.print()

            self.do(root, dst_folder, unpack)

        class asxipfs_inode():
            def __init__(self, _fd, _offset):
                self.reset(_offset)
                self._fd = _fd
                self.read()

            def get_current_inode_id(self):
                return self._current_inode_id

            def get_pos(self):
                return self.inode.get_node_offset()

            def get_name(self):
                return self.inode.name.decode().replace('\0', '')

            def reset(self, offset):
                self._next_inode = offset
                self._next_inode_id = 0
                self._current_inode = 0
                self._current_inode_id = 0

            def print(self):
                self.inode.print()

            def read(self):
                self._current_inode = self._next_inode
                self._current_inode_id = self._next_inode_id

                self.inode = self.asxipfs_inode_entry(self._fd, self._current_inode)
                
                self._next_inode += ASXIPFS_INODE_SIZE
                self._next_inode += self.inode.namelen
                self._next_inode_id = self._current_inode_id + 1
                return

            def next(self):
                self.inode.next()
            
            class asxipfs_inode_entry():
                def __init__(self, _fd, _offset):
                    self._fd = _fd
                    self._offset = _offset
                    self._id = 0

                    self._read()

                def next(self):
                    self._offset = self._offset + ASXIPFS_INODE_SIZE + self.namelen
                    self._id = self._id + 1
                    self._read()

                def _read(self):
                    self._fd.seek(self._offset)
                    asxipfs_inode = struct.unpack('<LLL', self._fd.read(ASXIPFS_INODE_SIZE))
                    # Namelengths on disk are shifted by two and the name padded out to 4-byte boundaries with zeroes.
                    namelen = (asxipfs_inode[ASXIPFS_INODE_NAMELEN_IDX] & 0x3F) << 2
                    offset = (asxipfs_inode[ASXIPFS_INODE_NAMELEN_IDX] >> 6) << 2
                    name = self._fd.read(namelen)
                    self.name = name
                    self.mode = asxipfs_inode[ASXIPFS_INODE_MODE_IDX] & 0xFFFF
                    self.uid = asxipfs_inode[ASXIPFS_INODE_MODE_IDX] >> 16
                    self.size = asxipfs_inode[ASXIPFS_INODE_SIZE_IDX] & 0xFFFFFF
                    self.gid = asxipfs_inode[ASXIPFS_INODE_SIZE_IDX] >> 24
                    self.namelen = namelen
                    self.offset = offset

                    
                def get_name(self):
                    return self.name.decode().replace('\0', '')

                def get_node_offset(self):
                    return self._offset

                def get_size(self):
                    return self.size
                
                def get_offset(self):
                    return self.offset

                def get_mode(self):
                    mode_str = ''

                    if stat.S_ISDIR(self.mode):
                        mode_str += 'd'
                    if stat.S_ISREG(self.mode):
                        mode_str += 'f'
                    elif stat.S_ISLNK(self.mode):
                        mode_str += 'l'
                    elif stat.S_ISBLK(self.mode):
                        mode_str += 'b'
                    elif stat.S_ISCHR(self.mode):
                        mode_str += 'c'
                    elif stat.S_ISFIFO(self.mode):
                        mode_str += 'p'
                    elif stat.S_ISSOCK(self.mode):
                        mode_str += 's'
                    else:
                        mode_str += '-'
    
                    # Deal with mode bits
                    mode_str += 'r' if (self.mode & stat.S_IRUSR) else '-'
                    mode_str += 'w' if (self.mode & stat.S_IWUSR) else '-'
                    if (self.mode & stat.S_IXUSR):
                        mode_str += 's' if (self.mode & stat.S_ISUID) else 'x'
                    else:
                        mode_str += 'S' if (self.mode & stat.S_ISUID) else '-'

                    mode_str += 'r' if (self.mode & stat.S_IRGRP) else '-'
                    mode_str += 'w' if (self.mode & stat.S_IWGRP) else '-'
                    if (self.mode & stat.S_IXGRP):
                        mode_str += 's' if (self.mode &stat.S_ISGID) else 'x'
                    else:
                        mode_str += 'S' if (self.mode & stat.S_ISGID) else '-'

                    mode_str += 'r' if (self.mode & stat.S_IROTH) else '-'
                    mode_str += 'w' if (self.mode & stat.S_IWOTH) else '-'
                    if (self.mode & stat.S_IXOTH):
                        mode_str += 't' if (self.mode & stat.S_ISVTX) else 'x'
                    else:
                        mode_str += 'T' if (self.mode & stat.S_ISVTX) else '-'

                    return mode_str

                def print(self):
                    print("  asxipfs_inode[%d] = {name: \'%s\', mode: 0x%x (%s), uid: 0x%x, size: 0x%x, gid: 0x%x, namelen: 0x%x, offset: 0x%x}" % (
                        self._id, self.get_name(), self.mode, self.get_mode(), self.uid, self.size, self.gid, self.namelen, self.offset))

    def close_file(self):
        self._input_file_name = ''
        if self._fd != 0:
            self._fd.close()
            self._fd = 0

    def open_file(self, _input_file_name):
        self._input_file_name = _input_file_name
        if self._fd == 0:
            self._fd = open(self._input_file_name, 'rb')
        else:
            raise Exception("ERR: You need to close the current handle first")

        self.parse_header()

    def unpack(self, _output_folder):
        if self.is_compressed_romfs():
            self.sb_info.walk_nodes(_output_folder, True)
        return

    def pack(self, _input_dir, _output_file):
        DIR = os.path.dirname(_input_dir)
        APPROOT = join(DIR, 'approot')
        MANIFEST = join(DIR, 'app_manifest.json')

        manifest = create_json(MANIFEST, 'avnet_aesms_mt3620', APPROOT)

        create_approot(APPROOT, img) 

        create_meta_data(img, 
            app_name = manifest['Name'], 
            app_uid  = manifest['ComponentId'],
            app_depends = [1, 3, 3]) # sysroot

        write_image(join(DIR, _output_file), img)
        return

    def print_nodes(self):
        self.sb_info.walk_nodes()
        return