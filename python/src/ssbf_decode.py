import os
import struct

""" To run this code you need to install the following packages
monocypher: https://pypi.org/project/pymonocypher/
lz4: https://pypi.org/project/lz4/
"""

import monocypher
import lz4.block

def bsd_checksum8(data):
    cs = 0
    for i in data:
        cs = ((cs >> 1) & 0xff) + ((cs & 0x1) << 7)
        cs = (cs + i) & 0xff
    return cs

def bsd_checksum16(data):
    cs = 0
    for i in data:
        cs = ((cs >> 1) & 0xffff) + ((cs & 0x1) << 15)
        cs = (cs + i) & 0xffff
    return cs


class ssbf_exception(Exception):
    def __init__(self, message, status_code):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class ssbf_main_header():
    ssbf_magic_number = 0x19345601
    MAIN_HEADER_FLAG_USE_META_EXTENSION = 1
    MAIN_HEADE_FLAG_USE_ENCRYPTION_EXTENSION = 2

    def __init__(self, data):
        self.header_size = 12

        if len(data) >= 12:
            self.raw_data = data[:12]
        else:
            raise ssbf_exception("Main header data too short", 1)

        self.decode()

    def get_size(self):
        return self.header_size

    def decode(self):
        magic_num, self.payload_size, self.full_header_size, \
            self.flags, self.checksum = struct.unpack('<IIHBB', self.raw_data)

        if (self.ssbf_magic_number != magic_num):
            print("Magic number foo")
            raise ssbf_exception("Wrong magic number", 1)

        cs = bsd_checksum8(self.raw_data[:self.header_size-1])
        if cs != self.checksum:
            print("Checksum failed")
            raise ssbf_exception("checksum failed", 1)
            
        print("Main Header:")
        print("payload size: ", self.payload_size)
        print("full header size: ", self.full_header_size)
        print("flags: ", self.flags)
        if (self.flags & self.MAIN_HEADER_FLAG_USE_META_EXTENSION):
            print("  meta extension used")
        else:
            print("  meta extension NOT used")

        if (self.flags & self.MAIN_HEADE_FLAG_USE_ENCRYPTION_EXTENSION):
            print("  encryption extension used")
        else:
            print("  encryption extension NOT used")


class ssbf_encryption():
    FLAG_ENCRYPTION_USED_CHACHA20 = (1 << 3)
    FLAG_ENCRYPTION_USED_HASH_POLY1305 = (1 << 0)
    
    nonce_size = 24

    def __init__(self, key, data, encryption_header_offset):
        self.header_size = 30

        if (len(data)+encryption_header_offset) >= self.header_size:

            self.header_raw_data = data[encryption_header_offset
                                        :encryption_header_offset+self.header_size]
        else:
            raise ssbf_exception("crypto header data too short", 1)

        self.key = key

        self.decode_header()

        if self.key:
            encrypted_data = data[encryption_header_offset+self.header_size:]
            hashed_data= data
            self.decode_encrypted_part_of_the_full_header(encrypted_data, 
                                                          hashed_data)

    def get_size(self):
        return self.header_size

    def decode_header(self):
        self.nonce = self.header_raw_data[:self.nonce_size]

        self.encryption_payload_size, \
            self.encrypted_header_size, self.flags, \
            self.checksum = struct.unpack('<HHBB', self.header_raw_data[self.nonce_size:])

        cs = bsd_checksum8(self.header_raw_data[:self.header_size-1])
        if cs != self.checksum:
            print("Checksum failed")
            raise ssbf_exception("checksum failed", 1)
        
        print("encryption payload size: ", self.encryption_payload_size)
        print("encrypted header size: ", self.encrypted_header_size)
        print("flags: ", self.flags)
        if (self.flags & self.FLAG_ENCRYPTION_USED_CHACHA20):
            print("  chacha20 used")
        else:
            print("  encryption not used")

        if (self.flags & self.FLAG_ENCRYPTION_USED_HASH_POLY1305):
            print("  poly1305 used")
        else:
            print("  data integrity NOT used")
        
    def decode_encrypted_part_of_the_full_header(self, encrypted_data, only_hashed_data):
        #if len(data) > self.encryption_payload_size:
                # unlock(key, nonce, mac, message, associated_data=None):

        self.mac = encrypted_data[self.encrypted_header_size:self.encrypted_header_size+16]

        print("mac: ", end=' ')
        for i in self.mac:
            print(hex(i), end=' ')
        print("")

        print("nonce: ", self.nonce)

        print("enc data: ", end=' ')
        for i in encrypted_data[:self.encrypted_header_size]:
            print(hex(i), end=' ')
        print("")

        print(f"oh {len(only_hashed_data[:12+30])}: ", end=' ')
        for i in only_hashed_data[:12+30]:
            print(hex(i), end=' ')
        print("")

        self.decrypted_data = monocypher.unlock(self.key, self.nonce, self.mac, 
                              encrypted_data[:self.encrypted_header_size],
                              only_hashed_data[:12+30])

        if None == self.decrypted_data:
            print("decryption failed")
        else:
            print("Decryption successfull")

        self.encryption_payload = self.decrypted_data[:32]
        self.decrypted_header = self.decrypted_data[32:]


class ssbf_meta():

    def __init__(self, data):
        self.header_size = 4

        if len(data) >= self.header_size:
            self.raw_data = data[:self.header_size]
        else:
            raise ssbf_exception("Meta header data too short", 1)

        self.decode_header()
        self.meta_payload = data[self.header_size: 
                                 self.header_size+self.payload_size]
        print("Meta payload: ", self.meta_payload)

    def get_size(self):
        return self.header_size

    def decode_header(self):
        self.meta_data_id, self.payload_size =  \
        struct.unpack('<HH', self.raw_data[:self.header_size])

        print("meta data id: ", hex(self.meta_data_id))
        print("meta payload size: ", self.payload_size)


class ssbf_data_block():
    FLAG_DATA_BLOCK_FLAG_ENCRYPTED = (1 << 2)
    FLAG_DATA_BLOCK_FLAG_COMPRESSED = (1 << 1)
    FLAG_DATA_BLOCK_LAST = (1 << 0)
    def __init__(self, data):
        self.header_size = 8

        if len(data) < self.header_size:
            raise ssbf_exception("Data block header data too short", 1)

        self.decode_block(data)


    def get_block_size(self):
        return self.header_size+self.blocks_payload_size


    def decode_block(self, data):
        self.block_number, self.blocks_payload_size, self.blocks_payload_checksum, \
            self.flags, self.header_checksum = struct.unpack('<HHHBB', data[:8])

        if (self.header_checksum != bsd_checksum8(data[:7])):
            print("Header checksum failed")
            raise ssbf_exception("Header checksum failed", 1)

        is_encrypted = self.flags & self.FLAG_DATA_BLOCK_FLAG_ENCRYPTED
        is_compressed = self.flags & self.FLAG_DATA_BLOCK_FLAG_COMPRESSED

        print("Found block {} with size {}, {}, {}".format(
            self.block_number, self.blocks_payload_size,
            'Encrypted' if is_encrypted else 'Not encrypted',
            'Compressed' if is_compressed else 'Not compressed'))

        
        self.raw_block = data[:self.header_size+self.blocks_payload_size]

    def decrypt_and_uncompress(self, key, max_output_data_size):
        buff = self.raw_block[self.header_size:] #make hard copy

        if self.raw_block and self.flags & self.FLAG_DATA_BLOCK_FLAG_ENCRYPTED:

            nonce = bytearray(b'\0'*24)
            nonce[0] =  self.block_number & 0xff
            nonce[1] =  (self.block_number >> 8) & 0xff

            buff = monocypher.chacha20(key, nonce, buff)

            if None == buff:
                print("decryption failed")

        if self.raw_block and self.flags & self.FLAG_DATA_BLOCK_FLAG_COMPRESSED:
            buff = lz4.block.decompress(buff, uncompressed_size=max_output_data_size)
            print("decompressed size: ", len(buff))


class ssbf_data():

    def __init__(self, header_data):
        self.header_size = 12
        
        self.last_block_number = 0


        if len(header_data) >= self.header_size:
            self.raw_header_data = header_data[:self.header_size]
        else:
            raise ssbf_exception("Data header data too short", 1)

        self.decode_header()

    def get_size(self):
        return self.header_size

    def decode_header(self):
        self.full_data_size_uncompressed, self.max_uncompressed_block_size, \
        self.flags, self.reserved, \
        self.full_data_checksum = struct.unpack('<IHBBI', self.raw_header_data)

        print("full uncompressed data size: ", self.full_data_size_uncompressed)
        print("max uncompressed block size: ", self.max_uncompressed_block_size)
        print("full data checksum: ", self.full_data_checksum)
        print("flags: (not supported atm, always default)", self.flags)


class ssbf_decoder():

    def __init__(self, file_name, key_file=None ):
        self.input_file_name = file_name
        self.key_file_name = key_file

        self.key = None
        if key_file:
            with open(key_file, 'rb') as kf:
                self.key = kf.read()[:32]
                print("key: ", self.key)


        with open(self.input_file_name, 'rb') as in_f:
            self.file_data = in_f.read()
            self.file_size = len(self.file_data)

    def decode(self):

        #if self.key == None:
        #    print("Cant decode, no encryption key")
        #    return

        print("\n/// MAIN HEADER ///")
        self.mh = ssbf_main_header(self.file_data)

        print("\n/// ENCRYPTION HEADER ///")
        self.ch = ssbf_encryption(self.key, self.file_data, 
                                  self.mh.get_size())

        if self.key != None:
            print("\n/// META HEADER ///")
            self.meta_h = ssbf_meta(self.ch.decrypted_header)

            print("\n/// DATA HEADER ///")
            self.ssbf_data = ssbf_data(
                self.ch.decrypted_header[self.meta_h.get_size():])


        print("\n/// BLOCKS ///")
        self.blocks = []
        payload = self.file_data[self.mh.get_size() + self.ch.get_size()
                                 + self.ch.encrypted_header_size + 16:]

        while payload:
            self.blocks.append(ssbf_data_block(payload))
            payload = payload[self.blocks[-1].get_block_size():]


        # check if block numbers are in sequence
        for b in self.blocks[1:]:
            if b.block_number != self.blocks[self.blocks.index(b)-1].block_number+1:
                print("Block number mismatch")
                return

        if self.key != None:
            print("Testing decryption/uncompression on block 1, ", 
                  len(self.ch.encryption_payload))

            self.blocks[0].decrypt_and_uncompress(
                self.ch.encryption_payload[:32], 
                self.ssbf_data.max_uncompressed_block_size)

        print("Done")


