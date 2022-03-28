#import sys
from abc import ABC, abstractmethod
from typing import Generator, List
from . import crypto, parsed


class RawBuffer(ABC):
    '''
    Types like this are part of the parsing tree of the nv data blob.
    '''

    name = None

    @property
    @abstractmethod
    def bytes(self) -> bytes:
        '''
        The bytes of this object.
        '''
        pass

    def __len__(self) -> int:
        return len(self.bytes)

    @property
    def value(self):
        '''
        The value of this object.
        '''
        return self.bytes

    @abstractmethod
    def fields(self) -> Generator:
        '''
        The fields of this object.
        '''
        pass

    def __str__(self) -> str:
        return self.value.__str__()

    def __repr__(self) -> str:
        prefix = ''
        if self.name:
            prefix = f'{self.name} : '
        fields = list(map(lambda f: f.__repr__().replace('\n','\n  '), self.fields()))
        if fields:
            return prefix + '{\n  ' + ',\n  '.join(fields) + '\n}'
        return prefix + self.__str__()


class NamedBytes(RawBuffer):
    '''
    Basically a field
    '''

    def __init__(self, name: str, buf: bytes):
        self.name = name
        self._buf = buf

    @property
    def bytes(self) -> bytes:
        return self._buf

    def fields(self) -> Generator:
        yield from ()

class NamedLittleInt(NamedBytes):
    @property
    def value(self) -> int:
        return int.from_bytes(self.bytes, 'little')

    def __str__(self) -> str:
        return hex(self.value)

class NamedBigInt(NamedBytes):
    @property
    def value(self) -> int:
        return int.from_bytes(self.bytes, 'big')

    def __str__(self) -> str:
        return hex(self.value)

class NamedStr(NamedBytes):
    @property
    def value(self) -> str:
        return self.bytes.decode('ascii', errors='backslashreplace')

class Header(NamedBytes):
    '''
    The header of the NVData structure.
    '''

    def __init__(self, buf: bytes):
        super().__init__('header', buf)

        assert len(buf) == 0x40, "The header needs to be 0x40 bytes long"
        self._buffer = buf

        self.magic = NamedStr("magic", buf[:4])
        self.version = NamedLittleInt("version", buf[4:8])
        self.reserved = NamedBytes("reserved", buf[8:])

        assert self.magic.value == 'NVx3'
        #assert self.version.value == 1
        assert self.reserved.bytes == b'\xff' * 0x38

    def fields(self) -> Generator:
        yield self.magic
        yield self.version
        yield self.reserved

class EntryHeader(NamedBytes):
    '''
    An NVData entry header
    '''

    def __init__(self, buf: bytes):
        super().__init__('header', buf)

        assert len(buf) == 0x20, "The entry header needs to be 0x20 bytes long"
        self._buffer = buf

        self.reserved_1 = NamedBytes("reserved_1", buf[:4])

        self.unknown_1 = NamedLittleInt("unknown_1", buf[4:6])

        self.total_size = NamedLittleInt("total_size", buf[6:8])
        self.body_size = NamedLittleInt("body_size", buf[8:10])

        self.has_checksum = NamedLittleInt("has_checksum", buf[10:12])
        self.context = NamedLittleInt("context", buf[12:16])
        self.sequence_nr = NamedLittleInt("sequence_nr", buf[16:20])

        self.magic = NamedStr("magic", buf[20:24])

        self.reserved_2 = NamedBytes("reserved_2", buf[24:32])

        assert self.has_checksum.value in {0,1}

        #assert self.reserved_1.bytes == b'\0'*4
        assert self.reserved_2.bytes == b'\0'*8

        assert self.unknown_1.value == 2

        assert self.total_size.value - self.body_size.value == 0x20
        assert self.total_size.value & 0xf == 0

        assert self.magic.value == 'NVR_'

    def fields(self) -> Generator:
        yield self.unknown_1
        yield self.total_size
        yield self.body_size
        yield self.has_checksum
        yield self.context
        yield self.sequence_nr
        yield self.magic


class EntryFieldDefs(NamedBytes):
    '''
    An NVData entry field definitions
    '''

    def __init__(self, buf: bytes):
        assert len(buf) == 0x20, "The entry field definitions are 0x20 bytes long!"
        super().__init__('field_defs', buf)

        self.total_size = NamedLittleInt("total_size", buf[:4])
        # total size includes hmac, iv, and field_defs
        expected_total_size = self.total_size.value - 0x30 - 0x20

        assert expected_total_size > 0, "There is no space for any fields {=expected_total_size}!"

        self.field_sizes = list()
        field_num = 0
        total_field_size = 0

        while field_num < 7:
            field_size_buf = buf[4+4*field_num:8+4*field_num]
            field_size = NamedLittleInt(f'field_{field_num}_size', field_size_buf)

            # last field def
            if field_size.value == 0:
                assert buf[4+4*field_num:] == b'\0' * (0x1c - 4*field_num), \
                    "There should only be zeroes after the last field def!"
                break

            total_field_size += field_size.value
            assert total_field_size <= expected_total_size

            self.field_sizes.append(field_size)

            field_num += 1

        assert total_field_size == expected_total_size 

    def fields(self) -> Generator:
        yield self.total_size
        for field_size in self.field_sizes:
            yield field_size


class EntryBody(NamedBytes):
    '''
    An NVData entry's body
    '''

    def __init__(self, buf: bytes):

        super().__init__('entry_body', buf)

        assert len(self) >= 0x30, \
            "There needs to be enough space for the iv and the field definitions!"

        self.iv = NamedBytes('iv', self.bytes[:0x10])

        self.field_defs = EntryFieldDefs(self.bytes[0x10:0x30])
        assert len(self) + 0x20 == self.field_defs.total_size.value

        self.body_fields = list()
        next_field_start = 0x30
        for (field_num, field_size) in enumerate(self.field_defs.field_sizes):
            field_buffer = self.bytes[next_field_start:next_field_start + field_size.value]
            self.body_fields.append(NamedBytes(f'field_{field_num}', field_buffer))

            next_field_start += field_size.value
            assert next_field_start <= len(self)

    def fields(self) -> Generator:
        yield self.iv
        yield self.field_defs
        for body_field in self.body_fields:
            yield body_field

    def raw_fields(self, _key):
        return [field.bytes for field in self.body_fields]

    def decrypt_fields(self, key):
        return [
            crypto.aes_ctr_dec(key, self.iv.bytes, field.bytes)
            for field in self.body_fields
        ]

class Entry(NamedBytes):
    '''
    An NVData entry
    '''

    def __init__(self, buf: bytes):

        self.header = EntryHeader(buf[:0x20])

        super().__init__('entry', buf[:self.header.total_size.value])

        assert len(self) >= 0x40, \
            "There needs to be enough space for header and hmac!"

        self.hmac = NamedBytes('hmac', self.bytes[0x20:0x40])
        self.body = EntryBody(self.bytes[0x40:])

    def fields(self) -> Generator:
        yield self.header
        yield self.hmac
        yield self.body

    def verify_hmac(self, key) -> bool:
        return crypto.hmac_sha256(key, self.body.bytes) == self.hmac.bytes

    def to_parsed(self, key) -> parsed.Entry:
        return parsed.Entry.build(
            self.header.context.value,
            self.header.sequence_nr.value,
            #self.body.raw_fields(key),
            self.body.decrypt_fields(key),
        )


class NVEntrySequence(NamedBytes):
    '''
    NV entries ending in an hmac checksum
    '''

    def __init__(self, buf: bytes):

        assert len(buf) >= 0x70, 'There needs to be enough space for an entry and the checksum!'

        self.entries = list()
        next_entry_start = 0x0

        while True:

            #sys.stdout.write(f'\rparsing entry at 0x{next_entry_start:x}')
            #sys.stdout.flush()

            try:
                entry = Entry(buf[next_entry_start:])
            except:
                #sys.stdout.write('\n')
                raise
            next_entry_start += len(entry)
            self.entries.append(entry)

            if entry.header.has_checksum.value:
                break

        #sys.stdout.write('\r                                        \r')

        self.hmac = NamedBytes('hmac', buf[next_entry_start:next_entry_start+0x20])

        super().__init__('nv_entry_sequence', buf[:next_entry_start + 0x20])

    def fields(self) -> Generator:
        for entry in self.entries:
            yield entry
        yield self.hmac

    def verify_all_hmacs(self, key) -> bool:
        return all(e.verify_hmac(key) for e in self.entries)

    def assert_hmac_is_valid(self, key):
        for e in self.entries:
            if not e.verify_hmac(key):
                raise Exception(e, "is not valid!")

    def to_parsed(self, key) -> List[parsed.Entry]:
        return [entry.to_parsed(key) for entry in self.entries]


class NVData(NamedBytes):
    '''
    NVData
    '''

    def __init__(self, buf: bytes):
        assert len(buf) >= 0x60, 'There needs to be enough space for header and checksum!'

        self.header = Header(buf[:0x40])
        self.entry_seqs = list()
        next_entry_seq_start = 0x40
        while buf[next_entry_seq_start:next_entry_seq_start+0x10] != b'\xff'*0x10:
            entry_seq = NVEntrySequence(buf[next_entry_seq_start:])

            next_entry_seq_start += len(entry_seq)
            self.entry_seqs.append(entry_seq)

        free_bytes_end = next_entry_seq_start
        while free_bytes_end < len(buf) and buf[free_bytes_end] == 255:
            free_bytes_end += 1
        self.free_space = NamedBytes('free_space', buf[next_entry_seq_start:free_bytes_end])
        assert self.free_space.bytes == b'\xff' * len(self.free_space)

        super().__init__('nv_data', buf[:free_bytes_end])

    def fields(self) -> Generator:
        yield self.header
        for entry_seq in self.entry_seqs:
            yield entry_seq

    def verify_all_hmacs(self, key) -> bool:
        buffer_len = len(self.header)
        for entry_seq in self.entry_seqs:
            buffer_len += len(entry_seq)
            checksum = crypto.hmac_sha256(key, self.bytes[:buffer_len-0x20])
            if checksum != entry_seq.hmac.bytes:
                return False

        return all(s.verify_all_hmacs(key) for s in self.entry_seqs)


    def assert_all_hmacs_are_valid(self, key):
        for s in self.entry_seqs:
            s.assert_hmac_is_valid(key)

        buffer_len = len(self.header)
        for entry_seq in self.entry_seqs:
            buffer_len += len(entry_seq)
            checksum = crypto.hmac_sha256(key, self.bytes[:buffer_len-0x20])
            if checksum != entry_seq.hmac.bytes:
                raise Exception("Sequence hmac up until {buffer_len} is invalid!")

    def to_parsed(self, key) -> List[List[parsed.Entry]]:
        return [seq.to_parsed(key) for seq in self.entry_seqs]


class NVRom(NamedBytes):
    '''
    NVRom
    '''

    def __init__(self, buf: bytes):

        super().__init__('nv_rom', buf)

        self.nvdatas = list()
        next_nvdata = 0
        while next_nvdata < len(buf):
            nvdata = NVData(buf[next_nvdata:])

            next_nvdata += len(nvdata)
            self.nvdatas.append(nvdata)

    def fields(self) -> Generator:
        for nvdata in self.nvdatas:
            yield nvdata

    def verify_all_hmacs(self, key) -> bool:
        return all(d.verify_all_hmacs(key) for d in self.nvdatas)

    def assert_all_hmacs_are_valid(self, key) -> bool:
        for d in self.nvdatas:
            d.assert_all_hmacs_are_valid(key)

    def to_parsed(self, key) -> List[List[List[parsed.Entry]]]:
        return [nvdata.to_parsed(key) for nvdata in self.nvdatas]


