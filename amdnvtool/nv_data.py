from psptool import PSPTool

from .crypto import NvDataKeys, sole
from . import raw, crypto, parsed


class NVData:

    def __init__(self, raw, nv_data_keys: NvDataKeys):
        self.raw = raw
        self.keys = nv_data_keys
        self._parsed = None
        self._by_context = None

    @staticmethod
    def from_file_and_lsb_key_hex(filename: str, lsb_key_hex: str):
        pt = PSPTool.from_file(filename)
        psp_nv_data_entry = sole(set(pt.blob.get_entries_by_type(0x4)))

        nv_data_keys = NvDataKeys.from_file_and_lsb_key_hex(filename, lsb_key_hex)
        return NVData(raw.NVRom(psp_nv_data_entry.get_bytes()), nv_data_keys)

    @staticmethod
    def from_file_and_secret_hex(filename: str, secret_hex: str):
        pt = PSPTool.from_file(filename)
        psp_nv_data_entry = sole(set(pt.blob.get_entries_by_type(0x4)))

        nv_data_keys = NvDataKeys.from_file_and_secret_hex(filename, secret_hex)
        return NVData(raw.NVRom(psp_nv_data_entry.get_bytes()), nv_data_keys)

    @property
    def parsed(self):
        if not self._parsed:
            self._parsed = self.raw.to_parsed(self.keys.aes_key)
        return self._parsed

    @property
    def by_context(self):
        if not self._by_context:
            self._by_context = parsed.map_by_context_id(self.parsed)
        return self._by_context

    @property
    def are_hmacs_valid(self):
        return self.raw.verify_all_hmacs(self.keys.hmac_key)

    def print_parsed(self):
        for (nvdata_num, nvdata) in enumerate(self.parsed):
            print(f'NVData {nvdata_num}:')
            for (seq_num, entries) in enumerate(nvdata):
                print(f'  Sequence {seq_num}:')
                for (entry_num, entry) in enumerate(entries):
                    print(f'    Entry {entry_num}:\n      ' + entry.try_interpret().replace('\n', '\n      '))

    def print_by_context(self):
        for (context_id, sequence) in self.by_context.items():
            print(f'Context {context_id:x}')
            for content in sequence:
                print(f'  {content}')
