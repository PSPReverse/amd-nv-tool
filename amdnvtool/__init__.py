from . import raw, crypto, parsed

class NVData:

    def __init__(self, raw):
        self.raw = raw
        self._keys = None
        self._parsed = None
        self._by_context = None

    @staticmethod
    def from_file(filename: str):
        with open(filename, 'rb') as f:
            return NVData(raw.NVData(f.read()))

    @property
    def keys(self):
        if not self._keys:
            self._keys = crypto.get_keys()
        return self._keys

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
        return self.raw.verify_all_hmays(self.keys.hmac_key)

    def print_parsed(self):
        for (seq_num, entries) in enumerate(self.parsed):
            print(f'Sequence {seq_num}:')
            for (entry_num, entry) in enumerate(entries):
                print(f'  Entry {entry_num}:\n    ' + entry.try_interpret().replace('\n', '\n    '))

    def print_by_context(self):
        for (context_id, sequence) in self.by_context.items():
            print(f'Context {context_id:x}')
            for content in sequence:
                print(f'  {content}')

def main():
    import sys
    nv_data = NVData.from_file(sys.argv[1])
    #nv_data.print_parsed()
    nv_data.print_by_context()

